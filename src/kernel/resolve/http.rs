//! The strict HTTP/1.1 subset the resolution proxy speaks to the tools it
//! serves: one request at a time on a connection, the request line and
//! headers within 64 KiB, and a body framed by `Content-Length` or by
//! `chunked`, never both.
//!
//! Anything ambiguous is refused rather than interpreted. Two parsers that
//! read the same bytes as different requests (request smuggling) is the
//! failure this module exists to rule out, so every construct whose meaning
//! depends on who reads it is an error: `Content-Length` together with
//! `Transfer-Encoding`, a repeated `Content-Length`, a transfer coding
//! other than `chunked`, a header continued on the next line (obs-fold), a
//! bare LF line ending, whitespace before a header's colon, and a second
//! request sent before the first was answered (pipelining).

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

/// The request line plus every header line, CRLFs included.
pub const MAX_HEAD: usize = 64 * 1024;
/// A tool's request body (a git `upload-pack` negotiation is the largest
/// one a resolver sends). Larger bodies are refused, not truncated.
pub const MAX_BODY: u64 = 64 << 20;

/// The header fields of one message, in the order they arrived. Names
/// compare case-insensitively.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// How many fields named `name` arrived.
    pub fn count(&self, name: &str) -> usize {
        self.0
            .iter()
            .filter(|(field, _)| field.eq_ignore_ascii_case(name))
            .count()
    }

    pub fn push(&mut self, name: &str, value: &str) {
        self.0.push((name.to_string(), value.to_string()));
    }

    /// Replace every field named `name` with one field.
    pub fn set(&mut self, name: &str, value: &str) {
        self.remove(name);
        self.push(name, value);
    }

    pub fn remove(&mut self, name: &str) {
        self.0
            .retain(|(field, _)| !field.eq_ignore_ascii_case(name));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

/// One parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The request target exactly as sent: origin-form (`/a/b?c`),
    /// authority-form for `CONNECT` (`host:443`), or absolute-form
    /// (`http://host/a`).
    pub target: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// HTTP/1.0 closes after one exchange unless it asked otherwise; an
    /// HTTP/1.1 client keeps the connection unless it sent `close`.
    pub keep_alive: bool,
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum ParseError {
    /// The peer closed the connection before sending a byte: the ordinary
    /// end of a keep-alive connection, not an error to answer.
    Closed,
    /// The bytes are not a request this subset accepts. Answered with 400
    /// and the connection closed.
    Malformed(String),
    /// The head or the body is over its cap. Answered with 431 or 413.
    TooLarge { head: bool },
    /// The transport failed mid-request (a reset, a read timeout).
    Io(io::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Closed => write!(f, "the client closed the connection"),
            ParseError::Malformed(why) => write!(f, "malformed request: {why}"),
            ParseError::TooLarge { head: true } => {
                write!(f, "request head over {} KiB", MAX_HEAD / 1024)
            }
            ParseError::TooLarge { head: false } => {
                write!(f, "request body over {} MiB", MAX_BODY >> 20)
            }
            ParseError::Io(error) => write!(f, "reading the request failed: {error}"),
        }
    }
}

fn malformed(why: impl Into<String>) -> ParseError {
    ParseError::Malformed(why.into())
}

/// A `tchar` (RFC 9110 section 5.6.2): what a method and a field name are
/// made of.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_token(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(is_tchar)
}

/// Read one CRLF-terminated line of the head into `line` (without the
/// CRLF), counting it against `budget`. A bare LF is refused.
fn read_head_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    budget: &mut usize,
) -> Result<(), ParseError> {
    line.clear();
    let limit = (*budget as u64).saturating_add(1);
    let read = reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', line)
        .map_err(ParseError::Io)?;
    if read == 0 {
        return Err(ParseError::Closed);
    }
    if read > *budget {
        return Err(ParseError::TooLarge { head: true });
    }
    *budget -= read;
    if line.last() != Some(&b'\n') {
        return Err(malformed("the head ended before its blank line"));
    }
    line.pop();
    if line.last() != Some(&b'\r') {
        return Err(malformed("a line ended with a bare LF"));
    }
    line.pop();
    Ok(())
}

/// Parse `METHOD SP target SP HTTP/1.x`, exactly one space apart.
fn parse_request_line(line: &[u8]) -> Result<(String, String, bool), ParseError> {
    let line = std::str::from_utf8(line).map_err(|_| malformed("request line is not UTF-8"))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        // The line is not echoed: its target may carry a token or a
        // secret query.
        return Err(malformed(
            "bad request line: expected METHOD SP target SP version",
        ));
    };
    if !is_token(method) {
        return Err(malformed(format!("bad method {method:?}")));
    }
    if target.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(malformed("bad request target"));
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        other => return Err(malformed(format!("unsupported version {other:?}"))),
    };
    Ok((method.to_string(), target.to_string(), http10))
}

/// Parse one header line. obs-fold, whitespace before the colon, and
/// control characters in the value are refused.
fn parse_header(line: &[u8]) -> Result<(String, String), ParseError> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(malformed("obsolete line folding (obs-fold)"));
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or_else(|| malformed("a header line has no colon"))?;
    let name = std::str::from_utf8(&line[..colon]).map_err(|_| malformed("bad header name"))?;
    if !is_token(name) {
        return Err(malformed(format!("bad header name {name:?}")));
    }
    let raw = &line[colon + 1..];
    if raw.iter().any(|&b| (b < b' ' && b != b'\t') || b == 0x7f) {
        return Err(malformed(format!("control character in header {name}")));
    }
    let value = String::from_utf8_lossy(raw)
        .trim_matches([' ', '\t'])
        .to_string();
    Ok((name.to_string(), value))
}

/// How the body of a request is framed.
enum Framing {
    None,
    Length(u64),
    Chunked,
}

fn framing(headers: &Headers, http10: bool) -> Result<Framing, ParseError> {
    let lengths = headers.count("content-length");
    let codings = headers.count("transfer-encoding");
    if lengths > 0 && codings > 0 {
        return Err(malformed(
            "both Content-Length and Transfer-Encoding (ambiguous framing)",
        ));
    }
    if codings > 1 {
        return Err(malformed("Transfer-Encoding repeated"));
    }
    if codings == 1 {
        if http10 {
            return Err(malformed("Transfer-Encoding in an HTTP/1.0 request"));
        }
        let coding = headers.get("transfer-encoding").unwrap_or_default();
        if !coding.eq_ignore_ascii_case("chunked") {
            return Err(malformed(format!(
                "transfer coding {coding:?}; only chunked is accepted"
            )));
        }
        return Ok(Framing::Chunked);
    }
    if lengths > 1 {
        return Err(malformed("Content-Length repeated"));
    }
    match headers.get("content-length") {
        None => Ok(Framing::None),
        Some(value) => {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed(format!("bad Content-Length {value:?}")));
            }
            let length: u64 = value
                .parse()
                .map_err(|_| malformed(format!("bad Content-Length {value:?}")))?;
            Ok(Framing::Length(length))
        }
    }
}

/// Read one request from `reader`. Refuses a request whose bytes arrived
/// together with the start of another one: this subset answers one request
/// before it reads the next, and a pipelined second request is exactly the
/// place a smuggled one would hide.
///
/// Only bytes already buffered count as pipelined: the check never waits on
/// the socket for more.
pub fn read_request<R: Read>(reader: &mut BufReader<R>) -> Result<Request, ParseError> {
    let mut budget = MAX_HEAD;
    let mut line = Vec::new();
    read_head_line(reader, &mut line, &mut budget)?;
    let (method, target, http10) = parse_request_line(&line)?;
    let mut headers = Headers::new();
    loop {
        match read_head_line(reader, &mut line, &mut budget) {
            Ok(()) => {}
            Err(ParseError::Closed) => return Err(malformed("the head ended early")),
            Err(error) => return Err(error),
        }
        if line.is_empty() {
            break;
        }
        let (name, value) = parse_header(&line)?;
        headers.push(&name, &value);
    }
    if !http10 && headers.count("host") != 1 {
        return Err(malformed("an HTTP/1.1 request needs exactly one Host"));
    }
    let body = match framing(&headers, http10)? {
        Framing::None => Vec::new(),
        Framing::Length(length) => read_sized(reader, length)?,
        Framing::Chunked => read_chunked(reader)?,
    };
    if !reader.buffer().is_empty() {
        return Err(malformed(
            "a second request arrived before the first was answered (pipelining)",
        ));
    }
    let connection = headers.get("connection").unwrap_or_default().to_string();
    let has = |option: &str| {
        connection
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(option))
    };
    let keep_alive = if http10 {
        has("keep-alive")
    } else {
        !has("close")
    };
    Ok(Request {
        method,
        target,
        headers,
        body,
        keep_alive,
    })
}

fn read_sized(reader: &mut impl Read, length: u64) -> Result<Vec<u8>, ParseError> {
    if length > MAX_BODY {
        return Err(ParseError::TooLarge { head: false });
    }
    let mut body = Vec::with_capacity(length.min(1 << 20) as usize);
    reader
        .take(length)
        .read_to_end(&mut body)
        .map_err(ParseError::Io)?;
    if body.len() as u64 != length {
        return Err(malformed("the body ended before its Content-Length"));
    }
    Ok(body)
}

/// Decode a chunked body. Chunk extensions are ignored; trailer fields are
/// read and dropped, and count against the head budget.
fn read_chunked(reader: &mut impl BufRead) -> Result<Vec<u8>, ParseError> {
    let mut body = Vec::new();
    let mut budget = MAX_HEAD;
    let mut line = Vec::new();
    loop {
        read_head_line(reader, &mut line, &mut budget).map_err(|error| match error {
            ParseError::Closed => malformed("the body ended inside a chunk"),
            other => other,
        })?;
        let text = std::str::from_utf8(&line).map_err(|_| malformed("bad chunk size"))?;
        let size_text = text.split(';').next().unwrap_or_default();
        if size_text.is_empty()
            || size_text.len() > 16
            || !size_text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(malformed(format!("bad chunk size {text:?}")));
        }
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| malformed(format!("bad chunk size {text:?}")))?;
        if size == 0 {
            break;
        }
        // A 16-hex-digit size would overflow a plain sum.
        let total = (body.len() as u64).checked_add(size);
        if total.is_none_or(|total| total > MAX_BODY) {
            return Err(ParseError::TooLarge { head: false });
        }
        let before = body.len();
        reader
            .by_ref()
            .take(size)
            .read_to_end(&mut body)
            .map_err(ParseError::Io)?;
        if (body.len() - before) as u64 != size {
            return Err(malformed("the body ended inside a chunk"));
        }
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|_| malformed("a chunk did not end with CRLF"))?;
        if &crlf != b"\r\n" {
            return Err(malformed("a chunk did not end with CRLF"));
        }
    }
    // Trailer section: fields until the blank line, all discarded.
    loop {
        read_head_line(reader, &mut line, &mut budget).map_err(|error| match error {
            ParseError::Closed => malformed("the body ended inside the trailer"),
            other => other,
        })?;
        if line.is_empty() {
            return Ok(body);
        }
        parse_header(&line)?;
    }
}

/// The reason phrase for the statuses the proxy sends or passes through.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        410 => "Gone",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// Write a status line and headers. `framing` headers (`Content-Length`,
/// `Transfer-Encoding`, `Connection`) are the caller's responsibility and
/// must not be in `headers`.
fn write_head(out: &mut impl Write, status: u16, headers: &Headers) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers.iter() {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    out.write_all(head.as_bytes())
}

/// Write a whole response with a `Content-Length` body. `head_only` is for
/// a `HEAD` request: the length is sent, the body is not.
pub fn write_response(
    out: &mut impl Write,
    status: u16,
    headers: &Headers,
    body: &[u8],
    keep_alive: bool,
    head_only: bool,
) -> io::Result<()> {
    write_head(out, status, headers)?;
    let mut framing = String::new();
    if status != 304 && status != 204 {
        framing.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if !keep_alive {
        framing.push_str("Connection: close\r\n");
    }
    framing.push_str("\r\n");
    out.write_all(framing.as_bytes())?;
    if !head_only && status != 304 && status != 204 {
        out.write_all(body)?;
    }
    out.flush()
}

/// Write the head of a response whose `length`-byte body the caller then
/// copies itself (a verified artifact streamed from the cache).
pub fn write_sized_head(
    out: &mut impl Write,
    status: u16,
    headers: &Headers,
    length: u64,
    keep_alive: bool,
) -> io::Result<()> {
    write_head(out, status, headers)?;
    let mut framing = format!("Content-Length: {length}\r\n");
    if !keep_alive {
        framing.push_str("Connection: close\r\n");
    }
    framing.push_str("\r\n");
    out.write_all(framing.as_bytes())
}

/// A response body of unknown length, sent with chunked framing. Each
/// `write` is one chunk; `finish` writes the terminating chunk.
pub struct ChunkedBody<'a, W: Write> {
    out: &'a mut W,
}

impl<'a, W: Write> ChunkedBody<'a, W> {
    /// Write the head and start a chunked body.
    pub fn start(
        out: &'a mut W,
        status: u16,
        headers: &Headers,
        keep_alive: bool,
    ) -> io::Result<Self> {
        write_head(out, status, headers)?;
        let mut framing = String::from("Transfer-Encoding: chunked\r\n");
        if !keep_alive {
            framing.push_str("Connection: close\r\n");
        }
        framing.push_str("\r\n");
        out.write_all(framing.as_bytes())?;
        Ok(Self { out })
    }

    pub fn chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        write!(self.out, "{:x}\r\n", bytes.len())?;
        self.out.write_all(bytes)?;
        self.out.write_all(b"\r\n")
    }

    pub fn finish(self) -> io::Result<()> {
        self.out.write_all(b"0\r\n\r\n")?;
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Result<Request, ParseError> {
        read_request(&mut BufReader::new(bytes))
    }

    fn refused(bytes: &[u8], why: &str) {
        match parse(bytes) {
            Err(ParseError::Malformed(reason)) => {
                assert!(reason.contains(why), "{why}: got {reason}")
            }
            other => panic!("{why}: expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn http_parser_rejects_ambiguous_framing() {
        // Content-Length and Transfer-Encoding together: the classic
        // smuggling shape, whichever order they arrive in.
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "ambiguous framing",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
            "ambiguous framing",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "Content-Length repeated",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: +1\r\n\r\nx",
            "bad Content-Length",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
            "only chunked",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "Transfer-Encoding repeated",
        );
        // obs-fold: a header continued on the next line.
        refused(
            b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: one\r\n two\r\n\r\n",
            "obs-fold",
        );
        refused(
            b"GET /a HTTP/1.1\r\nHost: h\r\nX-A : one\r\n\r\n",
            "bad header name",
        );
        refused(b"GET /a HTTP/1.1\nHost: h\n\n", "bare LF");
        refused(b"GET  /a HTTP/1.1\r\nHost: h\r\n\r\n", "bad request line");
        refused(b"GET /a HTTP/2\r\nHost: h\r\n\r\n", "unsupported version");
        refused(b"GET /a HTTP/1.1\r\n\r\n", "exactly one Host");
        refused(
            b"GET /a HTTP/1.1\r\nHost: h\r\nHost: i\r\n\r\n",
            "exactly one Host",
        );
        refused(
            b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
            "pipelining",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n0\r\n\r\n",
            "CRLF",
        );
        refused(
            b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "bad chunk size",
        );

        // Oversize headers: over the 64 KiB head cap.
        let mut big = b"GET /a HTTP/1.1\r\nHost: h\r\nX-Big: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        big.extend(b"\r\n\r\n");
        assert!(matches!(
            parse(&big),
            Err(ParseError::TooLarge { head: true })
        ));
        let huge = format!(
            "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(matches!(
            parse(huge.as_bytes()),
            Err(ParseError::TooLarge { head: false })
        ));

        // A chunk size near u64::MAX, after a first chunk, must be refused
        // as too large, not wrap the running total (or panic in debug).
        for size in ["ffffffffffffffff", "fffffffffffffffe", "8000000000000000"] {
            let request = format!(
                "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n{size}\r\n"
            );
            assert!(
                matches!(
                    parse(request.as_bytes()),
                    Err(ParseError::TooLarge { head: false })
                ),
                "{size}"
            );
        }

        // Control: the unambiguous forms parse.
        let chunked = parse(
            b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n",
        )
        .unwrap();
        assert_eq!(chunked.body, b"abcde");
        let sized = parse(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nxyz").unwrap();
        assert_eq!(sized.body, b"xyz");
        assert!(sized.keep_alive);
    }

    #[test]
    fn requests_parse_in_every_target_form() {
        let connect = parse(
            b"CONNECT registry.test:443 HTTP/1.1\r\nHost: registry.test:443\r\nProxy-Authorization: Basic eDp5\r\n\r\n",
        )
        .unwrap();
        assert_eq!(connect.method, "CONNECT");
        assert_eq!(connect.target, "registry.test:443");
        assert_eq!(
            connect.headers.get("proxy-authorization"),
            Some("Basic eDp5")
        );
        let origin =
            parse(b"GET /t/r/a?b=c HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").unwrap();
        assert_eq!(origin.target, "/t/r/a?b=c");
        assert!(!origin.keep_alive);
        let old = parse(b"GET http://h/a HTTP/1.0\r\n\r\n").unwrap();
        assert!(!old.keep_alive);
        assert!(matches!(parse(b""), Err(ParseError::Closed)));
    }

    #[test]
    fn responses_frame_their_bodies() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "text/plain");
        let mut out = Vec::new();
        write_response(&mut out, 404, &headers, b"gone", false, false).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngone"
        );
        let mut out = Vec::new();
        let mut body = ChunkedBody::start(&mut out, 200, &Headers::new(), true).unwrap();
        body.chunk(b"hello").unwrap();
        body.chunk(b"").unwrap();
        body.finish().unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        );
    }
}
