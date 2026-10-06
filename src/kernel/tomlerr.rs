//! TOML parse errors that name a position, never a line of the file
//! (kernel layer). A parser's own message quotes the failing source line,
//! and a project file can be a link to a secret (the signing key's
//! `ed25519:<seed>` line), so tog's readers report where, not what.

/// " at line L, column C" for `error` in `text`, or nothing when the
/// parser gave no position.
pub fn position(text: &str, error: &toml::de::Error) -> String {
    error
        .span()
        .and_then(|span| text.get(..span.start))
        .map(|before| {
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
            format!(" at line {line}, column {column}")
        })
        .unwrap_or_default()
}

/// "<name> is not valid TOML at line L, column C: <what>". `<what>` is the
/// parser's message without the source excerpt its `Display` adds: the
/// kind of mistake ("unknown field `x`", "expected `=`"), which names a
/// key at most, never a value.
pub fn describe(name: &str, text: &str, error: &toml::de::Error) -> String {
    format!(
        "{name} is not valid TOML{}: {}",
        position(text, error),
        error.message().trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "ed25519:c2VjcmV0LXNlZWQtYnl0ZXMtdGhhdC1tdXN0LW5vdC1sZWFr";

    #[test]
    fn the_message_names_the_position_and_no_source_text() {
        // A signing key file read as TOML, and a key file hard-linked
        // under a value.
        for text in [
            format!("a = 1\n{SECRET}\n"),
            format!("a = 1\nb = {SECRET}\n"),
        ] {
            let error = toml::from_str::<toml::Table>(&text).unwrap_err();
            assert!(
                error.to_string().contains("c2VjcmV0"),
                "the premise: toml quotes the line"
            );
            let message = describe("x.toml", &text, &error);
            assert!(!message.contains("c2VjcmV0"), "{message}");
            assert!(message.contains(" at line 2, column "), "{message}");
        }
        let text = format!("a = 1\n{SECRET}\n");
        let error = toml::from_str::<toml::Table>(&text).unwrap_err();
        assert!(
            error.to_string().contains(SECRET),
            "the premise: toml quotes the line"
        );
        let message = describe("x.toml", &text, &error);
        assert!(
            message.starts_with("x.toml is not valid TOML at line 2, column "),
            "{message}"
        );
        assert!(!message.contains("ed25519"), "{message}");
    }
}
