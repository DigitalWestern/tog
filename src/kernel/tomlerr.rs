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

/// "<name> is not valid TOML at line L, column C: <what>". `<what>` never
/// holds a value from the file. For a syntax error it is the parser's
/// message without the source excerpt its `Display` adds ("expected `=`",
/// "duplicate key `x`"). For a document that parses but does not fit the
/// type it is read into, serde's message can quote the value ("invalid
/// type: string \"...\""), so only the messages that name a key are kept
/// ("unknown field `x`", "missing field `x`") and any other becomes a
/// fixed reason.
pub fn describe(name: &str, text: &str, error: &toml::de::Error) -> String {
    let message = error.message().trim();
    let syntax = toml::from_str::<toml::Table>(text).is_err();
    let names_a_key = ["unknown field `", "missing field `", "duplicate field `"]
        .iter()
        .any(|prefix| message.starts_with(prefix));
    let what = if syntax || names_a_key {
        message
    } else {
        "a value has the wrong type or is not one this file accepts"
    };
    format!("{name} is not valid TOML{}: {what}", position(text, error))
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

    /// A document that parses but holds a value of the wrong type: serde's
    /// own message quotes the value, and the description does not.
    #[test]
    fn a_wrongly_typed_value_is_described_without_its_text() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct File {
            count: u64,
            kind: Option<Kind>,
        }
        #[derive(serde::Deserialize, Debug)]
        #[serde(rename_all = "lowercase")]
        enum Kind {
            One,
        }
        for text in [
            format!("count = \"{SECRET}\"\n"),
            format!("count = 1\nkind = \"{SECRET}\"\n"),
        ] {
            let error = toml::from_str::<File>(&text).unwrap_err();
            assert!(
                error.message().contains("c2VjcmV0"),
                "the premise: serde quotes the value: {}",
                error.message()
            );
            let message = describe("x.toml", &text, &error);
            assert!(!message.contains("c2VjcmV0"), "{message}");
            assert!(
                message.starts_with("x.toml is not valid TOML at line "),
                "{message}"
            );
        }
        let text = "count = 1\nmystery = 2\n";
        let error = toml::from_str::<File>(text).unwrap_err();
        let message = describe("x.toml", text, &error);
        assert!(message.contains("unknown field `mystery`"), "{message}");
    }
}
