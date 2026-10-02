//! `tog attest`'s grammar.

use std::path::PathBuf;

use super::parse::{non_empty, reject, separate_value, with_suggestion};
use super::spec::ECOSYSTEM_IDS;
use super::{Command, LedgerTransfer, UsageError};

/// `Ok(None)` means the command's help was requested. An ecosystem is a
/// tailor id; `--ledger-export` and `--ledger-import` run no lock check, so
/// they take no ecosystem and no `--record-out`, and one run moves one
/// ledger.
pub(super) fn parse_attest(args: &[String]) -> Result<Option<Command>, UsageError> {
    let usage = |message: String| UsageError::new(message, Some("attest"));
    let ecosystem_word = |word: &str| -> Result<String, UsageError> {
        if ECOSYSTEM_IDS.contains(&word) {
            return Ok(word.to_string());
        }
        Err(usage(with_suggestion(
            format!(
                "attest: unknown ecosystem '{word}' (one of: {})",
                ECOSYSTEM_IDS.join(", ")
            ),
            word,
            ECOSYSTEM_IDS.iter().copied(),
        )))
    };
    let mut ecosystems: Vec<String> = Vec::new();
    let mut record_out = None;
    let mut ledger = None;
    let mut set_ledger = |transfer: LedgerTransfer| -> Result<(), UsageError> {
        if ledger.replace(transfer).is_some() {
            return Err(usage(
                "attest: --ledger-export and --ledger-import move one ledger per run".into(),
            ));
        }
        Ok(())
    };
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "--record-out" => {
                let value =
                    separate_value(args, index, arg, Some("attest"), "a file or directory path")?;
                record_out = Some(PathBuf::from(value));
                index += 1;
            }
            _ if arg.starts_with("--record-out=") => {
                record_out = Some(non_empty(
                    &arg["--record-out=".len()..],
                    "--record-out",
                    Some("attest"),
                )?);
            }
            "--ledger-export" => {
                let needs = "an ecosystem and a file path";
                let ecosystem = separate_value(args, index, arg, Some("attest"), needs)?;
                let file = separate_value(args, index + 1, arg, Some("attest"), needs)?;
                set_ledger(LedgerTransfer::Export {
                    ecosystem: ecosystem_word(ecosystem)?,
                    file: PathBuf::from(file),
                })?;
                index += 2;
            }
            "--ledger-import" => {
                let file = separate_value(args, index, arg, Some("attest"), "a file path")?;
                set_ledger(LedgerTransfer::Import {
                    file: PathBuf::from(file),
                })?;
                index += 1;
            }
            _ if arg.starts_with("--ledger-import=") => {
                set_ledger(LedgerTransfer::Import {
                    file: non_empty(
                        &arg["--ledger-import=".len()..],
                        "--ledger-import",
                        Some("attest"),
                    )?,
                })?;
            }
            other if other.starts_with('-') => return Err(reject("attest", other)),
            other => {
                let ecosystem = ecosystem_word(other)?;
                if ecosystems.contains(&ecosystem) {
                    return Err(usage(format!("attest: '{other}' is named twice")));
                }
                ecosystems.push(ecosystem);
            }
        }
        index += 1;
    }
    if ledger.is_some() && (!ecosystems.is_empty() || record_out.is_some()) {
        return Err(usage(
            "attest: --ledger-export and --ledger-import run no lock check, so they take \
             no ecosystem and no --record-out"
                .into(),
        ));
    }
    Ok(Some(Command::Attest {
        ecosystems,
        record_out,
        ledger,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::super::{Command, LedgerTransfer, Parsed};
    use std::path::PathBuf;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    fn command(words: &[&str]) -> Command {
        match parse(&argv(words)).unwrap() {
            Parsed::Run(invocation) => invocation.command,
            other => panic!("expected a command, got {other:?}"),
        }
    }

    fn message(words: &[&str]) -> String {
        parse(&argv(words)).unwrap_err().message
    }

    fn attest(ecosystems: &[&str], record_out: Option<&str>) -> Command {
        Command::Attest {
            ecosystems: ecosystems.iter().map(|id| id.to_string()).collect(),
            record_out: record_out.map(PathBuf::from),
            ledger: None,
        }
    }

    #[test]
    fn attest_names_ecosystems_and_a_record_destination() {
        assert_eq!(command(&["attest"]), attest(&[], None));
        assert_eq!(
            command(&["attest", "go", "node"]),
            attest(&["go", "node"], None)
        );
        assert_eq!(
            command(&["attest", "go", "--record-out", "out/go.json"]),
            attest(&["go"], Some("out/go.json"))
        );
        assert_eq!(
            command(&["attest", "--record-out=records"]),
            attest(&[], Some("records"))
        );
    }

    #[test]
    fn attest_moves_one_ledger_per_run() {
        assert_eq!(
            command(&["attest", "--ledger-export", "go", "ledger.json"]),
            Command::Attest {
                ecosystems: Vec::new(),
                record_out: None,
                ledger: Some(LedgerTransfer::Export {
                    ecosystem: "go".into(),
                    file: "ledger.json".into(),
                }),
            }
        );
        assert_eq!(
            command(&["attest", "--ledger-import=ledger.json"]),
            Command::Attest {
                ecosystems: Vec::new(),
                record_out: None,
                ledger: Some(LedgerTransfer::Import {
                    file: "ledger.json".into(),
                }),
            }
        );
        let twice = message(&["attest", "--ledger-import", "a", "--ledger-import", "b"]);
        assert!(twice.contains("one ledger per run"), "{twice}");
        let mixed = message(&["attest", "go", "--ledger-import", "a"]);
        assert!(
            mixed.contains("take no ecosystem and no --record-out"),
            "{mixed}"
        );
        let mixed = message(&["attest", "--record-out", "x", "--ledger-import", "a"]);
        assert!(
            mixed.contains("take no ecosystem and no --record-out"),
            "{mixed}"
        );
        let short = message(&["attest", "--ledger-export", "go"]);
        assert!(short.contains("--ledger-export"), "{short}");
    }

    #[test]
    fn attest_refuses_unknown_and_repeated_ecosystems_and_sync_flags() {
        let unknown = message(&["attest", "golang"]);
        assert!(unknown.contains("unknown ecosystem 'golang'"), "{unknown}");
        assert!(message(&["attest", "go", "go"]).contains("named twice"));
        assert!(message(&["attest", "--ledger-export", "gol", "f"]).contains("'gol'"));
        assert!(message(&["attest", "--frozen"]).contains("--frozen"));
        assert!(message(&["attest", "--bogus"]).contains("--bogus"));
    }

    #[test]
    fn resolution_record_belongs_to_the_bare_sync() {
        assert_eq!(
            command(&["--resolution-record", "a.json", "--resolution-record=dir"]),
            Command::Sync {
                fresh: false,
                records: vec!["a.json".into(), "dir".into()],
            }
        );
        assert_eq!(
            command(&["sync", "--resolution-record", "a.json"]),
            Command::Sync {
                fresh: false,
                records: vec!["a.json".into()],
            }
        );
        let elsewhere = message(&["--resolution-record", "a.json", "status"]);
        assert!(
            elsewhere.contains("belongs to the bare 'tog'"),
            "{elsewhere}"
        );
        assert!(
            message(&["status", "--resolution-record", "a.json"]).contains("--resolution-record")
        );
        assert!(message(&["--resolution-record"]).contains("--resolution-record"));
        assert!(message(&["--resolution-record="]).contains("--resolution-record"));
    }
}
