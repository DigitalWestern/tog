//! `tog completions <shell>`: print the shell completion script.

use crate::cli;
use crate::tailors::{self, FileRunner};
use std::io;

pub fn run(shell: cli::Shell) -> io::Result<i32> {
    // Only the extensions a first word actually runs: a .rs or .cs file is
    // refused with a pointer to `tog build`, so it is not offered.
    let extensions: Vec<&str> = tailors::registry()
        .iter()
        .flat_map(|tailor| tailor.source_files())
        .filter(|file| !matches!(file.runner, FileRunner::Built(_)))
        .map(|file| file.extension)
        .collect();
    print!("{}", cli::completions(shell, &extensions));
    Ok(0)
}
