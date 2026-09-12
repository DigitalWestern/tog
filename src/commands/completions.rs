//! `blanket completions <shell>`: print the shell completion script.

use crate::cli;
use std::io;

pub fn run(shell: cli::Shell) -> io::Result<i32> {
    print!("{}", cli::completions(shell));
    Ok(0)
}
