//! `tog ls`: list the packages recorded in the project's closures.

use crate::commands::inspect;
use crate::commands::shared::project_dir;
use crate::kernel::ui;
use std::io;

/// Reads the committed closures and nothing else: no store, no lease.
pub fn run(ecosystem: Option<&str>, json: bool) -> io::Result<i32> {
    print!(
        "{}",
        inspect::ls(&project_dir(), ecosystem, json, ui::verbose())?
    );
    Ok(0)
}
