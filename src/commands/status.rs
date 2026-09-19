//! `tog status`: is each recorded closure still in sync with its inputs?

use crate::cli;
use crate::commands::inspect;
use crate::commands::shared::project_dir;
use crate::kernel::platform::Platform;
use std::io;

pub fn run(platform: Platform, json: bool) -> io::Result<i32> {
    let dir = project_dir();
    let rows = inspect::status(platform, &dir)?;
    if rows.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no project in {}: nothing to report", dir.display()),
        ));
    }
    print!("{}", inspect::render_status(&dir, &rows, json)?);
    if !rows.iter().all(inspect::EcosystemStatus::is_synced) {
        return Ok(cli::EXIT_FAILURE);
    }
    Ok(0)
}
