//! `tog doctor`: environment health checks over the project and store.

use crate::cli;
use crate::commands::inspect;
use crate::commands::shared::project_dir;
use crate::kernel::activity::ActivityMode;
use crate::kernel::store;
use std::io;

pub fn run(json: bool) -> io::Result<i32> {
    let store = store::Store::open()?;
    let _activity = store.activity(ActivityMode::Shared)?;
    let checks = inspect::doctor(&project_dir());
    print!("{}", inspect::render_doctor(&checks, json)?);
    if checks
        .iter()
        .any(|check| check.level == inspect::Level::Fail)
    {
        return Ok(cli::EXIT_FAILURE);
    }
    Ok(0)
}
