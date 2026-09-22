//! `tog doctor`: environment health checks over the project and store.

use crate::cli;
use crate::commands::inspect;
use crate::commands::selfupdate;
use crate::commands::shared::project_dir;
use crate::kernel::activity::ActivityMode;
use crate::kernel::store;
use std::io;

pub fn run(json: bool) -> io::Result<i32> {
    let store = store::Store::open()?;
    let _activity = store.activity(ActivityMode::Shared)?;
    // The build comes first: every other row is read against it. It is the
    // one row that talks to the network, and it lives here rather than in
    // `inspect::doctor`, which stays offline for the callers that need it
    // to be.
    let mut checks = vec![selfupdate::doctor_check()];
    checks.extend(inspect::doctor(&project_dir()));
    print!("{}", inspect::render_doctor(&checks, json)?);
    if checks
        .iter()
        .any(|check| check.level == inspect::Level::Fail)
    {
        return Ok(cli::EXIT_FAILURE);
    }
    Ok(0)
}
