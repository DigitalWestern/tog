//! `tog doctor`: environment health checks over the project and store.

use crate::cli;
use crate::commands::inspect;
use crate::commands::selfupdate;
use crate::commands::shared::project_dir;
use crate::kernel::store;
use std::io;

// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
pub fn run(json: bool, isolation: bool) -> io::Result<i32> {
    // The store is judged once, here, and the answer travels with its
    // lease: `inspect::doctor` reads a store only through the pair, so it
    // never reads one this command did not open and lease, and a store
    // that changes while doctor runs cannot move it from one answer to the
    // other. A store that cannot be opened or leased (one this tog refuses
    // among them) is a failing row with its fix, not a reason to print no
    // rows at all. Nor is a busy one: the lease is taken without waiting,
    // so behind a sweep or a reset doctor says the store is in use and
    // still runs every check that needs no store.
    let store = match store::Store::open() {
        Ok(store) => match store.try_activity_shared() {
            Ok(activity) => Ok((store, activity)),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let store = store
        .as_ref()
        .map(|(store, activity)| (store, activity.as_ref()));
    // The build comes first: every other row is read against it. It is the
    // one row that talks to the network, and it lives here rather than in
    // `inspect::doctor`, which stays offline for the callers that need it
    // to be.
    let checks = if isolation {
        inspect::isolation_doctor(store)?
    } else {
        let mut checks = vec![selfupdate::doctor_check()];
        checks.extend(inspect::doctor(&project_dir(), store));
        checks
    };
    print!("{}", inspect::render_doctor(&checks, json)?);
    if checks
        .iter()
        .any(|check| check.level == inspect::Level::Fail)
    {
        return Ok(cli::EXIT_FAILURE);
    }
    Ok(0)
}
