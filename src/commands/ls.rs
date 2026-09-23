//! `tog ls`: list the packages recorded in the project's closures.

use crate::commands::inspect;
use crate::commands::shared::project_dir;
use crate::kernel::activity::ActivityMode;
use crate::kernel::store;
use crate::kernel::ui;
use std::io;

// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
pub fn run(ecosystem: Option<&str>, json: bool) -> io::Result<i32> {
    let store = store::Store::open()?;
    let _activity = store.activity(ActivityMode::Shared)?;
    print!(
        "{}",
        inspect::ls(&project_dir(), ecosystem, json, ui::verbose())?
    );
    Ok(0)
}
