//! `blanket store roots` / `blanket store path`: read-only store diagnostics.
//! Kernel only; work without a valid host platform.

use crate::kernel::store;
use std::io;

pub fn roots() -> io::Result<()> {
    for root in store::Store::open()?.root_diagnostics()? {
        match (root.path, root.problem) {
            (Some(path), None) => println!("{}  {}", root.key, path.display()),
            (_, Some(problem)) => println!("{}  <invalid: {}>", root.key, problem),
            _ => println!("{}  <invalid root record>", root.key),
        }
    }
    Ok(())
}

pub fn path() -> io::Result<i32> {
    let store = store::Store::open()?;
    println!("{}", store.root.display());
    Ok(0)
}
