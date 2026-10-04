//! `tog store roots` / `tog store path`: read-only store diagnostics.
//! Kernel only; work without a valid host platform.

use crate::kernel::store;
use crate::kernel::ui;
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
    // A store this tog refuses to open still has a path, and the path is
    // what someone moving it aside needs: print it, and say on stderr why
    // nothing else will use it.
    if let Some((root, format)) = store::Store::probe()? {
        if let Some(refusal) = format.refusal(&root) {
            println!("{}", root.display());
            ui::warning(&refusal, format.fix());
            return Ok(0);
        }
    }
    let store = store::Store::open()?;
    println!("{}", store.root.display());
    Ok(0)
}
