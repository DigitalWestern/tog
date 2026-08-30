//! Wheel installer: unpack a .whl into a target environment, PEP 427 style.
//!
//! IMPLEMENTATION CONTRACT (see install_wheel below) — being implemented.

use std::io;
use std::path::Path;

/// Install one wheel file into an environment being assembled.
///
/// * `wheel_path`     — verified .whl on disk (a zip).
/// * `site_packages`  — env's lib/pythonX.Y/site-packages (exists).
/// * `bin_dir`        — env's bin/ (exists).
/// * `python_exe`     — absolute path to the env's bin/python (for shebangs
///                      and console-script generation).
///
/// Required behavior (PEP 427, pragmatic subset):
/// 1. Unzip everything except `{name}-{ver}.data/` into `site_packages`.
///    Preserve unix mode bits from zip external attrs when present.
/// 2. For `{name}-{ver}.data/`:
///      purelib/, platlib/  -> merge into site_packages
///      scripts/            -> into bin_dir; rewrite `#!python` shebang
///                             (any first line starting with b"#!python")
///                             to `#!{python_exe}`; set exec bit.
///      data/               -> merge into env root (bin_dir.parent()).
/// 3. Read `{name}-{ver}.dist-info/entry_points.txt`; for each entry in
///    [console_scripts] `name = module:func`, write an executable launcher
///    to bin_dir:
///        #!{python_exe}
///        import sys
///        from module import func_root  (handle dotted attrs: from m import a; obj = a.b.c)
///        sys.exit(obj())
///    Use the standard pattern:
///        #!/abs/python
///        # -*- coding: utf-8 -*-
///        import re, sys
///        from {module} import {attr0}
///        if __name__ == "__main__":
///            sys.argv[0] = re.sub(r"(-script\.pyw?|\.exe)?$", "", sys.argv[0])
///            sys.exit({attr_full}())
/// 4. Never write outside site_packages / bin_dir / env root. Reject zip
///    entries containing ".." or absolute paths (zip-slip guard).
/// 5. Leave RECORD as shipped; do not rewrite it (v0).
///
/// [gui_scripts] may be treated as console_scripts. Other entry point groups
/// are ignored.
pub fn install_wheel(
    wheel_path: &Path,
    site_packages: &Path,
    bin_dir: &Path,
    python_exe: &Path,
) -> io::Result<()> {
    let _ = (wheel_path, site_packages, bin_dir, python_exe);
    todo!("luna: implement")
}
