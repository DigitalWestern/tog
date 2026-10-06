//! `HostView::RuntimeOnly` on Linux: the host's system directories as a
//! sandboxed build sees them when it may use the C runtime and nothing else
//! the host happens to have installed (issue #304).
//!
//! The view is bubblewrap mounts applied on top of the full system root
//! `sandbox::system_root_args` binds. Each curated directory is replaced by
//! a skeleton directory tog builds on the host for the run. Every kept
//! subdirectory is bound from the host onto its placeholder there, and
//! every kept file is a symlink into `HOST_FILES`, where the whole host
//! directory is bound once (#334): a file costs no mount, so the view's
//! setup stays a few hundred mounts however many libraries the host has.
//! A dropped entry is absent from every path the build searches: no header
//! search, `-l` lookup, pkg-config query or listing of a curated directory
//! inside the sandbox can find it. A regular ELF shared library the linker
//! must not find, but host programs may load, moves to `RUNTIME_SUBDIR`
//! instead.
//!
//! A library subdirectory is bound whole when nothing under it is a
//! development file. One that holds headers, static or libtool archives,
//! `pkgconfig` or `cmake` (`/usr/lib64/perl5/CORE`,
//! `/usr/lib64/python3.14/site-packages/cffi`, `/usr/lib64/libnl`), or that
//! tog cannot list, is curated in turn with the library rule
//! (`Curation::Subtree`), so an explicit `-I` or `-L` into it finds no more
//! than the default paths do (#331). The compiler's own directories (`gcc`,
//! `clang`) are bound whole.

use crate::kernel::sandbox::{host_layout_error, push_arg};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The `PKG_CONFIG_LIBDIR` a `RuntimeOnly` build gets unless its caller sets
/// one. The view already empties every pkg-config directory; this keeps
/// pkg-config from falling back to the defaults compiled into it. Not the
/// empty string: pkgconf 2.x treats an empty `PKG_CONFIG_LIBDIR` as unset
/// and searches its defaults (checked with pkgconf 2.5.1). `/dev/null` is
/// not a directory on any host, so no `.pc` file resolves under it, for
/// pkgconf and freedesktop pkg-config alike, and `PKG_CONFIG_PATH` still
/// works for a build that sets it itself.
pub(crate) const PKG_CONFIG_LIBDIR: &str = "/dev/null";

/// The subdirectory of each curated library directory that holds the
/// host's regular ELF `lib*.so` files (see `Placement::Runtime`). GNU ld
/// never searches a subdirectory of its search path, so `-l` cannot find
/// what is here; the dynamic loader finds it through `LD_LIBRARY_PATH`.
pub(crate) const RUNTIME_SUBDIR: &str = ".tog-host-runtime";

/// Where the view binds each whole curated host directory, for the
/// skeleton's symlinks to reach the files it keeps: `/usr/lib64/libc.so.6`
/// is a symlink to `HOST_FILES/usr/lib64/libc.so.6`. A dropped file is
/// still under this path, but nothing searches it: no default include or
/// library path, pkg-config directory or `-L` a build would write names
/// it. The view keeps builds from depending on host files by accident; a
/// build that names this path on purpose is not what it guards against.
pub(crate) const HOST_FILES: &str = "/.tog-host-files";

/// The subdirectories of a library directory that are the compiler's own,
/// bound whole: their headers and archives are what every compile reads.
const COMPILER_DIRS: &[&str] = &["gcc", "clang"];

/// The suffixes of a header file in a library subdirectory
/// (`Curation::Subtree`).
const HEADER_SUFFIXES: &[&str] = &[".h", ".hh", ".hpp", ".hxx", ".h++", ".H", ".inl", ".tcc"];

/// One run's `RuntimeOnly` view.
pub(crate) struct RuntimeOnlyView {
    /// The bubblewrap arguments that mount it.
    pub(crate) mounts: Vec<OsString>,
    /// The skeleton they mount from; it must outlive the child.
    pub(crate) skeleton: ViewSkeleton,
    /// The `RUNTIME_SUBDIR` directories the view has, in library directory
    /// order: the build's `LD_LIBRARY_PATH`, so host programs still load
    /// the libraries that were moved out of the linker's reach.
    pub(crate) library_path: Vec<PathBuf>,
}

/// The `RuntimeOnly` view for one run. The skeleton must not sit under a
/// root the build may write: its directories become `/usr/include`,
/// `/usr/lib64` and the rest, so a build that could write to it could add
/// files to the view.
pub(crate) fn runtime_only_mounts(write_roots: &[PathBuf]) -> io::Result<RuntimeOnlyView> {
    let skeleton = ViewSkeleton::create()?;
    if let Some(root) = write_roots
        .iter()
        .find(|root| skeleton.path().starts_with(root))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the host view skeleton {} would sit inside the writable sandbox root {}; \
                 point TMPDIR somewhere else",
                skeleton.path().display(),
                root.display()
            ),
        ));
    }
    let (mounts, library_path) = runtime_only_args(Path::new("/"), skeleton.path())?;
    Ok(RuntimeOnlyView {
        mounts,
        skeleton,
        library_path,
    })
}

/// How `HostView::RuntimeOnly` treats the entries of one curated directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Curation {
    /// Keep only the names in `C_RUNTIME_HEADERS`.
    Headers,
    /// Keep runtime libraries and everything else, drop what only a link
    /// step reads (`library_entry_placement`).
    Libraries,
    /// Keep nothing.
    Empty,
    /// A library subdirectory with development files under it: drop what
    /// `Libraries` drops, keep plugins and extension modules where they are
    /// (`library_entry_placement`). One tog cannot list is empty.
    Subtree,
}

/// The directories `HostView::RuntimeOnly` rebuilds, in mount order. Each is
/// curated only where the host has it as a real directory: a symlink (the
/// merged-/usr `/lib64 -> usr/lib64`) already lands in a curated directory,
/// and a missing one stays missing. The top-level `/lib*` entries are real
/// directories only on split-/usr hosts, where `system_root_args` binds them.
const CURATED_DIRS: &[(&str, Curation)] = &[
    ("/usr/include", Curation::Headers),
    ("/usr/local/include", Curation::Headers),
    ("/usr/lib", Curation::Libraries),
    ("/usr/lib64", Curation::Libraries),
    ("/usr/lib32", Curation::Libraries),
    ("/usr/libx32", Curation::Libraries),
    ("/usr/local/lib", Curation::Libraries),
    ("/usr/local/lib64", Curation::Libraries),
    ("/lib", Curation::Libraries),
    ("/lib64", Curation::Libraries),
    ("/lib32", Curation::Libraries),
    ("/libx32", Curation::Libraries),
    ("/usr/share/pkgconfig", Curation::Empty),
    ("/usr/local/share/pkgconfig", Curation::Empty),
];

/// Debian's multiarch directories, curated with their parent's rule when
/// the parent's listing reaches them as real directories.
const CURATED_NESTED: &[&str] = &[
    "/usr/include/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu",
];

/// The top-level include entries the C runtime installs: glibc's headers,
/// libxcrypt's `crypt.h`, the kernel's UAPI directories, and `c++` (the
/// compiler's own C++ library headers). The union of what the package
/// managers list for Fedora 44 (glibc-devel, glibc-headers-x86,
/// kernel-headers, libxcrypt-devel, libstdc++-devel) and Ubuntu 22.04
/// (libc6-dev, linux-libc-dev, libcrypt-dev, libstdc++-11-dev).
///
/// A name missing here fails loudly: the build stops with a compile error
/// naming the header. Maintain the list by adding that name after checking
/// which package owns it, never by widening the rule.
const C_RUNTIME_HEADERS: &[&str] = &[
    "a.out.h",
    "aio.h",
    "aliases.h",
    "alloca.h",
    "ar.h",
    "argp.h",
    "argz.h",
    "arpa",
    "asm",
    "asm-generic",
    "assert.h",
    "bits",
    "byteswap.h",
    "c++",
    "complex.h",
    "cpio.h",
    "crypt.h",
    "ctype.h",
    "cxl",
    "dirent.h",
    "dlfcn.h",
    "drm",
    "elf.h",
    "endian.h",
    "envz.h",
    "err.h",
    "errno.h",
    "error.h",
    "execinfo.h",
    "fcntl.h",
    "features-time64.h",
    "features.h",
    "fenv.h",
    "finclude",
    "fmtmsg.h",
    "fnmatch.h",
    "fpu_control.h",
    "fstab.h",
    "fts.h",
    "ftw.h",
    "fwctl",
    "gconv.h",
    "getopt.h",
    "glob.h",
    "gnu",
    "gnu-versions.h",
    "grp.h",
    "gshadow.h",
    "iconv.h",
    "ieee754.h",
    "ifaddrs.h",
    "inttypes.h",
    "langinfo.h",
    "lastlog.h",
    "libgen.h",
    "libintl.h",
    "limits.h",
    "link.h",
    "linux",
    "locale.h",
    "malloc.h",
    "math.h",
    "mcheck.h",
    "memory.h",
    "misc",
    "mntent.h",
    "monetary.h",
    "mqueue.h",
    "mtd",
    "net",
    "netash",
    "netatalk",
    "netax25",
    "netdb.h",
    "neteconet",
    "netinet",
    "netipx",
    "netiucv",
    "netpacket",
    "netrom",
    "netrose",
    "nfs",
    "nl_types.h",
    "nss.h",
    "obstack.h",
    "paths.h",
    "poll.h",
    "printf.h",
    "proc_service.h",
    "protocols",
    "pthread.h",
    "pty.h",
    "pwd.h",
    "rdma",
    "re_comp.h",
    "regex.h",
    "regexp.h",
    "regulator",
    "resolv.h",
    "rpc",
    "sched.h",
    "scsi",
    "search.h",
    "semaphore.h",
    "setjmp.h",
    "sgtty.h",
    "shadow.h",
    "signal.h",
    "sound",
    "spawn.h",
    "stab.h",
    "stdbit.h",
    "stdc-predef.h",
    "stdint.h",
    "stdio.h",
    "stdio_ext.h",
    "stdlib.h",
    "string.h",
    "strings.h",
    "sys",
    "syscall.h",
    "sysexits.h",
    "syslog.h",
    "tar.h",
    "termio.h",
    "termios.h",
    "tgmath.h",
    "thread_db.h",
    "threads.h",
    "time.h",
    "ttyent.h",
    "uchar.h",
    "ucontext.h",
    "ulimit.h",
    "unistd.h",
    "utime.h",
    "utmp.h",
    "utmpx.h",
    "values.h",
    "video",
    "wait.h",
    "wchar.h",
    "wctype.h",
    "wordexp.h",
    "xen",
];

/// `lib<name>.so` link-time entries of the C runtime, kept even when they
/// are symlinks or linker scripts (`libc.so` and `libm.so` are text).
const C_RUNTIME_SHARED: &[&str] = &[
    "libc",
    "libm",
    "libmvec",
    "libpthread",
    "libdl",
    "librt",
    "libutil",
    "libresolv",
    "libanl",
    "libBrokenLocale",
    "libthread_db",
    "libc_malloc_debug",
    "libnss_compat",
    "libnss_hesiod",
    "libcrypt",
];

/// The C runtime's static archives. `libm-<version>.a` (Debian's, which
/// the `libm.a` linker script names) is matched by prefix.
const C_RUNTIME_ARCHIVES: &[&str] = &[
    "libc",
    "libc_nonshared",
    "libm",
    "libmvec",
    "libpthread",
    "libpthread_nonshared",
    "libdl",
    "librt",
    "libutil",
    "libresolv",
    "libanl",
    "libBrokenLocale",
    "libg",
    "libmcheck",
    "libcrypt",
];

/// The C runtime's start files, which every link of a program reads.
const C_RUNTIME_OBJECTS: &[&str] = &[
    "crt1", "Scrt1", "crti", "crtn", "gcrt1", "grcrt1", "Mcrt1", "rcrt1",
];

const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

/// Where one entry of a curated directory goes in the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Placement {
    /// Where the host has it.
    Keep,
    /// Into the directory's `RUNTIME_SUBDIR`: a regular ELF file named
    /// `*.so` that is not the C runtime's. Such a file is a runtime library
    /// some host program NEEDs by that very name (Fedora's `libnss3.so`,
    /// binutils' `libbfd-<version>.so`, which `ld` itself loads), so it
    /// cannot be dropped, but where it is `-lnss3` would link it.
    Runtime,
    /// Absent from the view.
    Drop,
    /// A directory mirrored and curated with `Curation::Subtree`: it holds
    /// development files somewhere under it.
    Curate,
}

/// Where an entry of a library directory (`Curation::Libraries`) or of a
/// library subdirectory curated in turn (`Curation::Subtree`) goes in the
/// `RuntimeOnly` view. One rule for both, so a `-L` into a curated
/// subdirectory finds no more than the default paths do.
///
/// Dropped: `pkgconfig` and `cmake` directories, headers, static (`.a`),
/// libtool (`.la`) and object (`.o`) files, and every `lib*.so` symlink or
/// linker script a link step would find by `-l` (what a `-dev` package
/// adds). A subdirectory is bound whole unless something under it is a
/// development file (`holds_dev_files`), and curated in turn otherwise;
/// the compiler's own directories (`gcc`, `clang`) are always whole.
///
/// The two curations differ where a library directory and a subdirectory
/// hold different things:
/// - The C runtime's own entries stay where they are in a library
///   directory. A subdirectory holds none of them, so the same names
///   there (a `libc.a` of some other libc) are another package's
///   development files and drop.
/// - A regular ELF `*.so` in a library directory moves out of the
///   linker's reach (`Placement::Runtime`). In a subdirectory it stays:
///   Python and Perl extension modules and other plugins there are loaded
///   by that path. A regular ELF `lib*.so` in a curated subdirectory thus
///   stays linkable with an explicit `-L`.
/// - A `.so` not named `lib*` stays in a subdirectory, whatever it is:
///   `-l` cannot find it, and a plugin may be a symlink.
fn library_entry_placement(
    name: &str,
    file_type: fs::FileType,
    host_entry: &Path,
    curation: Curation,
) -> Placement {
    let subtree = curation == Curation::Subtree;
    let c_runtime = |list: &[&str], stem: &str| !subtree && list.contains(&stem);
    let keep_if = |kept: bool| {
        if kept {
            Placement::Keep
        } else {
            Placement::Drop
        }
    };
    if name == "pkgconfig" || name == "cmake" || name == RUNTIME_SUBDIR {
        return Placement::Drop;
    }
    if file_type.is_dir() {
        return if COMPILER_DIRS.contains(&name) || !holds_dev_files(host_entry) {
            Placement::Keep
        } else {
            Placement::Curate
        };
    }
    if is_header(name) {
        return Placement::Drop;
    }
    if let Some(stem) = name.strip_suffix(".so") {
        if c_runtime(C_RUNTIME_SHARED, stem) || (subtree && !name.starts_with("lib")) {
            return Placement::Keep;
        }
        if file_type.is_file() && starts_with_elf_magic(host_entry) {
            return if subtree {
                Placement::Keep
            } else {
                Placement::Runtime
            };
        }
        return Placement::Drop;
    }
    if let Some(stem) = name.strip_suffix(".a") {
        return keep_if(
            c_runtime(C_RUNTIME_ARCHIVES, stem) || (!subtree && stem.starts_with("libm-")),
        );
    }
    if name.ends_with(".la") {
        return Placement::Drop;
    }
    if let Some(stem) = name.strip_suffix(".o") {
        return keep_if(c_runtime(C_RUNTIME_OBJECTS, stem));
    }
    Placement::Keep
}

/// Whether `name` is a header file.
fn is_header(name: &str) -> bool {
    HEADER_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Whether a library subdirectory entry marks the subdirectory as holding
/// a `-devel` package's files: a header, a static or libtool archive, a
/// `pkgconfig` or `cmake` directory. Narrower than what curation then
/// drops: a `lib*.so` symlink alone marks nothing, as plugin directories
/// are full of them (`bfd-plugins/liblto_plugin.so`, which `ld` loads by
/// that name, `sasl2`, `xtables`, `libibverbs`), and dropping them would
/// break the programs that load them. A subdirectory whose only
/// development file is such a symlink or linker script is bound whole.
fn marks_dev_dir(name: &str, file_type: fs::FileType) -> bool {
    if file_type.is_dir() {
        return name == "pkgconfig" || name == "cmake";
    }
    is_header(name) || name.ends_with(".a") || name.ends_with(".la")
}

/// Whether anything under the host directory `host` marks it as holding
/// development files (`marks_dev_dir`), stopping at the first. Symlinks
/// are not followed. A directory tog cannot list may hold any of them, by
/// a name the build can still open, so it counts as holding some: curated,
/// it is an empty directory in the view (`classify_dir`).
fn holds_dev_files(host: &Path) -> bool {
    let Ok(entries) = fs::read_dir(host) else {
        return true;
    };
    entries.flatten().any(|entry| {
        let Ok(file_type) = entry.file_type() else {
            return false;
        };
        let name = entry.file_name();
        marks_dev_dir(&name.to_string_lossy(), file_type)
            || (file_type.is_dir() && holds_dev_files(&entry.path()))
    })
}

/// A file tog cannot read is one the build cannot read either, so failing
/// to read it counts as "not ELF" and drops it.
fn starts_with_elf_magic(path: &Path) -> bool {
    use std::io::Read as _;
    let mut magic = [0u8; 4];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok_and(|()| magic == ELF_MAGIC)
}

/// The host-side tree the `RuntimeOnly` view mounts: one directory per
/// curated directory, holding the kept symlinks themselves and an empty
/// file or directory where each kept file or directory is bound on top.
/// Symlinks cost no bubblewrap arguments this way, which keeps a host with
/// thousands of library entries under bubblewrap's argument limit
/// (`sandbox::BWRAP_MAX_ARGS`). Built fresh for every run under the
/// temporary directory and deleted when dropped.
pub(crate) struct ViewSkeleton {
    path: PathBuf,
    /// The exclusive `flock` on `SKELETON_LOCK` that marks this skeleton
    /// live for as long as it exists (`sweep_stale_skeletons`). It is
    /// close-on-exec, as std opens every file: the skeleton lives exactly
    /// as long as this tog, whose `Drop` removes it, so a sandboxed child
    /// (or a daemon it left behind) must not keep it marked live after tog
    /// is gone. `None` only where the filesystem has no `flock`.
    _lock: Option<fs::File>,
}

impl ViewSkeleton {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The root is private (mode 0700, whatever the umask) and its name
    /// carries a random nonce, so no other local user can find it early or
    /// change what it mirrors while a build runs. `create` refuses a name
    /// that already exists, so a planted directory or symlink is skipped,
    /// never used.
    fn create() -> io::Result<Self> {
        use std::hash::{BuildHasher as _, Hasher as _};
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = fs::canonicalize(std::env::temp_dir())?;
        sweep_stale_skeletons(&base);
        loop {
            let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // `RandomState` is seeded from the operating system's random
            // source; hashing the sequence under it gives an unguessable
            // nonce without another dependency.
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u64(sequence);
            let path = base.join(format!(
                "{SKELETON_PREFIX}{}-{:016x}",
                std::process::id(),
                hasher.finish()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    // The umask can only narrow the mode `create` asked
                    // for; under `umask 077`-and-stricter it could leave a
                    // root bubblewrap cannot traverse. Set it outright.
                    let mut skeleton = Self { path, _lock: None };
                    fs::set_permissions(skeleton.path(), fs::Permissions::from_mode(0o700))?;
                    skeleton._lock = lock_skeleton(skeleton.path())?;
                    return Ok(skeleton);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("create the sandbox host view {}: {error}", path.display()),
                    ))
                }
            }
        }
    }
}

impl Drop for ViewSkeleton {
    fn drop(&mut self) {
        // The lock field drops after this, so the skeleton stays marked
        // live until it is gone.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Create a fresh skeleton's lock file and take its exclusive `flock`. A
/// filesystem with no `flock` leaves the skeleton unlocked: the lock file
/// it still has keeps every sweep away from it, as no sweep can lock it
/// either, and a leftover is inert where a refused build is not.
fn lock_skeleton(root: &Path) -> io::Result<Option<fs::File>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = root.join(SKELETON_LOCK);
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "create the sandbox host view lock {}: {error}",
                    path.display()
                ),
            )
        })?;
    Ok(file.try_lock().is_ok().then_some(file))
}

/// Every skeleton's name: this prefix, the creating tog's pid, a dash, and a
/// 16-hex-digit nonce.
const SKELETON_PREFIX: &str = "tog-host-view-";

/// The file in a skeleton's root its tog holds an exclusive `flock` on for
/// the skeleton's whole life. The view mounts only the curated directories
/// under the root, so the build never sees it.
const SKELETON_LOCK: &str = ".lock";

/// How long a skeleton whose tog is gone is left alone before a later run
/// removes it. The pid check alone would do on one machine, but a tog in
/// another pid namespace sharing this TMPDIR (a container) has a pid that
/// means nothing here. Its skeleton's lock (`SKELETON_LOCK`) is what keeps
/// a long build's view in place; the age covers a skeleton an older tog
/// made without one, and the moment before a new one takes its lock.
const STALE_SKELETON_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Remove the skeletons a killed tog left in `base` (issue #335): `Drop`
/// never ran for a SIGKILL. Only a real directory this user owns, named
/// like a skeleton, whose tog is no longer running, which has not changed
/// for `STALE_SKELETON_AGE`, and whose lock no one holds is removed; one
/// with no lock file, made by an older tog, is judged by the rest alone.
/// Anything else, and any failure, is left as it is: a leftover is inert,
/// so the sweep never stops a build.
fn sweep_stale_skeletons(base: &Path) {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(skeleton_pid) else {
            continue;
        };
        if pid == std::process::id() || process_exists(pid) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        let stale = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= STALE_SKELETON_AGE);
        if !(metadata.is_dir() && metadata.uid() == uid && stale) {
            continue;
        }
        // Held while the tree goes, so its owner cannot be mid-setup.
        let Ok(_lock) = skeleton_unlocked(&path) else {
            continue;
        };
        let _ = fs::remove_dir_all(&path);
    }
}

/// The skeleton's lock taken without waiting, `None` for a skeleton with
/// no lock file, or an error while its tog still holds it (or it cannot be
/// read). The lock file is opened without following a symlink.
fn skeleton_unlocked(root: &Path) -> io::Result<Option<fs::File>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(SKELETON_LOCK))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
        Err(fs::TryLockError::Error(error)) => Err(error),
    }
}

/// The pid in a skeleton's name, or `None` for any other name.
fn skeleton_pid(name: &str) -> Option<u32> {
    let (pid, nonce) = name.strip_prefix(SKELETON_PREFIX)?.split_once('-')?;
    if nonce.len() != 16 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    pid.parse()
        .ok()
        .filter(|pid| *pid > 0 && i32::try_from(*pid).is_ok())
}

/// Whether a process with this pid exists. EPERM means it exists under
/// another user.
fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks the pid; `skeleton_pid` never yields 0
    // or a negative pid, which would address a process group.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The mounts that turn the full system root `system_root_args` binds into
/// `HostView::RuntimeOnly`, applied after it. Each directory in
/// `CURATED_DIRS` the host has is replaced by its skeleton directory under
/// `skeleton` (read-only), and the whole host directory is bound read-only
/// under `HOST_FILES`. Every kept file is a symlink into that bind, every
/// subdirectory kept whole is bound read-only from the host onto its
/// placeholder, and kept symlinks are recreated in the skeleton with the
/// host's own targets. Nothing is
/// cached: the host directories are read again on every run. Also returns
/// the `RUNTIME_SUBDIR` directories the view has, in mount order.
///
/// `host_root` is `/` in production; tests pass a fake host layout.
fn runtime_only_args(
    host_root: &Path,
    skeleton: &Path,
) -> io::Result<(Vec<OsString>, Vec<PathBuf>)> {
    let mut args = Vec::new();
    let mut library_path = Vec::new();
    for (inside, host, curation) in curated_roots(host_root)? {
        let relative = inside.strip_prefix("/").unwrap_or(inside);
        let mirror = skeleton.join(relative);
        fs::create_dir_all(&mirror)?;
        push_arg(&mut args, "--ro-bind");
        args.push(mirror.clone().into_os_string());
        args.push(inside.as_os_str().to_os_string());
        if curation != Curation::Empty {
            push_arg(&mut args, "--ro-bind");
            args.push(host.clone().into_os_string());
            args.push(host_files_path(inside).into_os_string());
            curate_dir(
                &host,
                inside,
                &mirror,
                curation,
                &mut args,
                &mut library_path,
            )?;
        }
    }
    Ok((args, library_path))
}

/// Where the host's `inside` is under `HOST_FILES`.
fn host_files_path(inside: &Path) -> PathBuf {
    Path::new(HOST_FILES).join(inside.strip_prefix("/").unwrap_or(inside))
}

/// The `CURATED_DIRS` this host has as real directories: where each is in
/// the sandbox, where it is under `host_root`, and its curation.
fn curated_roots(host_root: &Path) -> io::Result<Vec<(&'static Path, PathBuf, Curation)>> {
    let mut roots = Vec::new();
    for &(inside, curation) in CURATED_DIRS {
        let inside = Path::new(inside);
        let host = host_root.join(inside.strip_prefix("/").unwrap_or(inside));
        match fs::symlink_metadata(&host) {
            Ok(metadata) if metadata.is_dir() => roots.push((inside, host, curation)),
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(host_layout_error(&host, error)),
        }
    }
    Ok(roots)
}

/// Mirror the kept entries of one host directory into `mirror`: files as
/// symlinks under `HOST_FILES`, symlinks as themselves, subdirectories kept
/// whole as binds, curated ones in turn. Entries are visited in name order so
/// the command line is the same on every run of an unchanged host.
fn curate_dir(
    host: &Path,
    inside: &Path,
    mirror: &Path,
    curation: Curation,
    args: &mut Vec<OsString>,
    library_path: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let entries = classify_dir(host, inside, curation)?;
    // A kept symlink naming a moved file in this directory (`libfoo.so.1
    // -> libfoo.so`) follows it into the runtime subdirectory.
    let moved: Vec<&OsStr> = entries
        .iter()
        .filter(|(_, _, _, placement)| *placement == Placement::Runtime)
        .map(|(name, ..)| name.as_os_str())
        .collect();
    if !moved.is_empty() {
        fs::create_dir(mirror.join(RUNTIME_SUBDIR))?;
        library_path.push(inside.join(RUNTIME_SUBDIR));
    }
    for (name, file_type, nested, placement) in &entries {
        let host_entry = host.join(name);
        let (inside_entry, mirror_entry) = match placement {
            Placement::Drop => continue,
            Placement::Keep | Placement::Curate => (inside.join(name), mirror.join(name)),
            Placement::Runtime => (
                inside.join(RUNTIME_SUBDIR).join(name),
                mirror.join(RUNTIME_SUBDIR).join(name),
            ),
        };
        let nested_curation = match placement {
            Placement::Curate => Some(Curation::Subtree),
            _ if *nested && file_type.is_dir() => Some(curation),
            _ => None,
        };
        if let Some(nested_curation) = nested_curation {
            fs::create_dir(&mirror_entry)?;
            curate_dir(
                &host_entry,
                &inside_entry,
                &mirror_entry,
                nested_curation,
                args,
                library_path,
            )?;
            continue;
        }
        if file_type.is_symlink() {
            let target = fs::read_link(&host_entry)
                .map_err(|error| host_layout_error(&host_entry, error))?;
            let target = if moved.contains(&target.as_os_str()) {
                Path::new(RUNTIME_SUBDIR).join(&target)
            } else {
                target
            };
            std::os::unix::fs::symlink(&target, &mirror_entry)?;
            continue;
        }
        if file_type.is_file() {
            // A file is a symlink to its host copy, under the whole
            // directory's bind (`HOST_FILES`): no mount of its own.
            std::os::unix::fs::symlink(host_files_path(&inside.join(name)), &mirror_entry)?;
            continue;
        }
        if !file_type.is_dir() {
            // Sockets, fifos and device nodes have no business in a system
            // library or include directory.
            continue;
        }
        fs::create_dir(&mirror_entry)?;
        push_arg(args, "--ro-bind");
        args.push(host_entry.into_os_string());
        args.push(inside_entry.into_os_string());
    }
    Ok(())
}

/// One entry of a curated host directory: its name, its type, whether it
/// is a `CURATED_NESTED` directory, and where the view puts it.
type Classified = (OsString, fs::FileType, bool, Placement);

/// Where the view puts each entry of the curated host directory `host`
/// (`inside` in the sandbox), in name order. The one place the curation
/// rules are applied, so the view and `host_build_inputs` cannot disagree.
fn classify_dir(host: &Path, inside: &Path, curation: Curation) -> io::Result<Vec<Classified>> {
    let listing = match fs::read_dir(host) {
        // A subdirectory tog cannot list is curated because it may hold
        // development files (`holds_dev_files`): it keeps nothing.
        Err(error)
            if curation == Curation::Subtree && error.kind() == io::ErrorKind::PermissionDenied =>
        {
            return Ok(Vec::new());
        }
        listing => listing.map_err(|error| host_layout_error(host, error))?,
    };
    let mut names = Vec::new();
    for entry in listing {
        names.push(
            entry
                .map_err(|error| host_layout_error(host, error))?
                .file_name(),
        );
    }
    names.sort();
    let mut entries = Vec::new();
    for name in names {
        let host_entry = host.join(&name);
        let file_type = fs::symlink_metadata(&host_entry)
            .map_err(|error| host_layout_error(&host_entry, error))?
            .file_type();
        let inside_entry = inside.join(&name);
        let nested = CURATED_NESTED
            .iter()
            .any(|path| Path::new(path) == inside_entry);
        let text = name.to_string_lossy();
        let placement = match curation {
            _ if nested && file_type.is_dir() => Placement::Keep,
            Curation::Headers if nested || C_RUNTIME_HEADERS.contains(&text.as_ref()) => {
                Placement::Keep
            }
            Curation::Headers | Curation::Empty => Placement::Drop,
            Curation::Libraries | Curation::Subtree => {
                library_entry_placement(&text, file_type, &host_entry, curation)
            }
        };
        entries.push((name, file_type, nested, placement));
    }
    Ok(entries)
}

/// A digest of everything a build against the whole host (`HostView::Full`)
/// sees that a `RuntimeOnly` build does not, plus the compiler: every entry
/// the view drops from a curated directory (whole trees for dropped
/// directories such as `/usr/include/libxml2`, `pkgconfig` and `cmake`),
/// every library it moves into `RUNTIME_SUBDIR`, for each such symlink the
/// file its chain finally resolves to (a dropped `liblzma.so` covers the
/// kept `liblzma.so.5.8.1` a `-llzma` link reads), what `/usr/bin/cc` and
/// `/usr/bin/c++` resolve to, and every file under `/usr/lib/gcc` and
/// `/usr/libexec/gcc`. Hex SHA-256.
///
/// It is stat-based: each entry contributes its path, type, size,
/// modification time and symlink target, and a resolved target its inode
/// and device too, never file bytes. Installing, removing or upgrading a
/// development package changes it; rewriting a file with bytes of the same
/// size and putting its modification time back does not. The walk
/// classifies entries with the view's own rules (`classify_dir`), so the
/// two cannot disagree about what is dropped. Any read that fails is an
/// error: an unreadable directory never passes for an empty one.
pub(crate) fn host_build_inputs() -> io::Result<String> {
    host_build_inputs_at(Path::new("/"))
}

fn host_build_inputs_at(host_root: &Path) -> io::Result<String> {
    use sha2::Digest as _;
    let mut digest = Fingerprint {
        host_root,
        digest: sha2::Sha256::new(),
    };
    digest.digest.update(b"tog-host-build-inputs/3");
    for (inside, host, curation) in curated_roots(host_root)? {
        if curation == Curation::Empty {
            digest.tree(&host, inside)?;
        } else {
            digest.dropped(&host, inside, curation)?;
        }
    }
    // The compilers the full view's PATH finds, by what they resolve to.
    for compiler in ["/usr/bin/cc", "/usr/bin/c++"] {
        digest.field(compiler.as_bytes());
        digest.resolved(Path::new(compiler))?;
    }
    // The compiler's internals, every file of them.
    for internal in ["/usr/lib/gcc", "/usr/libexec/gcc"] {
        let inside = Path::new(internal);
        let host = host_root.join(&internal[1..]);
        if digest.entry(&host, inside)? {
            digest.tree(&host, inside)?;
        }
    }
    Ok(hex::encode(digest.digest.finalize()))
}

/// The walk behind `host_build_inputs`: the host root it reads and the
/// digest it feeds. Every read that fails is an error naming its path;
/// only a confirmed `NotFound` is recorded, as absence.
struct Fingerprint<'a> {
    host_root: &'a Path,
    digest: sha2::Sha256,
}

impl Fingerprint<'_> {
    /// The entries of a curated host directory the view drops or moves,
    /// and the `CURATED_NESTED` directories it curates in turn.
    fn dropped(&mut self, host: &Path, inside: &Path, curation: Curation) -> io::Result<()> {
        let entries =
            classify_dir(host, inside, curation).map_err(|error| fingerprint_error(host, error))?;
        for (name, file_type, nested, placement) in entries {
            let (host_entry, inside_entry) = (host.join(&name), inside.join(&name));
            match placement {
                Placement::Keep if nested && file_type.is_dir() => {
                    self.dropped(&host_entry, &inside_entry, curation)?;
                }
                Placement::Curate => match fs::read_dir(&host_entry) {
                    // Empty in the view, whatever the full host has in it:
                    // recorded as unlistable, never as an empty directory.
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        self.entry(&host_entry, &inside_entry)?;
                        self.field(b"unlistable");
                    }
                    _ => self.dropped(&host_entry, &inside_entry, Curation::Subtree)?,
                },
                // What the view keeps, both views see.
                Placement::Keep => {}
                Placement::Runtime => {
                    self.entry(&host_entry, &inside_entry)?;
                }
                Placement::Drop => {
                    if self.entry(&host_entry, &inside_entry)? {
                        self.tree(&host_entry, &inside_entry)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Every entry under `host`, depth first in name order. Symlinks are
    /// recorded with what they resolve to (`entry`), never walked into.
    fn tree(&mut self, host: &Path, inside: &Path) -> io::Result<()> {
        let mut names = fs::read_dir(host)
            .and_then(|entries| {
                entries
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<io::Result<Vec<_>>>()
            })
            .map_err(|error| fingerprint_error(host, error))?;
        names.sort();
        for name in names {
            let (host_entry, inside_entry) = (host.join(&name), inside.join(&name));
            if self.entry(&host_entry, &inside_entry)? {
                self.tree(&host_entry, &inside_entry)?;
            }
        }
        Ok(())
    }

    /// One entry's path (as the sandbox names it), type, size and
    /// modification time; for a symlink, its target and the stat of what
    /// the whole chain finally resolves to. `true` when it is a directory.
    fn entry(&mut self, host: &Path, inside: &Path) -> io::Result<bool> {
        use std::os::unix::ffi::OsStrExt as _;
        self.field(inside.as_os_str().as_bytes());
        let metadata = match fs::symlink_metadata(host) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.field(b"absent");
                return Ok(false);
            }
            Err(error) => return Err(fingerprint_error(host, error)),
        };
        self.stat(&metadata, false);
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(host).map_err(|error| fingerprint_error(host, error))?;
            self.field(target.as_os_str().as_bytes());
            self.resolved(inside)?;
        }
        Ok(metadata.is_dir())
    }

    /// The stat of what `inside` resolves to on the host, following every
    /// symlink on the way (`sandbox::resolve_host_path`): a dropped
    /// `liblzma.so -> liblzma.so.5 -> liblzma.so.5.8.1` covers the kept
    /// library a `-llzma` link reads. A dangling chain is recorded as
    /// missing; a loop is an error.
    fn resolved(&mut self, inside: &Path) -> io::Result<()> {
        let resolved = crate::kernel::sandbox::resolve_host_path(self.host_root, inside)
            .map_err(|error| fingerprint_error(inside, error))?;
        let host = self
            .host_root
            .join(resolved.strip_prefix("/").unwrap_or(&resolved));
        match fs::symlink_metadata(&host) {
            Ok(metadata) => self.stat(&metadata, true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.field(b"missing"),
            Err(error) => return Err(fingerprint_error(&host, error)),
        }
        Ok(())
    }

    /// Type, size and modification time; with `identity`, also the inode
    /// and device, so a replaced file behind an unchanged chain counts.
    fn stat(&mut self, metadata: &fs::Metadata, identity: bool) {
        use std::os::unix::fs::MetadataExt as _;
        let file_type = metadata.file_type();
        let kind: &[u8] = if file_type.is_symlink() {
            b"l"
        } else if file_type.is_dir() {
            b"d"
        } else if file_type.is_file() {
            b"f"
        } else {
            b"o"
        };
        self.field(kind);
        self.field(&metadata.size().to_le_bytes());
        let modified =
            i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
        self.field(&modified.to_le_bytes());
        if identity {
            self.field(&metadata.ino().to_le_bytes());
            self.field(&metadata.dev().to_le_bytes());
        }
    }

    fn field(&mut self, bytes: &[u8]) {
        digest_field(&mut self.digest, bytes);
    }
}

fn fingerprint_error(path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "cannot read host {} to fingerprint its build inputs: {error}",
            path.display()
        ),
    )
}

/// A length-prefixed field, so no name can run into the next one.
fn digest_field(digest: &mut sha2::Sha256, bytes: &[u8]) {
    use sha2::Digest as _;
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn temp_dir(test_name: &str) -> TempDir {
        TempDir::named(&format!("hostview-{test_name}"))
    }

    /// A fake host with one of each entry the `RuntimeOnly` rules decide
    /// on: allowed and disallowed headers, a multiarch include directory,
    /// a linker script, a `-dev` symlink chain, a runtime ELF `lib*.so`,
    /// static, object and package-config entries, the compiler's own
    /// directory, a library subdirectory with nothing but runtime files in
    /// it and one with headers, an archive and a plugin.
    fn curated_fake_host(test_name: &str, split_usr: bool) -> TempDir {
        let root = temp_dir(test_name);
        let dirs = [
            "usr/include/sys",
            "usr/include/c++",
            "usr/include/x86_64-linux-gnu/bits",
            "usr/lib64/pkgconfig",
            "usr/lib64/cmake",
            "usr/lib64/gcc",
            "usr/lib64/python3/site-packages",
            "usr/lib64/perl5/CORE",
            "usr/lib64/perl5/pkgconfig",
            "usr/share/pkgconfig",
        ];
        for directory in dirs {
            fs::create_dir_all(root.0.join(directory)).unwrap();
        }
        let write = |path: &str, bytes: &[u8]| fs::write(root.0.join(path), bytes).unwrap();
        write("usr/include/stdio.h", b"/* glibc */\n");
        write("usr/include/lzma.h", b"/* xz-devel */\n");
        write(
            "usr/include/x86_64-linux-gnu/lzma.h",
            b"/* liblzma-dev */\n",
        );
        write(
            "usr/lib64/libc.so",
            b"/* GNU ld script */\nGROUP ( libc.so.6 )\n",
        );
        write("usr/lib64/liblzma.so.5.2", b"\x7fELF\x02\x01\x01");
        write("usr/lib64/libnss3.so", b"\x7fELF\x02\x01\x01");
        write("usr/lib64/libz.a", b"!<arch>\n");
        write("usr/lib64/crt1.o", b"\x7fELF\x02\x01\x01");
        write("usr/lib64/foo.o", b"\x7fELF\x02\x01\x01");
        write("usr/share/pkgconfig/zlib.pc", b"Name: zlib\n");
        write("usr/lib64/gcc/stddef.h", b"/* gcc */\n");
        write("usr/lib64/python3/site-packages/mod.py", b"pass\n");
        write("usr/lib64/perl5/CORE/perl.h", b"/* perl-devel */\n");
        write("usr/lib64/perl5/CORE/libperl.so", b"\x7fELF\x02\x01\x01");
        write("usr/lib64/perl5/libfoo.a", b"!<arch>\n");
        write("usr/lib64/perl5/pkgconfig/perl.pc", b"Name: perl\n");
        let link = |target: &str, name: &str| {
            std::os::unix::fs::symlink(target, root.0.join(name)).unwrap();
        };
        link("liblzma.so.5", "usr/lib64/liblzma.so");
        link("liblzma.so.5.2", "usr/lib64/liblzma.so.5");
        link("libnss3.so", "usr/lib64/libnss3.so.1");
        if split_usr {
            fs::create_dir_all(root.0.join("lib64")).unwrap();
            write("lib64/libz.so.1", b"\x7fELF\x02\x01\x01");
            link("libz.so.1", "lib64/libz.so");
        } else {
            link("usr/lib64", "lib64");
        }
        root
    }

    /// The `(source, destination)` pairs of every `--ro-bind` in `args`.
    fn ro_binds(args: &[OsString]) -> Vec<(PathBuf, PathBuf)> {
        args.windows(3)
            .filter(|window| window[0] == "--ro-bind")
            .map(|window| (PathBuf::from(&window[1]), PathBuf::from(&window[2])))
            .collect()
    }

    /// Every rule, against a merged-/usr host: allowed entries are bound
    /// or recreated, everything a link step alone would read is absent,
    /// and a symlinked `/lib64` is left to its curated target.
    #[test]
    fn runtime_only_view_keeps_the_c_runtime_and_drops_host_dev_files() {
        let host = curated_fake_host("runtime-only-merged", false);
        let skeleton = temp_dir("runtime-only-merged-skeleton");
        let (args, library_path) = runtime_only_args(&host.0, &skeleton.0).unwrap();
        let binds = ro_binds(&args);
        let bound = |inside: &str| binds.iter().any(|(_, to)| to == Path::new(inside));
        let from_host = |inside: &str| {
            binds.contains(&(
                host.0.join(inside.trim_start_matches('/')),
                PathBuf::from(inside),
            ))
        };
        let mirrored = |inside: &str| {
            fs::symlink_metadata(skeleton.0.join(inside.trim_start_matches('/'))).is_ok()
        };
        // A kept file is a symlink to its host copy under `HOST_FILES`.
        let linked = |at: &str, inside: &str| {
            fs::read_link(skeleton.0.join(at.trim_start_matches('/'))).ok()
                == Some(Path::new(HOST_FILES).join(inside.trim_start_matches('/')))
        };

        // Each curated directory the host has is its skeleton, read-only.
        for inside in ["/usr/include", "/usr/lib64", "/usr/share/pkgconfig"] {
            assert!(
                binds.contains(&(
                    skeleton.0.join(inside.trim_start_matches('/')),
                    PathBuf::from(inside)
                )),
                "{inside} is not its skeleton: {args:?}"
            );
            // One that keeps anything is bound whole under `HOST_FILES`.
            let whole = binds.contains(&(
                host.0.join(inside.trim_start_matches('/')),
                Path::new(HOST_FILES).join(inside.trim_start_matches('/')),
            ));
            assert_eq!(
                whole,
                inside != "/usr/share/pkgconfig",
                "{inside}: {args:?}"
            );
        }
        // Headers: the C runtime's names, the multiarch directory curated
        // with the same list, nothing else.
        assert!(linked("/usr/include/stdio.h", "/usr/include/stdio.h"));
        assert!(!bound("/usr/include/stdio.h"), "a file costs no mount");
        for kept in ["/usr/include/sys", "/usr/include/c++"] {
            assert!(from_host(kept), "{kept} not bound from the host: {args:?}");
            assert!(mirrored(kept), "{kept} has no placeholder");
        }
        assert!(from_host("/usr/include/x86_64-linux-gnu/bits"), "{args:?}");
        assert!(!bound("/usr/include/x86_64-linux-gnu"), "{args:?}");
        assert!(mirrored("/usr/include/x86_64-linux-gnu"));
        for dropped in [
            "/usr/include/lzma.h",
            "/usr/include/x86_64-linux-gnu/lzma.h",
        ] {
            assert!(!bound(dropped), "{dropped} bound: {args:?}");
            assert!(!mirrored(dropped), "{dropped} mirrored");
        }
        // Libraries: the C runtime's linker script and start file,
        // versioned runtime ELF files, the compiler's directory, and the
        // soname link, recreated with the host's own target.
        for kept in [
            "/usr/lib64/libc.so",
            "/usr/lib64/liblzma.so.5.2",
            "/usr/lib64/crt1.o",
        ] {
            assert!(linked(kept, kept), "{kept} not linked to the host");
        }
        // A subdirectory with no development files in it, and the
        // compiler's own, headers and all, are bound whole.
        for kept in ["/usr/lib64/gcc", "/usr/lib64/python3"] {
            assert!(from_host(kept), "{kept} not bound from the host: {args:?}");
        }
        // One with development files is curated in turn: its plugin stays,
        // its headers, archives and pkg-config are gone (#331).
        assert!(!bound("/usr/lib64/perl5"), "{args:?}");
        assert!(linked(
            "/usr/lib64/perl5/CORE/libperl.so",
            "/usr/lib64/perl5/CORE/libperl.so"
        ));
        for dropped in [
            "/usr/lib64/perl5/CORE/perl.h",
            "/usr/lib64/perl5/libfoo.a",
            "/usr/lib64/perl5/pkgconfig",
        ] {
            assert!(!mirrored(dropped), "{dropped} mirrored");
        }
        // An unversioned runtime ELF (`libnss3.so`) moves where `-lnss3`
        // cannot find it and the loader can, and a symlink naming it
        // follows it there.
        assert!(!bound("/usr/lib64/libnss3.so"), "{args:?}");
        assert!(!mirrored("/usr/lib64/libnss3.so"));
        assert!(linked(
            "/usr/lib64/.tog-host-runtime/libnss3.so",
            "/usr/lib64/libnss3.so"
        ));
        assert_eq!(
            fs::read_link(skeleton.0.join("usr/lib64/libnss3.so.1")).unwrap(),
            Path::new(".tog-host-runtime/libnss3.so")
        );
        assert_eq!(
            library_path,
            [PathBuf::from("/usr/lib64/.tog-host-runtime")]
        );
        assert_eq!(
            fs::read_link(skeleton.0.join("usr/lib64/liblzma.so.5")).unwrap(),
            Path::new("liblzma.so.5.2")
        );
        assert!(
            !bound("/usr/lib64/liblzma.so.5"),
            "a symlink costs no mount"
        );
        for dropped in [
            "/usr/lib64/liblzma.so",
            "/usr/lib64/libz.a",
            "/usr/lib64/foo.o",
            "/usr/lib64/pkgconfig",
            "/usr/lib64/cmake",
            "/usr/share/pkgconfig/zlib.pc",
        ] {
            assert!(!bound(dropped), "{dropped} bound: {args:?}");
            assert!(!mirrored(dropped), "{dropped} mirrored");
        }
        // A symlinked /lib64 already lands in /usr/lib64; directories the
        // host does not have are not invented.
        for absent in ["/lib64", "/usr/lib", "/usr/local/include", "/lib"] {
            assert!(!bound(absent), "{absent} curated: {args:?}");
        }
        // The whole view is binds of real paths, nothing else.
        assert_eq!(args.len(), binds.len() * 3, "{args:?}");
    }

    /// On a split-/usr host the real `/lib64` `system_root_args` binds is
    /// curated too.
    #[test]
    fn runtime_only_view_curates_a_split_usr_lib64() {
        let host = curated_fake_host("runtime-only-split", true);
        let skeleton = temp_dir("runtime-only-split-skeleton");
        let (args, library_path) = runtime_only_args(&host.0, &skeleton.0).unwrap();
        let binds = ro_binds(&args);
        assert_eq!(
            library_path,
            [PathBuf::from("/usr/lib64/.tog-host-runtime")],
            "only /usr/lib64 has an unversioned runtime ELF"
        );
        assert!(binds.contains(&(skeleton.0.join("lib64"), PathBuf::from("/lib64"))));
        assert!(binds.contains(&(
            host.0.join("lib64"),
            PathBuf::from("/.tog-host-files/lib64")
        )));
        assert_eq!(
            fs::read_link(skeleton.0.join("lib64/libz.so.1")).unwrap(),
            Path::new("/.tog-host-files/lib64/libz.so.1")
        );
        assert!(!binds
            .iter()
            .any(|(_, to)| to == Path::new("/lib64/libz.so")));
        assert!(fs::symlink_metadata(skeleton.0.join("lib64/libz.so")).is_err());
    }

    /// The fingerprint is a pure function of the host: the same tree gives
    /// the same digest, and so does a copy made at another time or path.
    /// It moves with what only `Full` exposes (a dropped header, a dropped
    /// directory's contents, a relocated library, the compiler), never with
    /// what the view keeps.
    #[test]
    fn host_build_inputs_track_only_what_the_view_hides() {
        use std::time::{Duration, SystemTime};
        let host = curated_fake_host("fingerprint", false);
        fs::create_dir_all(host.0.join("usr/bin")).unwrap();
        fs::write(host.0.join("usr/bin/gcc-15"), b"\x7fELF").unwrap();
        std::os::unix::fs::symlink("gcc-15", host.0.join("usr/bin/cc")).unwrap();
        fs::create_dir_all(host.0.join("usr/lib/gcc/x86_64-redhat-linux/15")).unwrap();
        let fingerprint = || host_build_inputs_at(&host.0).unwrap();
        let first = fingerprint();
        assert_eq!(first.len(), 64);
        assert_eq!(fingerprint(), first, "not deterministic");

        // Pin every modification time so each change below differs from
        // the baseline only in what it changes.
        let touch = |path: &str, seconds: u64| {
            let file = fs::File::options()
                .write(true)
                .open(host.0.join(path))
                .unwrap();
            file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
                .unwrap();
        };

        // A kept C-runtime header does not count, whatever happens to it.
        fs::write(host.0.join("usr/include/stdio.h"), b"/* glibc 2.44 */\n").unwrap();
        touch("usr/include/stdio.h", 7);
        assert_eq!(
            fingerprint(),
            first,
            "a kept header changed the fingerprint"
        );

        // A dropped header does, as does a new file in a dropped directory.
        fs::write(host.0.join("usr/include/lzma.h"), b"/* xz-devel 5.8 */\n").unwrap();
        let after_header = fingerprint();
        assert_ne!(after_header, first, "a dropped header did not count");
        fs::write(
            host.0.join("usr/lib64/pkgconfig/liblzma.pc"),
            b"Name: liblzma\n",
        )
        .unwrap();
        let after_pc = fingerprint();
        assert_ne!(after_pc, after_header, "a new .pc file did not count");
        fs::create_dir_all(host.0.join("usr/include/libxml2/libxml")).unwrap();
        let after_dir = fingerprint();
        assert_ne!(after_dir, after_pc, "a new header directory did not count");
        fs::write(host.0.join("usr/include/libxml2/libxml/tree.h"), b"").unwrap();
        touch("usr/include/libxml2/libxml/tree.h", 7);
        let after_nested = fingerprint();
        assert_ne!(
            after_nested, after_dir,
            "a header inside a dropped directory did not count"
        );
        // A header in a curated library subdirectory counts too (#331); a
        // file the subdirectory keeps does not.
        fs::write(host.0.join("usr/lib64/perl5/CORE/perl.h"), b"/* 5.42 */\n").unwrap();
        let after_subtree = fingerprint();
        assert_ne!(
            after_subtree, after_nested,
            "a curated subtree header did not count"
        );
        fs::write(host.0.join("usr/lib64/perl5/CORE/libperl.so"), b"\x7fELF").unwrap();
        assert_eq!(
            fingerprint(),
            after_subtree,
            "a kept plugin changed the fingerprint"
        );

        // A relocated runtime library counts by size and modification time.
        touch("usr/lib64/libnss3.so", 7);
        let after_touch = fingerprint();
        assert_ne!(
            after_touch, after_subtree,
            "a relocated library's mtime did not count"
        );
        fs::write(
            host.0.join("usr/lib64/libnss3.so"),
            b"\x7fELF\x02\x01\x01\x00",
        )
        .unwrap();
        touch("usr/lib64/libnss3.so", 7);
        assert_ne!(
            fingerprint(),
            after_touch,
            "a relocated library's size did not count"
        );

        // The compiler: where `cc` resolves, and its internal directory.
        let before_compiler = fingerprint();
        fs::write(host.0.join("usr/bin/gcc-16"), b"\x7fELF").unwrap();
        fs::remove_file(host.0.join("usr/bin/cc")).unwrap();
        std::os::unix::fs::symlink("gcc-16", host.0.join("usr/bin/cc")).unwrap();
        let after_cc = fingerprint();
        assert_ne!(after_cc, before_compiler, "a new cc did not count");
        fs::create_dir_all(host.0.join("usr/lib/gcc/x86_64-redhat-linux/16")).unwrap();
        let after_gcc_dir = fingerprint();
        assert_ne!(
            after_gcc_dir, after_cc,
            "a new gcc internal directory did not count"
        );
        // Every file under the compiler's internals counts, however deep.
        fs::create_dir_all(host.0.join("usr/lib/gcc/x86_64-redhat-linux/16/include")).unwrap();
        fs::write(
            host.0
                .join("usr/lib/gcc/x86_64-redhat-linux/16/include/stddef.h"),
            b"/* gcc */",
        )
        .unwrap();
        assert_ne!(
            fingerprint(),
            after_gcc_dir,
            "a gcc internal header did not count"
        );

        // A dropped symlink covers the kept file its chain resolves to:
        // `liblzma.so -> liblzma.so.5 -> liblzma.so.5.2` is what `-llzma`
        // reads under the full view.
        let before_target = fingerprint();
        fs::write(
            host.0.join("usr/lib64/liblzma.so.5.2"),
            b"\x7fELF\x02\x01\x01\x00\x00",
        )
        .unwrap();
        touch("usr/lib64/liblzma.so.5.2", 7);
        let after_target = fingerprint();
        assert_ne!(
            after_target, before_target,
            "a dropped symlink's target did not count"
        );
        // The same size and time through a new inode still counts.
        let target = host.0.join("usr/lib64/liblzma.so.5.2");
        fs::rename(&target, host.0.join("usr/lib64/old")).unwrap();
        fs::write(&target, b"\x7fELF\x02\x01\x01\x00\x00").unwrap();
        touch("usr/lib64/liblzma.so.5.2", 7);
        fs::remove_file(host.0.join("usr/lib64/old")).unwrap();
        assert_ne!(
            fingerprint(),
            after_target,
            "a replaced target did not count"
        );
    }

    /// A fake host whose library subdirectories carry the development
    /// files of a `-devel` package beside its runtime: Fedora's
    /// openmpi-devel (`pkgconfig/` beside a `libmpi.so` symlink, a linker
    /// script, an object, another libc's archive, a plugin), Debian's
    /// libperl-dev under the multiarch `/usr/lib/x86_64-linux-gnu`, and a
    /// plugin directory of `lib*.so` symlinks with no development file.
    fn subtree_fake_host(test_name: &str) -> TempDir {
        let root = temp_dir(test_name);
        for directory in [
            "usr/lib64/openmpi/lib/pkgconfig",
            "usr/lib64/openmpi/lib/openmpi",
            "usr/lib64/bfd-plugins",
            "usr/lib/x86_64-linux-gnu/perl/5.34/CORE",
        ] {
            fs::create_dir_all(root.0.join(directory)).unwrap();
        }
        let write = |path: &str, bytes: &[u8]| fs::write(root.0.join(path), bytes).unwrap();
        let link = |target: &str, name: &str| {
            std::os::unix::fs::symlink(target, root.0.join(name)).unwrap();
        };
        write("usr/lib64/openmpi/lib/pkgconfig/ompi.pc", b"Name: ompi\n");
        write("usr/lib64/openmpi/lib/libmpi.so.40", b"\x7fELF\x02\x01\x01");
        link("libmpi.so.40", "usr/lib64/openmpi/lib/libmpi.so");
        write(
            "usr/lib64/openmpi/lib/libmpi_script.so",
            b"/* GNU ld script */\nINPUT ( libmpi.so.40 )\n",
        );
        write(
            "usr/lib64/openmpi/lib/libopen-pal.so",
            b"\x7fELF\x02\x01\x01",
        );
        write("usr/lib64/openmpi/lib/libc.a", b"!<arch>\n");
        write("usr/lib64/openmpi/lib/crt1.o", b"\x7fELF\x02\x01\x01");
        write(
            "usr/lib64/openmpi/lib/openmpi/mca_btl_self.so",
            b"\x7fELF\x02\x01\x01",
        );
        write(
            "usr/lib64/bfd-plugins/liblto_plugin.so.0",
            b"\x7fELF\x02\x01\x01",
        );
        link(
            "liblto_plugin.so.0",
            "usr/lib64/bfd-plugins/liblto_plugin.so",
        );
        write(
            "usr/lib/x86_64-linux-gnu/perl/5.34/CORE/perl.h",
            b"/* libperl-dev */\n",
        );
        link(
            "../../../libperl.so.5.34",
            "usr/lib/x86_64-linux-gnu/perl/5.34/CORE/libperl.so",
        );
        write(
            "usr/lib/x86_64-linux-gnu/perl/5.34/CORE/config.sh",
            b"# perl\n",
        );
        write(
            "usr/lib/x86_64-linux-gnu/libperl.so.5.34",
            b"\x7fELF\x02\x01\x01",
        );
        root
    }

    /// A curated subdirectory drops what a library directory drops: an
    /// explicit `-L` into it links nothing the default paths would not
    /// (#331). Plugins stay where they are loaded from, and a plugin
    /// directory with no development file is bound whole.
    #[test]
    fn curated_subtrees_drop_what_library_directories_drop() {
        let host = subtree_fake_host("subtree");
        let skeleton = temp_dir("subtree-skeleton");
        let (args, library_path) = runtime_only_args(&host.0, &skeleton.0).unwrap();
        let binds = ro_binds(&args);
        let mirrored = |inside: &str| {
            fs::symlink_metadata(skeleton.0.join(inside.trim_start_matches('/'))).is_ok()
        };
        let linked = |inside: &str| {
            fs::read_link(skeleton.0.join(inside.trim_start_matches('/'))).ok()
                == Some(Path::new(HOST_FILES).join(inside.trim_start_matches('/')))
        };
        for dropped in [
            "/usr/lib64/openmpi/lib/pkgconfig",
            "/usr/lib64/openmpi/lib/libmpi.so",
            "/usr/lib64/openmpi/lib/libmpi_script.so",
            "/usr/lib64/openmpi/lib/libc.a",
            "/usr/lib64/openmpi/lib/crt1.o",
            "/usr/lib/x86_64-linux-gnu/perl/5.34/CORE/perl.h",
            "/usr/lib/x86_64-linux-gnu/perl/5.34/CORE/libperl.so",
        ] {
            assert!(!mirrored(dropped), "{dropped} mirrored");
            assert!(
                !binds.iter().any(|(_, to)| to == Path::new(dropped)),
                "{dropped} bound: {args:?}"
            );
        }
        for kept in [
            "/usr/lib64/openmpi/lib/libmpi.so.40",
            "/usr/lib64/openmpi/lib/libopen-pal.so",
            "/usr/lib/x86_64-linux-gnu/perl/5.34/CORE/config.sh",
            "/usr/lib/x86_64-linux-gnu/libperl.so.5.34",
        ] {
            assert!(linked(kept), "{kept} not linked to the host");
        }
        // A plugin directory below a curated one is bound whole, and so is
        // one of `lib*.so` symlinks: `ld` loads `liblto_plugin.so`.
        for whole in ["/usr/lib64/openmpi/lib/openmpi", "/usr/lib64/bfd-plugins"] {
            assert!(
                binds.contains(&(
                    host.0.join(whole.trim_start_matches('/')),
                    PathBuf::from(whole)
                )),
                "{whole} not bound whole: {args:?}"
            );
        }
        // Nothing in a subdirectory moves out of its loader's reach.
        assert!(library_path.is_empty(), "{library_path:?}");
    }

    /// A development file appearing in a curated subdirectory, a dev
    /// symlink included, changes the fingerprint; one appearing in a
    /// subdirectory bound whole changes it by curating that subdirectory.
    #[test]
    fn host_build_inputs_track_curated_subtrees() {
        let host = subtree_fake_host("subtree-fingerprint");
        let fingerprint = || host_build_inputs_at(&host.0).unwrap();
        let first = fingerprint();
        let link = |target: &str, name: &str| {
            std::os::unix::fs::symlink(target, host.0.join(name)).unwrap();
        };
        link("libmpi_cxx.so.40", "usr/lib64/openmpi/lib/libmpi_cxx.so");
        let after_link = fingerprint();
        assert_ne!(after_link, first, "a dev symlink did not count");
        fs::write(
            host.0
                .join("usr/lib/x86_64-linux-gnu/perl/5.34/CORE/EXTERN.h"),
            b"",
        )
        .unwrap();
        let after_multiarch = fingerprint();
        assert_ne!(
            after_multiarch, after_link,
            "a multiarch subtree header did not count"
        );
        fs::write(host.0.join("usr/lib64/bfd-plugins/plugin-api.h"), b"").unwrap();
        assert_ne!(
            fingerprint(),
            after_multiarch,
            "a header in a whole subdirectory did not count"
        );
    }

    /// A library subdirectory tog cannot list may hold development files
    /// by names the build can open, so it is curated: an empty directory
    /// in the view, recorded in the fingerprint as unlistable.
    #[test]
    fn an_unlistable_library_subdirectory_is_empty() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip unlistable directory: running as root");
            return;
        }
        let host = subtree_fake_host("subtree-unlistable");
        let vendor = host.0.join("usr/lib64/vendor");
        fs::create_dir(&vendor).unwrap();
        fs::write(vendor.join("vendor.h"), b"").unwrap();
        fs::write(vendor.join("libvendor.so.1"), b"\x7fELF\x02\x01\x01").unwrap();
        let listable = host_build_inputs_at(&host.0).unwrap();
        // Unlistable to its owner, who runs the test: a 0711 directory of
        // root's is unlistable to everyone else the same way.
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o311)).unwrap();
        let skeleton = temp_dir("subtree-unlistable-skeleton");
        let view = runtime_only_args(&host.0, &skeleton.0);
        let unlistable = host_build_inputs_at(&host.0);
        let again = host_build_inputs_at(&host.0);
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o755)).unwrap();
        let (args, _) = view.unwrap();
        assert!(
            !ro_binds(&args)
                .iter()
                .any(|(_, to)| to.starts_with("/usr/lib64/vendor")),
            "{args:?}"
        );
        let mirror = skeleton.0.join("usr/lib64/vendor");
        assert!(mirror.is_dir(), "no empty placeholder");
        assert_eq!(fs::read_dir(&mirror).unwrap().count(), 0);
        let unlistable = unlistable.unwrap();
        assert_eq!(again.unwrap(), unlistable, "not deterministic");
        assert_ne!(unlistable, listable, "unlistable passed for listable");
    }

    /// A dangling symlink is recorded as such; a symlink loop and a
    /// directory tog cannot read are errors naming the path, never a
    /// quietly smaller fingerprint.
    #[test]
    fn host_build_inputs_refuse_what_they_cannot_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let host = curated_fake_host("fingerprint-errors", false);
        let link = |target: &str, name: &str| {
            std::os::unix::fs::symlink(target, host.0.join(name)).unwrap();
        };
        let clean = host_build_inputs_at(&host.0).unwrap();
        link("libgone.so.1", "usr/lib64/libgone.so");
        let dangling = host_build_inputs_at(&host.0).unwrap();
        assert_ne!(dangling, clean);
        fs::remove_file(host.0.join("usr/lib64/libgone.so")).unwrap();

        link("libloop.so.b", "usr/lib64/libloop.so");
        link("libloop.so", "usr/lib64/libloop.so.b");
        let error = host_build_inputs_at(&host.0).unwrap_err().to_string();
        assert!(error.contains("libloop.so"), "{error}");
        fs::remove_file(host.0.join("usr/lib64/libloop.so")).unwrap();
        fs::remove_file(host.0.join("usr/lib64/libloop.so.b")).unwrap();
        assert_eq!(host_build_inputs_at(&host.0).unwrap(), clean);

        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip unreadable directory: running as root");
            return;
        }
        let secret = host.0.join("usr/include/secret");
        fs::create_dir(&secret).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
        let result = host_build_inputs_at(&host.0);
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o755)).unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("usr/include/secret"), "{error}");
    }

    /// The real host's fingerprint is stable between two walks, and how
    /// long a walk takes here is printed for the record.
    #[test]
    fn this_hosts_build_inputs_are_stable() {
        let started = std::time::Instant::now();
        let first = host_build_inputs().unwrap();
        let elapsed = started.elapsed();
        assert_eq!(host_build_inputs().unwrap(), first);
        eprintln!("host build inputs {first} in {elapsed:?}");
    }

    /// A pid no process has: a child that has already been reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    fn age(path: &Path, seconds: u64) {
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
        fs::File::open(path).unwrap().set_modified(then).unwrap();
    }

    /// Age a symlink itself, not what it points at.
    fn age_link(path: &Path, seconds: u64) {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
        let then = then
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time = libc::timespec {
            tv_sec: then.try_into().unwrap(),
            tv_nsec: 0,
        };
        // SAFETY: `path` is a NUL-terminated string and `times` points at
        // two initialised timespecs, which is what utimensat reads.
        let result = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                [time, time].as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
    }

    /// A child process that runs until the guard is dropped.
    struct Running(std::process::Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A skeleton a killed tog left is removed by a later run once it is a
    /// day old; one whose tog still runs, a fresh one, anything not named
    /// like a skeleton, and a symlink, all a day old, are left (#335).
    #[test]
    fn stale_skeletons_of_gone_runs_are_swept() {
        let temp = temp_dir("skeleton-sweep");
        let base = temp.0.as_path();
        let dead = dead_pid();
        let nonce = "0123456789abcdef";
        let make = |name: &str, seconds: u64| {
            let path = base.join(name);
            fs::create_dir(&path).unwrap();
            fs::create_dir(path.join("usr")).unwrap();
            fs::write(path.join("usr/placeholder"), "").unwrap();
            age(&path, seconds);
            path
        };
        let stale = make(&format!("{SKELETON_PREFIX}{dead}-{nonce}"), 2 * 86_400);
        let fresh = make(&format!("{SKELETON_PREFIX}{dead}-{}", "f".repeat(16)), 60);
        let running = make(
            &format!("{SKELETON_PREFIX}{}-{nonce}", std::process::id()),
            2 * 86_400,
        );
        // Another live process, which only `process_exists` can tell.
        let other_tog = Running(
            std::process::Command::new("sleep")
                .arg("600")
                .spawn()
                .unwrap(),
        );
        let other_running = make(
            &format!("{SKELETON_PREFIX}{}-{nonce}", other_tog.0.id()),
            2 * 86_400,
        );
        let other = make(&format!("{SKELETON_PREFIX}{dead}-short"), 2 * 86_400);
        let unrelated = make("tog-something-else", 2 * 86_400);
        let target = make("target", 2 * 86_400);
        let link = base.join(format!("{SKELETON_PREFIX}{dead}-{}", "a".repeat(16)));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // Only the `is_dir` check can keep the link: it is as old as the rest.
        age_link(&link, 2 * 86_400);

        sweep_stale_skeletons(base);

        assert!(!stale.exists(), "the stale skeleton was kept");
        for kept in [
            &fresh,
            &running,
            &other_running,
            &other,
            &unrelated,
            &target,
        ] {
            assert!(kept.join("usr/placeholder").exists(), "{}", kept.display());
        }
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// A tog in another pid namespace looks dead from here, and a build can
    /// outlast a day: its skeleton is kept while its lock is held, and
    /// swept once it is released.
    #[test]
    fn a_locked_skeleton_is_kept_until_its_lock_is_released() {
        let temp = temp_dir("skeleton-sweep-locked");
        let base = temp.0.as_path();
        let path = base.join(format!("{SKELETON_PREFIX}{}-0123456789abcdef", dead_pid()));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("usr")).unwrap();
        let held = lock_skeleton(&path).unwrap().expect("the lock was taken");
        age(&path, 2 * 86_400);

        sweep_stale_skeletons(base);
        assert!(path.join("usr").is_dir(), "a locked skeleton was swept");

        drop(held);
        // Another test thread may be between `fork` and `exec` right now,
        // and its child holds a copy of the lock's descriptor until the
        // `exec` closes it: the lock is released a moment after the drop.
        for _ in 0..200 {
            sweep_stale_skeletons(base);
            if !path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!path.exists(), "an unlocked stale skeleton was kept");
    }

    /// A skeleton holds its own lock until it is dropped.
    #[test]
    fn a_skeleton_holds_its_lock() {
        let skeleton = ViewSkeleton::create().unwrap();
        assert!(matches!(
            skeleton_unlocked(skeleton.path()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn skeleton_names_carry_a_pid() {
        assert_eq!(skeleton_pid("tog-host-view-42-0123456789abcdef"), Some(42));
        for name in [
            "tog-host-view-0-0123456789abcdef",
            "tog-host-view--1-0123456789abcdef",
            "tog-host-view-4294967295-0123456789abcdef",
            "tog-host-view-42-0123456789abcdeg",
            "tog-host-view-42-0123",
            "tog-host-view-42",
            "tog-other-42-0123456789abcdef",
        ] {
            assert_eq!(skeleton_pid(name), None, "{name}");
        }
    }

    /// The skeleton root is 0700 whatever the umask left.
    #[test]
    fn the_skeleton_root_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let skeleton = ViewSkeleton::create().unwrap();
        let mode = fs::metadata(skeleton.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700);
    }

    /// Set in the child `the_skeleton_root_is_private_under_umask_0777`
    /// runs: only there does this test set the umask, which is process-wide
    /// and would leak into every other test in this binary.
    const UMASK_CHILD: &str = "TOG_TEST_HOSTVIEW_UMASK_CHILD";

    /// The root is 0700 even under `umask 0777`, where the mode `create`
    /// asks for alone would leave it 000 and every `RuntimeOnly` build
    /// unable to traverse it (#337). The umask is set in a child run of
    /// this test binary, which reports through its exit status.
    #[test]
    fn the_skeleton_root_is_private_under_umask_0777() {
        use std::os::unix::fs::PermissionsExt as _;
        const NAME: &str = "kernel::hostview::tests::the_skeleton_root_is_private_under_umask_0777";
        if std::env::var_os(UMASK_CHILD).is_some() {
            // SAFETY: umask has no preconditions; this process is the
            // child run, which runs this one test and nothing else.
            unsafe { libc::umask(0o777) };
            let skeleton = ViewSkeleton::create().unwrap();
            let mode = fs::metadata(skeleton.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o700, "{}", skeleton.path().display());
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
            .env(UMASK_CHILD, "1")
            .output()
            .unwrap();
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{report}");
        // The child ran the test rather than filtering it out.
        assert!(report.contains("1 passed"), "{report}");
    }
}

/// The skeleton becomes `/usr/include`, `/usr/lib64` and the rest inside the
/// sandbox, so it must never sit under a root the build may write.
#[cfg(test)]
mod skeleton_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn refused(write_roots: &[PathBuf]) -> io::Error {
        let error = runtime_only_mounts(write_roots).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
        error
    }

    /// The message names the skeleton and the root; the refused skeleton
    /// is removed, not left behind in TMPDIR.
    #[test]
    fn a_skeleton_inside_a_writable_root_is_refused() {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let unrelated = TempDir::named("hostview-unrelated-root");
        for (root, others) in [
            (temp.clone(), vec![]),
            (PathBuf::from("/"), vec![]),
            (temp.clone(), vec![unrelated.0.clone()]),
        ] {
            let mut roots = others.clone();
            roots.push(root.clone());
            let message = refused(&roots).to_string();
            let skeleton = message
                .strip_prefix("the host view skeleton ")
                .and_then(|rest| rest.split_once(" would sit inside the writable sandbox root "))
                .map(|(skeleton, _)| PathBuf::from(skeleton))
                .unwrap_or_else(|| panic!("{message}"));
            assert!(skeleton.starts_with(&temp), "{message}");
            assert_eq!(
                message,
                format!(
                    "the host view skeleton {} would sit inside the writable sandbox root {}; \
                     point TMPDIR somewhere else",
                    skeleton.display(),
                    root.display()
                )
            );
            assert!(
                !skeleton.exists(),
                "refused skeleton left behind: {message}"
            );
        }
    }

    /// Control: write roots beside the skeleton, including one whose name
    /// merely shares its prefix, do not contain it.
    #[test]
    fn a_skeleton_beside_the_writable_roots_is_accepted() {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let beside = TempDir::named("hostview-beside");
        let view = runtime_only_mounts(&[
            beside.0.clone(),
            temp.join("tog-host-view"),
            temp.join(format!("tog-host-view-{}", std::process::id())),
        ])
        .unwrap();
        assert!(view.skeleton.path().starts_with(&temp));
        assert!(view.skeleton.path().is_dir());
    }
}
