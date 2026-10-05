//! tog's pinned native library set (`kernel::provider::nativelibs`) in
//! Linux gem builds (#329). A gem whose gemspec declares native extensions
//! builds with the set mounted and on every search path its extconf can
//! use: pkg-config, gcc's own `CPATH` and `LIBRARY_PATH`, and mkmf's
//! `--with-cppflags`/`--with-ldflags`, which carry the rpath into the
//! extension, since mkmf-generated Makefiles ignore `LDFLAGS` from the
//! environment. A gem that needs openssl, libffi, libxml2, sqlite or zlib
//! then builds against the C runtime alone instead of falling back to the
//! host, and loads the store's copy at run time.
//!
//! Whether a plan has a native gem is known only from its gemspecs, after
//! download. Each answer is kept as a store record keyed by the gem's
//! sha256, so a warm sync names the set in the gems identity without
//! fetching anything.

use super::*;

/// The store record kind holding whether the `.gem` with a given sha256
/// declares native extensions.
const GEM_NATIVE: &str = "ruby-gem-native";

/// The `native` identity input of a Linux gems object whose plan has a
/// native gem: the set is mounted into those builds.
pub(super) const NATIVE_LIBS_MOUNTED: &str = "native-libs";
/// The `native` identity input of a Linux gems object with no native gem.
pub(super) const NATIVE_NONE: &str = "none";

/// Keep what `.gem` `sha256`'s gemspec says about native extensions.
/// A failed write costs the next sync a download and nothing else, so it
/// is reported and the sync goes on.
pub(super) fn record_classification(
    store: &Store,
    activity: &StoreActivity,
    sha256: &str,
    native: bool,
) {
    let value = serde_json::json!({ "native": native });
    if let Err(error) = store.write_record(activity, GEM_NATIVE, sha256, &value) {
        crate::kernel::ui::note(&format!(
            "whether gem {sha256} is native was not recorded in the store ({error}); \
             the next sync downloads it again"
        ));
    }
}

/// Whether any gem of `plan` declares native extensions, when every gem
/// has been classified before; `None` when one has not.
pub(super) fn persisted_classification(store: &Store, plan: &RubyPlan) -> io::Result<Option<bool>> {
    let mut native = false;
    for gem in &plan.gems {
        let Some(value) = store.read_record(GEM_NATIVE, &gem.sha256)? else {
            return Ok(None);
        };
        let Some(recorded) = value["native"].as_bool() else {
            return Ok(None);
        };
        native |= recorded;
    }
    Ok(Some(native))
}

/// The native library set a gems object on `platform` names: the set's
/// object id when the plan has a native gem on Linux, else none. macOS has
/// no pinned set.
pub(super) fn identity_id(
    store: &Store,
    platform: Platform,
    has_native: bool,
) -> io::Result<Option<String>> {
    if has_native && !platform.is_macos() {
        Ok(Some(crate::kernel::provider::nativelibs::object_id_for(
            store, platform,
        )?))
    } else {
        Ok(None)
    }
}

/// The environment a native gem's build gets with the set at `set`
/// mounted, for an attempt with `host_view`. gcc searches the set's
/// headers and libraries before the system's in either view (`CPATH` and
/// `LIBRARY_PATH` come ahead of the default directories). pkg-config
/// differs: the runtime-only attempt sees only the set
/// (`PKG_CONFIG_LIBDIR` replaces the default search path), so nothing
/// else can answer. The whole-host fallback still searches the set first
/// (`PKG_CONFIG_PATH`) but keeps pkg-config's default directories after
/// it, so a library the set lacks (ImageMagick for rmagick, say) is found
/// in the host's `.pc` files, which is what the fallback exists for.
pub(super) fn build_env(set: &Path, host_view: HostView) -> Vec<(String, String)> {
    let pkgconfig = set.join("lib/pkgconfig").display().to_string();
    let mut env = vec![("PKG_CONFIG_PATH".to_string(), pkgconfig.clone())];
    if host_view == HostView::RuntimeOnly {
        env.push(("PKG_CONFIG_LIBDIR".to_string(), pkgconfig));
    }
    env.extend([
        (
            "CPATH".to_string(),
            set.join("include").display().to_string(),
        ),
        (
            "LIBRARY_PATH".to_string(),
            set.join("lib").display().to_string(),
        ),
    ]);
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// The runtime-only attempt's pkg-config sees only the set; the
    /// whole-host fallback searches the set first and then the host's own
    /// `.pc` directories, so a library the set lacks is still found there.
    #[test]
    fn each_attempt_gets_its_own_pkg_config_search() {
        let set = Path::new("/store/set");
        let runtime_only = build_env(set, HostView::RuntimeOnly);
        let full = build_env(set, HostView::Full);
        for env in [&runtime_only, &full] {
            assert_eq!(
                lookup(env, "PKG_CONFIG_PATH"),
                Some("/store/set/lib/pkgconfig")
            );
            assert_eq!(lookup(env, "CPATH"), Some("/store/set/include"));
            assert_eq!(lookup(env, "LIBRARY_PATH"), Some("/store/set/lib"));
        }
        assert_eq!(
            lookup(&runtime_only, "PKG_CONFIG_LIBDIR"),
            Some("/store/set/lib/pkgconfig")
        );
        assert_eq!(lookup(&full, "PKG_CONFIG_LIBDIR"), None, "{full:?}");
    }
}
