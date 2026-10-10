//! The .NET resolution doors: the store SDK's restore confined through the
//! proxy session's NuGet mirror, for a missing lock and for `tog attest`.

use super::door::{dotnet_tool, run_restore, DotnetRun};
use super::{err, find_project, require_lock, LOCK_FILE};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::record;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use std::io;
use std::path::{Path, PathBuf};

/// The csproj and packages.lock.json: what restore resolves from and
/// writes.
pub(crate) fn resolution_outputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    Ok(vec![find_project(project)?, PathBuf::from(LOCK_FILE)])
}

/// MSBuild property functions and imported targets can read arbitrary project
/// data. Bind every regular file visible to its snapshot until precise input
/// declarations have a reviewed design.
pub(crate) fn resolution_inputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let outputs = resolution_outputs(project)?;
    let outputs: Vec<_> = outputs
        .iter()
        .map(|p| {
            p.to_str()
                .ok_or_else(|| err(".NET resolution output path is not UTF-8"))
        })
        .collect::<io::Result<_>>()?;
    crate::kernel::resolve::inputs::project_files(project, &super::door::EXCLUDE, &outputs)
}

/// Every resolution file of `project` that exists, by digest: a closure's
/// `resolution_basis`.
pub(crate) fn resolution_basis(
    project: &ProjectRoot,
) -> io::Result<crate::comforter::join::Digests> {
    let mut listed = resolution_outputs(project)?;
    listed.extend(resolution_inputs(project)?);
    record::file_digests(project, &listed)
}

/// Command-line global properties hold the lock contract unless imported
/// MSBuild opts them back into local reassignment. Scan all visible bytes,
/// including UTF-16/32 XML's NUL-padded ASCII names, rather than guessing
/// which extensions arbitrary imports may use. This is a conservative refusal.
fn reject_lock_controls(
    project: &ProjectRoot,
    basis: &crate::comforter::join::Digests,
) -> io::Result<()> {
    for path in basis.keys().filter(|path| path.as_str() != LOCK_FILE) {
        let bytes = project
            .read_input(Path::new(path))?
            .ok_or_else(|| err("MSBuild input vanished"))?;
        let ascii: Vec<u8> = bytes
            .into_iter()
            .filter(|byte| *byte != 0)
            .map(|byte| byte.to_ascii_lowercase())
            .collect();
        for control in ["treataslocalproperty", "nugetlockfilepath"] {
            if ascii
                .windows(control.len())
                .any(|part| part == control.as_bytes())
            {
                return Err(err(format!("{path}: unsupported MSBuild lock control {control}; restore must check packages.lock.json with tog's global settings")));
            }
        }
    }
    Ok(())
}

/// What preflight checked: the canonical project file, and the lock's text
/// and parse when the project has one (it may not exist until delegated
/// planning writes it). Planning and realization take it as proof.
#[derive(Debug)]
pub struct Preflight {
    pub csproj: PathBuf,
    pub(super) lock: Option<(String, super::ParsedLock)>,
    pub(super) basis: crate::comforter::join::Digests,
}

/// Central v0 trust-boundary validation.
///
/// Project files are read through the held descriptor (a held root is a
/// directory by construction); the returned paths are for messages and
/// child-process arguments. Ancestors lie outside the project and are
/// still inspected by path.
pub fn preflight(project: &ProjectRoot, sdk_version: &str) -> io::Result<Preflight> {
    let observed = project.observing_inputs()?;
    let project = &observed;
    let basis = resolution_basis(project)?;
    reject_lock_controls(project, &basis)?;
    let project_dir = project.path();
    let csproj_rel = find_project(project)?;
    let csproj = project_dir.join(&csproj_rel);
    if !super::regular_file_if_present(project, &csproj_rel, "csproj")? {
        return Err(err(format!("csproj is missing: {}", csproj.display())));
    }
    super::validate_csproj(project, &csproj_rel)?;

    let lock_rel = Path::new(LOCK_FILE);
    super::regular_file_if_present(project, lock_rel, "packages.lock.json")?;
    super::regular_file_if_present(project, Path::new("global.json"), "global.json")?;
    super::check_global_json(project, sdk_version)?;

    // Each directory above is reached from the held project, not its path.
    for (depth, ancestor) in project.ancestors().enumerate() {
        let ancestor = ancestor?;
        let present = |name: &str| {
            ancestor
                .entry(Path::new(name))
                .map(|entry| entry != crate::kernel::fsroot::Entry::Absent)
        };
        for name in [
            "Directory.Packages.props",
            "Directory.Build.rsp",
            "packages.config",
        ] {
            if present(name)? {
                return Err(err(format!(
                    "{name} is not supported in the project or an SDK ancestor: {}",
                    ancestor.path().join(name).display()
                )));
            }
        }
        if depth > 0 && present("global.json")? {
            return Err(err(format!(
                "ancestor global.json is not supported; SDK discovery would see {}",
                ancestor.path().join("global.json").display()
            )));
        }
    }
    let lock = if project.is_input_file(lock_rel) {
        let text = super::read_input_text(project, lock_rel)?;
        let parsed = super::parse_lock(&text)?;
        Some((text, parsed))
    } else {
        None
    };
    project.verify_observed_inputs()?;
    if resolution_basis(project)? != basis {
        return Err(err(
            ".NET resolution inputs changed during preflight; run `tog` again",
        ));
    }
    Ok(Preflight {
        csproj,
        lock,
        basis,
    })
}

/// `prepare`: packages.lock.json, written by the store SDK's `restore
/// --use-lock-file` when there is none. The one place the .NET tailor
/// writes project inputs. Restore runs confined through `door` (a
/// missing-lock door), and the lock and the signed resolution record are
/// published together through its transaction.
pub fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    sdk_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    preflight(project, selected.version("dotnet-sdk")?)?;
    let basis = resolution_basis(project)?;
    ui::note("no packages.lock.json; resolving with the store SDK...");
    let args = ["--use-lock-file"];
    let spec = crate::tailors::record_spec(
        &super::tailor::Dotnet,
        project,
        dotnet_tool(selected)?,
        &["restore", "--use-lock-file"],
    )?;
    let report = run_restore(
        door,
        DotnetRun {
            sdk_obj,
            lock_root: project.path(),
            args: &args,
            outputs: resolution_outputs(project)?,
            inputs: Some(&basis),
            receipt: Some(record::producer(spec, Default::default())),
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "store dotnet restore --use-lock-file failed: {}",
            restore_failure(&report)
        )));
    }
    Ok(())
}

/// `tog attest` for .NET: `restore --locked-mode` in the project, through
/// `door`'s transaction with the record's producer. A csproj the lock no
/// longer matches fails locked mode (NU1004); a lock it would rewrite
/// anyway is refused by the record. Nothing is published here.
pub fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    sdk_obj: &Path,
    selected: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    preflight(project, selected.version("dotnet-sdk")?)?;
    let basis = resolution_basis(project)?;
    require_lock(project)?;
    let args = ["--locked-mode"];
    let mut spec = crate::tailors::record_spec(
        &super::tailor::Dotnet,
        project,
        dotnet_tool(selected)?,
        &["restore", "--locked-mode"],
    )?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = run_restore(
        door,
        DotnetRun {
            sdk_obj,
            lock_root: project.path(),
            args: &args,
            outputs: resolution_outputs(project)?,
            inputs: Some(&basis),
            receipt: Some(record::producer(spec, slot.clone())),
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "packages.lock.json in {} is not what restore would write, so it is not attested; \
             run `tog` to bring it up to date and commit the result\n{}",
            project.path().display(),
            restore_failure(&report)
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("restore's lock check published no record"))
}

/// What a failed restore said: MSBuild writes its errors to stdout.
fn restore_failure(report: &crate::kernel::resolve::DelegateReport) -> String {
    let mut text = String::from_utf8_lossy(&report.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&report.stdout);
    for line in stdout.lines().filter(|line| line.contains("error")) {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(line.trim());
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::testing::{relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC};
    use crate::kernel::resolve::DoorKind;
    use crate::kernel::testutil::TempDir;
    use crate::tailors::dotnet::registry::HOST;
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::io::Write as _;

    #[test]
    fn msbuild_data_and_nested_imports_are_resolution_inputs() {
        let temp = TempDir::named("dotnet-inputs");
        for directory in ["config/nested", "obj", "bin", ".git", ".tog"] {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        fs::write(temp.0.join("app.csproj"), csproj("")).unwrap();
        fs::write(temp.0.join("config/nested/version.txt"), "1.0.0").unwrap();
        for file in [
            "obj/ignored",
            "bin/ignored",
            ".git/config",
            ".tog/closure.json",
        ] {
            fs::write(temp.0.join(file), "excluded").unwrap();
        }
        let project = ProjectRoot::open(&temp.0).unwrap();
        assert_eq!(
            resolution_inputs(&project).unwrap(),
            vec![PathBuf::from("config/nested/version.txt")]
        );
        let before = resolution_basis(&project).unwrap();
        fs::write(temp.0.join("config/nested/version.txt"), "2.0.0").unwrap();
        assert_ne!(resolution_basis(&project).unwrap(), before);
        std::os::unix::fs::symlink("config", temp.0.join("linked")).unwrap();
        assert!(resolution_inputs(&project).is_err());
    }

    #[test]
    fn a_cached_preflight_cannot_label_a_changed_project_generation() {
        let temp = TempDir::named("dotnet-captured-plan");
        fs::write(temp.0.join("app.csproj"), csproj("")).unwrap();
        fs::write(
            temp.0.join(LOCK_FILE),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        fs::write(temp.0.join("version.txt"), "A").unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let selected = super::super::shipped_selection().unwrap();
        let checked = preflight(&project, selected.version("dotnet-sdk").unwrap()).unwrap();
        super::super::plan_dotnet(&project, &selected, &checked).unwrap();
        fs::write(temp.0.join("version.txt"), "B").unwrap();
        let why = super::super::plan_dotnet(&project, &selected, &checked)
            .unwrap_err()
            .to_string();
        assert!(why.contains("resolution inputs changed"), "{why}");
        fs::write(temp.0.join("version.txt"), "A").unwrap();
        fs::write(temp.0.join("new.props"), "new input").unwrap();
        assert!(super::super::plan_dotnet(&project, &selected, &checked).is_err());
        fs::remove_file(temp.0.join("new.props")).unwrap();
        fs::write(temp.0.join("app.csproj"), csproj("<!-- changed -->")).unwrap();
        assert!(super::super::plan_dotnet(&project, &selected, &checked).is_err());
    }

    #[test]
    fn alternate_lock_controls_are_refused_in_main_and_imported_files() {
        let temp = TempDir::named("dotnet-lock-control");
        let plain = csproj("");
        fs::write(temp.0.join("app.csproj"), &plain).unwrap();
        fs::write(
            temp.0.join(LOCK_FILE),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        fs::write(
            temp.0.join("alternate.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{}}}}"#,
        )
        .unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let sdk_version = super::super::shipped_selection()
            .unwrap()
            .version("dotnet-sdk")
            .unwrap()
            .to_owned();
        fs::write(temp.0.join("app.csproj"), plain.replace("</Project>", "<PropertyGroup><NuGetLockFilePath>alternate.lock.json</NuGetLockFilePath></PropertyGroup></Project>")).unwrap();
        let why = preflight(&project, &sdk_version).unwrap_err().to_string();
        assert!(why.contains("nugetlockfilepath"), "{why}");
        fs::write(temp.0.join("app.csproj"), &plain).unwrap();
        for control in [
            "<Project TreatAsLocalProperty=\"NuGetLockFilePath;RestoreLockedMode\" />",
            "<Project><PropertyGroup><NuGetLockFilePath>alternate.lock.json</NuGetLockFilePath></PropertyGroup></Project>",
        ] {
            fs::write(temp.0.join("Directory.Build.props"), control).unwrap();
            assert!(preflight(&project, &sdk_version).is_err());
            let utf16: Vec<_> = std::iter::once(0xfeffu16).chain(control.encode_utf16()).flat_map(u16::to_le_bytes).collect();
            fs::write(temp.0.join("Directory.Build.props"), utf16).unwrap();
            assert!(preflight(&project, &sdk_version).is_err());
        }
    }

    /// An unsigned package with one netstandard2.0 asset, so the fixture
    /// restore has a real `.nupkg` to install (the recorded rows kept
    /// Humanizer.Core's index but not its 500 KB body).
    fn fixture_nupkg() -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("Tog.Fixture.nuspec", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<package \
              xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n  \
              <metadata>\n    <id>Tog.Fixture</id>\n    <version>1.0.0</version>\n    \
              <authors>tog</authors>\n    <description>tog test fixture</description>\n  \
              </metadata>\n</package>\n",
        )
        .unwrap();
        zip.start_file("lib/netstandard2.0/_._", options).unwrap();
        zip.finish().unwrap().into_inner()
    }

    /// A harness whose upstream answers api.nuget.org from the recorded
    /// NuGet rows plus a served Tog.Fixture 1.0.0 and an empty
    /// vulnerability base (the recording kept neither body), and whose
    /// proxy every door in this thread uses while it lives.
    fn nuget_harness(label: &str) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(20);
        let rows = stored_rows("dotnet", label);
        let mut kept: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(rows.0.join("index.json")).unwrap()).unwrap();
        let stamp = "2026.09.23.05.36.38";
        for (path, body) in [
            (
                "/v3-flatcontainer/tog.fixture/index.json".to_string(),
                br#"{"versions":["1.0.0"]}"#.to_vec(),
            ),
            (
                "/v3-flatcontainer/tog.fixture/1.0.0/tog.fixture.1.0.0.nupkg".to_string(),
                fixture_nupkg(),
            ),
            (
                format!("/v3-vulnerabilities/{stamp}/vulnerability.base.json"),
                b"{}".to_vec(),
            ),
        ] {
            let file = format!("served{path}.body");
            fs::create_dir_all(rows.0.join(&file).parent().unwrap()).unwrap();
            fs::write(rows.0.join(&file), &body).unwrap();
            kept.retain(|row| row["url"] != format!("https://{HOST}{path}"));
            kept.push(serde_json::json!({
                "method": "GET",
                "url": format!("https://{HOST}{path}"),
                "file": file,
                "sha256": hex::encode(Sha256::digest(&body)),
                "size": body.len(),
                "status": 200,
                "headers": {"content-type": "application/octet-stream"},
            }));
        }
        fs::write(
            rows.0.join("index.json"),
            serde_json::to_vec(&kept).unwrap(),
        )
        .unwrap();
        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            &[HOST],
            &rows.0.to_string_lossy(),
        )));
        std::mem::forget(rows);
        PROXY_FOR_TEST.with(|slot| slot.set(Some(&harness.proxy)));
        Some(harness)
    }

    fn done() {
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        PROXY_FOR_TEST.with(|slot| slot.set(None));
    }

    fn through_door<T>(
        harness: &Harness,
        kind: DoorKind,
        job: impl FnOnce(&mut ResolutionDoor<'_>) -> T,
    ) -> (T, Vec<Exception>) {
        let mut attribution = Attribution::open("dotnet").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            kind,
            &mut attribution,
        )
        .unwrap();
        let out = job(&mut door);
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        (out, recorded)
    }

    fn csproj(references: &str) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
             <TargetFramework>net9.0</TargetFramework>\n  </PropertyGroup>\n  \
             <ItemGroup>\n{references}  </ItemGroup>\n</Project>\n"
        )
    }

    /// The .NET door against the recorded api.nuget.org: a missing lock
    /// restored through the NuGet mirror (the rewritten service index, the
    /// flat container, NuGetAudit's files), published with its record and
    /// no `obj/`, then `tog attest`'s locked-mode check: an unchanged lock
    /// signed, a drifted csproj refused.
    #[test]
    #[ignore = "realizes the store .NET SDK over the network"]
    fn dotnet_restore_attest_without_unix_sockets_through_nuget_mirror() {
        let _env = policy::test_env_lock();
        let _serial = policy::attribution_test_lock();
        let label = "dotnet_restore_attest_without_unix_sockets_through_nuget_mirror";
        let Some(harness) = nuget_harness(label) else {
            return;
        };
        let selected = super::super::shipped_selection().unwrap();
        let sdk = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        let temp = TempDir::named("dotnet-mirror");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        let reference =
            "    <PackageReference Include=\"Tog.Fixture\" Version=\"$(FixtureVersion)\" Condition=\"!Exists('empty-switch')\" />\n";
        fs::write(dir.join("app.csproj"), csproj(reference)).unwrap();
        fs::create_dir_all(dir.join("config")).unwrap();
        fs::write(dir.join("config/version.txt"), "1.0.0").unwrap();
        fs::write(dir.join("config/package.props"), r#"<Project><PropertyGroup>
          <FixtureVersion>$([System.IO.File]::ReadAllText('$(MSBuildThisFileDirectory)version.txt').Trim())</FixtureVersion>
        </PropertyGroup></Project>"#).unwrap();
        fs::write(dir.join("Directory.Build.props"), r#"<Project>
          <Import Project="config/package.props" />
          <PropertyGroup>
            <TogDiagnostics>$([System.Environment]::GetEnvironmentVariable('DOTNET_EnableDiagnostics'))</TogDiagnostics>
            <TogNodeReuse>$([System.Environment]::GetEnvironmentVariable('MSBUILDDISABLENODEREUSE'))</TogNodeReuse>
          </PropertyGroup>
          <Target Name="TogNoUnixSettings" BeforeTargets="Restore">
            <Error Condition="'$(TogDiagnostics)' != '0'" Text="diagnostic IPC not disabled" />
            <Error Condition="'$(TogNodeReuse)' != '1'" Text="MSBuild node reuse not disabled" />
            <Error Condition="'$(MSBuildNodeCount)' != '1'" Text="parallel MSBuild workers not disabled" />
          </Target>
        </Project>"#).unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();

        let (generated, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &held, &sdk, &selected)
        });
        generated.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join(LOCK_FILE)).unwrap();
        assert!(lock.contains("\"Tog.Fixture\""), "{lock}");
        assert!(lock.contains("\"resolved\": \"1.0.0\""), "{lock}");
        assert!(dir.join(".tog/resolution/dotnet.json").is_file());
        assert!(
            !dir.join("obj").exists(),
            "restore output reached the project"
        );

        let (attested, recorded) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        let (record, _) = attested.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(record.outputs.len(), 2, "{:?}", record.outputs);
        for input in [
            "Directory.Build.props",
            "config/package.props",
            "config/version.txt",
        ] {
            assert!(record.inputs.contains_key(input), "{record:?}");
        }
        // Changing data read by an imported props file invalidates the receipt,
        // even though the main project and its lock remain byte-identical.
        let before_basis = resolution_basis(&held).unwrap();
        fs::write(dir.join("config/version.txt"), "2.0.0").unwrap();
        assert_ne!(resolution_basis(&held).unwrap(), before_basis);
        let before_lock = fs::read(dir.join(LOCK_FILE)).unwrap();
        let (changed_data, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        assert!(changed_data.is_err());
        assert_eq!(fs::read(dir.join(LOCK_FILE)).unwrap(), before_lock);
        fs::write(dir.join("config/version.txt"), "1.0.0").unwrap();

        // Empty directories and host execute bits cannot select a different
        // dependency set in the canonical resolver view. The checkout stays intact.
        use std::os::unix::fs::PermissionsExt as _;
        fs::create_dir(dir.join("empty-switch")).unwrap();
        fs::set_permissions(
            dir.join("config/version.txt"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let (canonical, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        canonical.unwrap();
        assert!(dir.join("empty-switch").is_dir());
        assert_eq!(
            fs::metadata(dir.join("config/version.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        fs::write(dir.join("app.csproj"), csproj("")).unwrap();
        let before = fs::read(dir.join(LOCK_FILE)).unwrap();
        let (drifted, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        let why = drifted.unwrap_err().to_string();
        assert!(why.contains("not attested"), "{why}");
        assert_eq!(fs::read(dir.join(LOCK_FILE)).unwrap(), before);
        done();
    }
}
