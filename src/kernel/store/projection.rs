//! Projection references (kernel store): where a root's environment is
//! projected, as `ProjectionBase` plus a validated relative path.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionBase {
    Forests,
    Backups,
}

impl ProjectionBase {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Forests => "forests",
            Self::Backups => "backups",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Forests => 0,
            Self::Backups => 1,
        }
    }
}

/// A typed, relative projection reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRef {
    pub base: ProjectionBase,
    pub components: Vec<OsString>,
}

impl Ord for ProjectionRef {
    fn cmp(&self, other: &Self) -> Ordering {
        self.base.rank().cmp(&other.base.rank()).then_with(|| {
            self.components
                .iter()
                .map(|component| component.as_os_str().as_bytes())
                .cmp(
                    other
                        .components
                        .iter()
                        .map(|component| component.as_os_str().as_bytes()),
                )
        })
    }
}

impl PartialOrd for ProjectionRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ProjectionRef {
    pub fn new(base: ProjectionBase, components: Vec<OsString>) -> io::Result<Self> {
        let reference = Self { base, components };
        validate_projection_components(&reference.components)?;
        Ok(reference)
    }

    pub fn path(&self, store: &Store) -> PathBuf {
        let base = match self.base {
            ProjectionBase::Forests => store.root.join("forests"),
            ProjectionBase::Backups => store.root.join("backups"),
        };
        self.components
            .iter()
            .fold(base, |path, component| path.join(component))
    }
}

impl Store {
    pub(crate) fn projection_ref(
        &self,
        base: ProjectionBase,
        path: &Path,
    ) -> io::Result<ProjectionRef> {
        let prefix = match base {
            ProjectionBase::Forests => self.root.join("forests"),
            ProjectionBase::Backups => self.root.join("backups"),
        };
        let relative = path.strip_prefix(&prefix).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("projection {} is outside this store", path.display()),
            )
        })?;
        validate_projection_path(&prefix, path)?;
        let components = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "projection {} contains an invalid component",
                        path.display()
                    ),
                )),
            })
            .collect::<io::Result<Vec<_>>>()?;
        ProjectionRef::new(base, components)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionWire {
    base: String,
    components: Vec<PathWire>,
}

pub(super) fn projection_wire(reference: &ProjectionRef) -> ProjectionWire {
    ProjectionWire {
        base: reference.base.wire_name().into(),
        components: reference
            .components
            .iter()
            .map(|component| path_wire(Path::new(component)))
            .collect(),
    }
}

pub(super) fn projection_from_wire(wire: ProjectionWire, label: &str) -> io::Result<ProjectionRef> {
    let base = match wire.base.as_str() {
        "forests" => ProjectionBase::Forests,
        "backups" => ProjectionBase::Backups,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} has unknown projection base {other}"),
            ))
        }
    };
    let mut components = Vec::with_capacity(wire.components.len());
    for (index, component) in wire.components.iter().enumerate() {
        let path = path_from_wire(component, &format!("{label} component {index}"))?;
        let mut iter = path.components();
        let Some(std::path::Component::Normal(name)) = iter.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} component {index} is empty or not a name"),
            ));
        };
        if iter.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} component {index} contains a slash"),
            ));
        }
        components.push(name.to_os_string());
    }
    ProjectionRef::new(base, components)
}

pub(super) fn validate_projection_components(components: &[OsString]) -> io::Result<()> {
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "projection reference must contain at least one component",
        ));
    }
    for component in components {
        let bytes = component.as_os_str().as_bytes();
        if bytes.is_empty()
            || bytes.contains(&0)
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection reference contains an invalid component",
            ));
        }
    }
    Ok(())
}

/// Check existing projection path components without following symlinks. A
/// reserved destination may not exist yet, so the walk stops at the first
/// missing component and lets the producer create it later. Existing parent
/// components must be real directories inside the selected store namespace.
pub(super) fn validate_projection_path(prefix: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(prefix).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "projection {} is outside its store namespace",
                path.display()
            ),
        )
    })?;
    let mut current = prefix.to_path_buf();
    let prefix_metadata = fs::symlink_metadata(prefix)?;
    if prefix_metadata.file_type().is_symlink() || !prefix_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "projection namespace {} is not a real directory",
                prefix.display()
            ),
        ));
    }
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "projection {} contains an invalid component",
                    path.display()
                ),
            ));
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "projection {} contains a symlinked component {}",
                    path.display(),
                    current.display()
                ),
            ));
        }
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "projection {} contains a non-directory component {}",
                    path.display(),
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn projection_reference_for_path(
    store: &Store,
    path: &Path,
) -> io::Result<Option<ProjectionRef>> {
    let bases = [
        (ProjectionBase::Forests, store.root.join("forests")),
        (ProjectionBase::Backups, store.root.join("backups")),
    ];
    for (base, prefix) in bases {
        let Ok(relative) = path.strip_prefix(&prefix) else {
            continue;
        };
        let components: Vec<OsString> = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("projection path {path:?} contains an invalid component"),
                )),
            })
            .collect::<io::Result<Vec<_>>>()?;
        return ProjectionRef::new(base, components).map(Some);
    }
    Ok(None)
}
