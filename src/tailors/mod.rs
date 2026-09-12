//! The tailors: one folder per ecosystem adapter. Each tailor is a leaf of
//! the module graph: it depends on the kernel, never on another tailor or
//! on a command (REFACTOR.md §2). The `Tailor` trait and `registry()` land
//! here in Stage 3.

pub mod cargo;
pub mod dotnet;
pub mod elixir;
pub mod go;
pub mod node;
pub mod python;
pub mod ruby;
