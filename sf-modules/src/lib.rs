//! `sf-modules` — the 200+ source/detector/tool modules.
//!
//! Each `modules::sfp_*` file implements [`sf_core::Module`] and self-registers
//! via the `inventory`-backed `register_module!` macro. Collect them all with
//! [`all_modules`].

pub mod helpers;
pub mod modules;
pub mod prelude;

pub use sf_core;

/// Instantiate every registered module.
pub fn all_modules() -> Vec<Box<dyn sf_core::Module>> {
    sf_core::registered_modules()
}

/// Number of registered modules.
pub fn module_count() -> usize {
    sf_core::registered_count()
}

/// Reference this from the binary to guarantee the module object files (and
/// thus their `inventory` registrations) are linked in.
pub fn ensure_linked() {
    modules::touch();
}
