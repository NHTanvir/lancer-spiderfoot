//! Named scan policies that select a module subset by category / flags.

use crate::module::{Category, Module, ModuleFlag};

/// A scan policy (upstream `-u` use-case profiles + custom module lists).
#[derive(Debug, Clone)]
pub enum Policy {
    /// Every registered module (respecting flags / key availability).
    All,
    /// Only `Passive` modules.
    Passive,
    /// `Passive` + `Footprint`.
    Footprint,
    /// `Passive` + `Footprint` + `Investigate`.
    Investigate,
    /// An explicit comma-list of module names.
    Custom(Vec<String>),
}

impl Policy {
    /// Parse a policy name (`all` | `passive` | `footprint` | `investigate`).
    pub fn from_name(s: &str) -> Option<Policy> {
        Some(match s.to_ascii_lowercase().as_str() {
            "all" => Policy::All,
            "passive" => Policy::Passive,
            "footprint" => Policy::Footprint,
            "investigate" => Policy::Investigate,
            _ => return None,
        })
    }

    /// Build a custom policy from a comma-separated module list.
    pub fn custom(list: &str) -> Policy {
        Policy::Custom(
            list.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    }

    fn allows_category(&self, cats: &[Category]) -> bool {
        let has = |c: Category| cats.contains(&c);
        match self {
            Policy::All => true,
            Policy::Passive => has(Category::Passive),
            Policy::Footprint => has(Category::Passive) || has(Category::Footprint),
            Policy::Investigate => {
                has(Category::Passive) || has(Category::Footprint) || has(Category::Investigate)
            }
            Policy::Custom(_) => true,
        }
    }

    /// Filter `modules` according to the policy.
    ///
    /// `has_key` reports whether a module has a usable API key, so `ApiKey`
    /// modules without keys are skipped (except when named explicitly).
    pub fn select(
        &self,
        modules: Vec<Box<dyn Module>>,
        has_key: impl Fn(&str) -> bool,
    ) -> Vec<Box<dyn Module>> {
        match self {
            Policy::Custom(names) => modules
                .into_iter()
                .filter(|m| names.iter().any(|n| n == m.name()))
                .collect(),
            _ => modules
                .into_iter()
                .filter(|m| {
                    if !self.allows_category(m.categories()) {
                        return false;
                    }
                    // Skip key-requiring modules without a key.
                    if m.flags().contains(&ModuleFlag::ApiKey) && !has_key(m.name()) {
                        return false;
                    }
                    // Active/invasive modules are only included by `All`.
                    if m.flags().contains(&ModuleFlag::Invasive)
                        && !matches!(self, Policy::All)
                    {
                        return false;
                    }
                    true
                })
                .collect(),
        }
    }
}
