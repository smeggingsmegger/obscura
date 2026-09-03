use serde::{Deserialize, Serialize};

/// Machine-readable runtime capabilities consumed by a supervising broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    pub schema_version: u16,
    pub runtime: String,
    pub rendered_dom: bool,
    pub screenshots: bool,
    pub stealth_transport: bool,
    pub request_interception: bool,
    pub screencast_frames: bool,
    pub complete_viewer_input: bool,
    pub direct_portable_state: bool,
    pub persistent_profiles_certified: bool,
    pub durable_local_storage: bool,
    pub durable_session_storage: bool,
}

impl RuntimeCapabilities {
    /// Capabilities compiled into this Obscura binary.
    pub fn current() -> Self {
        Self {
            schema_version: 1,
            runtime: "obscura".to_string(),
            rendered_dom: true,
            screenshots: cfg!(feature = "render"),
            stealth_transport: cfg!(feature = "stealth"),
            request_interception: true,
            screencast_frames: cfg!(feature = "render"),
            // Obscura intentionally does not advertise profile/manual viewer
            // eligibility until the full input and cookie fidelity suites pass.
            complete_viewer_input: false,
            direct_portable_state: true,
            persistent_profiles_certified: false,
            durable_local_storage: true,
            durable_session_storage: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_session_storage_capabilities_fail_closed() {
        let capabilities = RuntimeCapabilities::current();
        assert!(!capabilities.persistent_profiles_certified);
        assert!(!capabilities.complete_viewer_input);
        assert!(!capabilities.durable_session_storage);
        assert!(capabilities.direct_portable_state);
    }
}
