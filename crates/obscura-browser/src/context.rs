use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use obscura_js::ops::{OriginStorage, OriginStorageError};
use obscura_net::{CookieJar, ObscuraHttpClient, PortableCookie, PortableCookieError, RobotsCache};
use serde::{Deserialize, Serialize};

/// Current broker profile-state schema.
pub const PORTABLE_PROFILE_STATE_VERSION: u16 = 1;

/// Maximum serialized state accepted by the engine for one profile.
pub const PORTABLE_PROFILE_STATE_MAX_BYTES: usize = 25 * 1024 * 1024;

/// Broker-owned browser state. It deliberately excludes sessionStorage,
/// IndexedDB, CacheStorage, service workers, cache, history, and artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableProfileState {
    pub version: u16,
    #[serde(default)]
    pub cookies: Vec<PortableCookie>,
    #[serde(default)]
    pub origins: Vec<PortableOriginState>,
}

impl Default for PortableProfileState {
    fn default() -> Self {
        Self {
            version: PORTABLE_PROFILE_STATE_VERSION,
            cookies: Vec::new(),
            origins: Vec::new(),
        }
    }
}

/// One exact HTTPS origin's durable localStorage entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableOriginState {
    pub origin: String,
    #[serde(default, rename = "localStorage")]
    pub local_storage: Vec<PortableStorageEntry>,
}

/// One localStorage name/value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableStorageEntry {
    pub name: String,
    pub value: String,
}

/// Validation failure for direct broker profile-state operations.
#[derive(Debug, thiserror::Error)]
pub enum ProfileStateError {
    #[error("unsupported portable profile-state version {0}")]
    UnsupportedVersion(u16),
    #[error("profile origin {0:?} is not a canonical HTTPS origin")]
    InvalidOrigin(String),
    #[error("profile origin {0:?} is not in the broker grant set")]
    OriginNotGranted(String),
    #[error("profile cookie domain {0:?} is not covered by the broker grant set")]
    CookieDomainNotGranted(String),
    #[error("portable profile state is {actual} bytes; maximum is {limit}")]
    TooLarge { actual: usize, limit: usize },
    #[error(transparent)]
    Storage(#[from] OriginStorageError),
    #[error(transparent)]
    Cookie(#[from] PortableCookieError),
    #[error("portable profile state could not be encoded: {0}")]
    Encode(#[from] serde_json::Error),
}

pub struct BrowserContext {
    pub id: String,
    pub cookie_jar: Arc<CookieJar>,
    pub local_storage: Arc<OriginStorage>,
    pub http_client: Arc<ObscuraHttpClient>,
    pub user_agent: String,
    pub platform: String,
    pub ua_platform: String,
    pub ua_platform_version: String,
    pub proxy_url: Option<String>,
    pub robots_cache: Arc<RobotsCache>,
    pub obey_robots: bool,
    pub stealth: bool,
    /// When true, CDP-driven navigation to file:// URLs is permitted.
    /// Default is false: a remote CDP client cannot point the browser
    /// at /etc/shadow even if Obscura is running as a privileged user.
    /// Flip on via `obscura serve --allow-file-access` for legitimate
    /// local-HTML testing workflows. The CLI's own `obscura fetch
    /// file://...` path is unaffected because it does not go through
    /// the CDP server.
    pub allow_file_access: bool,
    pub storage_dir: Option<PathBuf>,
    /// When true, the http client allows fetching localhost / RFC1918 /
    /// link-local addresses. Set via `--allow-private-network` (issue #33).
    /// Independent of `allow_file_access` because they cover different threat
    /// models: file:// is a local file-system read, while private-network is
    /// the broader SSRF gate from issue #4.
    pub allow_private_network: bool,
}

impl BrowserContext {
    pub fn new(id: String) -> Self {
        Self::_new_inner(id, None, false, None, None, false)
    }

    /// Create a BrowserContext with an optional legacy cookie directory.
    /// When `storage_dir` is set, cookies are automatically loaded from
    /// `{storage_dir}/cookies.json` on creation. Local and session storage are
    /// never loaded from this directory.
    pub fn with_storage(id: String, storage_dir: Option<PathBuf>) -> Self {
        Self::_new_inner(id, None, false, None, storage_dir, false)
    }

    /// Create a BrowserContext with full options including storage_dir.
    pub fn with_storage_full(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, storage_dir, false)
    }

    /// Variant that also accepts the `allow_private_network` opt-in. All
    /// pre-existing constructors default it to `false`; callers that want the
    /// CLI's `--allow-private-network` (issue #33) behaviour go through here.
    pub fn with_storage_and_network(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
        allow_private_network: bool,
    ) -> Self {
        Self::_new_inner(
            id,
            proxy_url,
            stealth,
            user_agent,
            storage_dir,
            allow_private_network,
        )
    }

    fn _new_inner(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
        allow_private_network: bool,
    ) -> Self {
        let cookie_jar = Arc::new(CookieJar::new());

        // Restore cookies from disk if storage_dir is configured
        if let Some(ref dir) = storage_dir {
            let cookie_path = dir.join("cookies.json");
            if cookie_path.exists() {
                match cookie_jar.load_from_file(&cookie_path) {
                    Ok(n) if n > 0 => {
                        tracing::info!("Loaded {} cookies from {}", n, cookie_path.display());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load cookies from {}: {}",
                            cookie_path.display(),
                            e
                        );
                    }
                }
            }
        }

        let mut client = ObscuraHttpClient::with_full_options(
            cookie_jar.clone(),
            proxy_url.as_deref(),
            allow_private_network,
        );
        if stealth {
            client.block_trackers = true;
        }
        let profile = crate::profiles::select_profile();
        let resolved_ua = user_agent.unwrap_or_else(|| profile.user_agent.to_string());
        let platform = profile.platform.to_string();
        let ua_platform = profile.ua_platform.to_string();
        let ua_platform_version = profile.ua_platform_version.to_string();
        // Sync the http client's UA at construction so navigation requests pick it
        // up before any async setup runs. The lock has no other holders here, so
        // try_write always succeeds; we fall back silently if it ever fails.
        if let Ok(mut guard) = client.user_agent.try_write() {
            *guard = resolved_ua.clone();
        }
        let http_client = Arc::new(client);
        BrowserContext {
            id,
            cookie_jar,
            local_storage: Arc::new(OriginStorage::default()),
            http_client,
            user_agent: resolved_ua,
            platform,
            ua_platform,
            ua_platform_version,
            proxy_url,
            robots_cache: Arc::new(RobotsCache::new()),
            obey_robots: false,
            stealth,
            allow_file_access: false,
            storage_dir,
            allow_private_network,
        }
    }

    pub fn with_options(id: String, proxy_url: Option<String>, stealth: bool) -> Self {
        Self::with_full_options(id, proxy_url, stealth, None)
    }

    pub fn with_full_options(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, None, false)
    }

    pub fn with_proxy(id: String, proxy_url: Option<String>) -> Self {
        Self::with_options(id, proxy_url, false)
    }

    /// Create a context with the same browser configuration but independent
    /// mutable network state. Persistent copies start with the template's
    /// current cookies; incognito copies start empty and never write to the
    /// template's storage directory.
    pub fn isolated_copy(&self, id: String, persistent: bool) -> Self {
        let cookie_jar = Arc::new(CookieJar::new());
        if persistent {
            cookie_jar.copy_from(&self.cookie_jar);
        }

        let mut client = ObscuraHttpClient::with_full_options(
            cookie_jar.clone(),
            self.proxy_url.as_deref(),
            self.allow_private_network,
        );
        if self.stealth {
            client.block_trackers = true;
        }
        if let Ok(mut guard) = client.user_agent.try_write() {
            *guard = self.user_agent.clone();
        }

        BrowserContext {
            id,
            cookie_jar,
            local_storage: Arc::new(OriginStorage::default()),
            http_client: Arc::new(client),
            user_agent: self.user_agent.clone(),
            platform: self.platform.clone(),
            ua_platform: self.ua_platform.clone(),
            ua_platform_version: self.ua_platform_version.clone(),
            proxy_url: self.proxy_url.clone(),
            robots_cache: Arc::new(RobotsCache::new()),
            obey_robots: self.obey_robots,
            stealth: self.stealth,
            allow_file_access: self.allow_file_access,
            storage_dir: persistent.then(|| self.storage_dir.clone()).flatten(),
            allow_private_network: self.allow_private_network,
        }
    }

    /// Persist cookies to disk if storage_dir is configured.
    /// Called during graceful shutdown.
    pub fn save_cookies(&self) {
        if let Some(ref dir) = self.storage_dir {
            let _ = std::fs::create_dir_all(dir);
            let cookie_path = dir.join("cookies.json");
            if let Err(e) = self.cookie_jar.save_to_file(&cookie_path) {
                tracing::warn!("Failed to save cookies to {}: {}", cookie_path.display(), e);
            } else {
                tracing::info!("Saved cookies to {}", cookie_path.display());
            }
        }
    }

    /// Export cookies and granted-origin localStorage for a trusted broker.
    ///
    /// The operation reads native context state directly and never navigates a
    /// page or executes page JavaScript. Callers must supply the exact HTTPS
    /// origins currently approved for the profile.
    pub fn export_portable_state(
        &self,
        granted_origins: &[String],
    ) -> Result<PortableProfileState, ProfileStateError> {
        let grants = canonical_grants(granted_origins)?;
        let snapshot = self.local_storage.snapshot_all();
        let mut origins = Vec::new();
        for (raw_origin, entries) in snapshot {
            let Ok(origin) = canonical_https_origin(&raw_origin) else {
                // Opaque origins are intentionally never durable.
                continue;
            };
            if !grants.contains(&origin) {
                continue;
            }
            let mut local_storage = entries
                .into_iter()
                .map(|(name, value)| PortableStorageEntry { name, value })
                .collect::<Vec<_>>();
            local_storage.sort_by(|left, right| left.name.cmp(&right.name));
            origins.push(PortableOriginState {
                origin,
                local_storage,
            });
        }
        origins.sort_by(|left, right| left.origin.cmp(&right.origin));

        let cookies = self
            .cookie_jar
            .export_portable_cookies()
            .into_iter()
            .filter(|cookie| cookie_is_granted(cookie, &grants))
            .collect();
        let state = PortableProfileState {
            version: PORTABLE_PROFILE_STATE_VERSION,
            cookies,
            origins,
        };
        enforce_profile_size(&state)?;
        Ok(state)
    }

    /// Import a broker profile snapshot directly into a pristine context.
    ///
    /// This must be called before navigation. The complete payload is
    /// validated before either store changes, and sessionStorage is absent by
    /// construction.
    pub fn import_portable_state(
        &self,
        state: PortableProfileState,
        granted_origins: &[String],
    ) -> Result<(), ProfileStateError> {
        if state.version != PORTABLE_PROFILE_STATE_VERSION {
            return Err(ProfileStateError::UnsupportedVersion(state.version));
        }
        enforce_profile_size(&state)?;
        let grants = canonical_grants(granted_origins)?;
        let mut origins = HashMap::new();
        for origin_state in &state.origins {
            let origin = canonical_https_origin(&origin_state.origin)?;
            if !grants.contains(&origin) {
                return Err(ProfileStateError::OriginNotGranted(origin));
            }
            if origins
                .insert(
                    origin.clone(),
                    origin_state
                        .local_storage
                        .iter()
                        .map(|entry| (entry.name.clone(), entry.value.clone()))
                        .collect(),
                )
                .is_some()
            {
                return Err(ProfileStateError::InvalidOrigin(origin));
            }
        }
        for cookie in &state.cookies {
            if !cookie_is_granted(cookie, &grants) {
                return Err(ProfileStateError::CookieDomainNotGranted(
                    cookie.domain.clone(),
                ));
            }
            if let Some(partition_key) = &cookie.partition_key {
                let partition_key = canonical_https_origin(partition_key)?;
                if !grants.contains(&partition_key) {
                    return Err(ProfileStateError::OriginNotGranted(partition_key));
                }
            }
        }

        // Validate in detached stores first. Applying the already validated
        // values below cannot fail, and callers invoke this before navigation.
        let candidate_storage = OriginStorage::default();
        candidate_storage.replace_all(origins.clone())?;
        let candidate_cookies = CookieJar::new();
        candidate_cookies.replace_portable_cookies(state.cookies.clone())?;

        self.local_storage.replace_all(origins)?;
        self.cookie_jar.replace_portable_cookies(state.cookies)?;
        Ok(())
    }
}

fn canonical_https_origin(raw: &str) -> Result<String, ProfileStateError> {
    let parsed = url::Url::parse(raw).map_err(|_| ProfileStateError::InvalidOrigin(raw.into()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(ProfileStateError::InvalidOrigin(raw.into()));
    }
    Ok(parsed.origin().ascii_serialization())
}

fn canonical_grants(origins: &[String]) -> Result<HashSet<String>, ProfileStateError> {
    origins
        .iter()
        .map(|origin| canonical_https_origin(origin))
        .collect()
}

fn cookie_is_granted(cookie: &PortableCookie, grants: &HashSet<String>) -> bool {
    let domain = obscura_net::canonical_domain(&cookie.domain);
    grants.iter().any(|origin| {
        let Ok(url) = url::Url::parse(origin) else {
            return false;
        };
        let Some(host) = url.host_str() else {
            return false;
        };
        if cookie.host_only {
            host.eq_ignore_ascii_case(&domain)
        } else {
            host.eq_ignore_ascii_case(&domain)
                || host
                    .strip_suffix(&domain)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }
    })
}

fn enforce_profile_size(state: &PortableProfileState) -> Result<(), ProfileStateError> {
    let actual = serde_json::to_vec(state)?.len();
    if actual > PORTABLE_PROFILE_STATE_MAX_BYTES {
        return Err(ProfileStateError::TooLarge {
            actual,
            limit: PORTABLE_PROFILE_STATE_MAX_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn with_full_options_propagates_user_agent_to_http_client() {
        let ctx = BrowserContext::with_full_options(
            "test".to_string(),
            None,
            false,
            Some("Custom-UA/1.0".to_string()),
        );
        assert_eq!(ctx.user_agent, "Custom-UA/1.0");
        let client_ua = ctx.http_client.user_agent.read().await.clone();
        assert_eq!(client_ua, "Custom-UA/1.0");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_full_options_falls_back_to_chrome_default() {
        let ctx = BrowserContext::with_full_options("test".to_string(), None, false, None);
        assert!(ctx.user_agent.contains("Chrome"));
        let client_ua = ctx.http_client.user_agent.read().await.clone();
        assert!(client_ua.contains("Chrome"));
        assert_eq!(ctx.user_agent, client_ua);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_options_keeps_default_user_agent() {
        let ctx = BrowserContext::with_options("test".to_string(), None, false);
        assert!(ctx.user_agent.contains("Chrome"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn isolated_copy_does_not_share_mutable_network_state() {
        let source = BrowserContext::with_full_options(
            "source".to_string(),
            None,
            false,
            Some("Template-UA/1.0".to_string()),
        );
        source.cookie_jar.set_cookie(
            "sid=source",
            &url::Url::parse("https://example.com").unwrap(),
        );

        let persistent = source.isolated_copy("persistent".to_string(), true);
        let incognito = source.isolated_copy("incognito".to_string(), false);

        assert_eq!(persistent.cookie_jar.get_all_cookies().len(), 1);
        assert!(incognito.cookie_jar.get_all_cookies().is_empty());
        assert!(persistent
            .cookie_jar
            .get_cookie_header(&url::Url::parse("https://sub.example.com").unwrap())
            .is_empty());
        persistent.cookie_jar.clear();
        persistent
            .http_client
            .set_user_agent("Changed-UA/2.0")
            .await;

        assert_eq!(source.cookie_jar.get_all_cookies().len(), 1);
        assert_eq!(
            source.http_client.user_agent.read().await.as_str(),
            "Template-UA/1.0"
        );
    }

    #[test]
    fn portable_state_roundtrip_is_direct_grant_scoped_and_has_no_session_storage() {
        let source = BrowserContext::new("source".to_string());
        source
            .local_storage
            .replace_all(HashMap::from([
                (
                    "https://example.com".to_string(),
                    vec![("token".to_string(), "allowed".to_string())],
                ),
                (
                    "https://other.test".to_string(),
                    vec![("token".to_string(), "excluded".to_string())],
                ),
                (
                    "opaque:7".to_string(),
                    vec![("secret".to_string(), "excluded".to_string())],
                ),
            ]))
            .unwrap();
        source
            .cookie_jar
            .replace_portable_cookies(vec![PortableCookie {
                name: "sid".to_string(),
                value: "session".to_string(),
                domain: "example.com".to_string(),
                path: "/".to_string(),
                host_only: true,
                secure: true,
                http_only: true,
                same_site: "Lax".to_string(),
                expires: None,
                partition_key: None,
            }])
            .unwrap();

        let grants = vec!["https://example.com".to_string()];
        let state = source.export_portable_state(&grants).unwrap();
        let encoded = serde_json::to_string(&state).unwrap();
        assert!(!encoded.contains("sessionStorage"));
        assert_eq!(state.origins.len(), 1);
        assert_eq!(state.origins[0].origin, "https://example.com");
        assert_eq!(state.cookies.len(), 1);

        let destination = BrowserContext::new("destination".to_string());
        destination
            .import_portable_state(state.clone(), &grants)
            .unwrap();
        assert_eq!(destination.export_portable_state(&grants).unwrap(), state);
    }

    #[test]
    fn rejected_profile_import_does_not_change_existing_state() {
        let context = BrowserContext::new("profile".to_string());
        context
            .local_storage
            .replace_all(HashMap::from([(
                "https://example.com".to_string(),
                vec![("existing".to_string(), "kept".to_string())],
            )]))
            .unwrap();
        let before = context.local_storage.snapshot_all();
        let state = PortableProfileState {
            version: PORTABLE_PROFILE_STATE_VERSION,
            cookies: Vec::new(),
            origins: vec![PortableOriginState {
                origin: "https://unapproved.test".to_string(),
                local_storage: vec![PortableStorageEntry {
                    name: "bad".to_string(),
                    value: "value".to_string(),
                }],
            }],
        };

        assert!(matches!(
            context.import_portable_state(state, &["https://example.com".to_string()]),
            Err(ProfileStateError::OriginNotGranted(_))
        ));
        assert_eq!(context.local_storage.snapshot_all(), before);
    }
}
