//! Call logger plugin — structured `tracing` output for every tool call.
//!
//! Always allows requests (never blocks). Emits pre-dispatch and
//! post-dispatch log entries with configurable sampling and field
//! redaction (builtin credential-key allowlist + value heuristic).
//! Redaction is applied to both arguments and results; over-long values
//! are truncated on a UTF-8 char boundary so a multibyte payload can't
//! turn a log line into a request-controlled Deny.
//!
//! This crate ships as a `native-cdylib-v1` plugin distributed via
//! OCI. See `plugin.yaml` for the descriptor; the plugin protocol /
//! ABI version is frozen at 1 until the first public release.
//! Operator config:
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.call-logger
//!     kind: native
//!     class: tool_gate
//!     source:
//!       oci: ghcr.io/mcpg-dev/source-code/plugins/call-logger:<version>
//!     config:
//!       sample_rate: 1.0
//!       log_arguments: true
//!       log_results: true
//!       max_argument_bytes: 4096
//!       max_result_bytes: 8192
//!       redact_fields: []
//! ```

use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::Deserialize;
use serde_json::Value;

const PLUGIN_ID: &str = "dev.mcpg.call-logger";

/// Configuration for the call logger plugin. Deserialised from the
/// `config:` block of the operator's `plugins[]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallLoggerPluginConfig {
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    #[serde(default = "bool_true")]
    pub log_arguments: bool,
    #[serde(default = "bool_true")]
    pub log_results: bool,
    #[serde(default = "default_max_argument_bytes")]
    pub max_argument_bytes: usize,
    #[serde(default = "default_max_result_bytes")]
    pub max_result_bytes: usize,
    #[serde(default)]
    pub redact_fields: Vec<String>,
}

fn default_sample_rate() -> f64 {
    1.0
}
fn bool_true() -> bool {
    true
}
fn default_max_argument_bytes() -> usize {
    4096
}
fn default_max_result_bytes() -> usize {
    8192
}

impl Default for CallLoggerPluginConfig {
    fn default() -> Self {
        Self {
            sample_rate: 1.0,
            log_arguments: true,
            log_results: true,
            max_argument_bytes: 4096,
            max_result_bytes: 8192,
            redact_fields: Vec::new(),
        }
    }
}

/// Structured logging plugin for tool calls.
///
/// Emits structured log entries via `tracing` for pre-dispatch and
/// post-dispatch events. Always returns `GateDecision::Allow` —
/// never blocks requests.
pub struct CallLoggerPlugin {
    config: CallLoggerPluginConfig,
    manifest: PluginManifest,
}

impl CallLoggerPlugin {
    pub fn new(config: CallLoggerPluginConfig) -> Self {
        tracing::warn!(
            log_arguments = config.log_arguments,
            log_results = config.log_results,
            sample_rate = config.sample_rate,
            "call-logger plugin is BETA: full request/response payloads may be logged — \
             ensure log sinks are appropriately secured"
        );
        metrics::counter!("mcpg_call_logger_beta_warning_total").increment(1);

        Self {
            config,
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "Call Logger".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
        }
    }

    /// Parse the operator config JSON. Used by the SDK macro factory.
    /// Fails CLOSED: a present-but-malformed config refuses the plugin
    /// (panic → null handle → host boot rejection) rather than silently
    /// degrading to defaults. An empty / absent config block still
    /// yields `Default`.
    pub fn from_config_json(config_json: &str) -> Self {
        let config: CallLoggerPluginConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, CallLoggerPluginConfig);
        Self::new(config)
    }

    fn should_sample(&self) -> bool {
        if self.config.sample_rate >= 1.0 {
            return true;
        }
        if self.config.sample_rate <= 0.0 {
            return false;
        }
        rand_f64() < self.config.sample_rate
    }

    fn redact_and_truncate(&self, value: &Value, max_bytes: usize) -> String {
        let redacted = redact_fields(value, &self.config.redact_fields);
        let serialized = serde_json::to_string(&redacted).unwrap_or_default();
        if serialized.len() > max_bytes {
            // Truncate on a UTF-8 char boundary. A raw byte slice
            // (`&serialized[..max_bytes]`) panics when a multibyte
            // sequence straddles `max_bytes`; because the gate body is
            // wrapped in `catch_panic_to_deny`, that panic would turn
            // this always-Allow logger into a request-controlled `Deny`
            // (and, post-dispatch, mask an otherwise-successful result).
            let mut end = max_bytes.min(serialized.len());
            while end > 0 && !serialized.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...[truncated]", &serialized[..end])
        } else {
            serialized
        }
    }
}

impl SyncToolGate for CallLoggerPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if !self.should_sample() {
            // Emit-outcome counter so operators can verify the
            // sampler is doing what they configured.
            metrics::counter!(
                "mcpg_call_logger_emits_total",
                "phase" => "pre",
                "outcome" => "sampled_out",
            )
            .increment(1);
            return GateDecision::allow();
        }

        let safe_args = if self.config.log_arguments {
            Some(self.redact_and_truncate(arguments, self.config.max_argument_bytes))
        } else {
            None
        };

        tracing::info!(
            event = "tool_call_start",
            request_id = %ctx.request_id,
            tool = %ctx.tool_name,
            transport = %ctx.transport,
            identity.kind = %ctx.identity.kind,
            identity.subject = ?ctx.identity.subject_id,
            identity.trust = %ctx.identity.trust_level,
            arguments = ?safe_args,
        );
        metrics::counter!(
            "mcpg_call_logger_emits_total",
            "phase" => "pre",
            "outcome" => "emitted",
        )
        .increment(1);

        GateDecision::allow()
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        _arguments: &Value,
        result: &Value,
        duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        if !self.should_sample() {
            metrics::counter!(
                "mcpg_call_logger_emits_total",
                "phase" => "post",
                "outcome" => "sampled_out",
            )
            .increment(1);
            return GateDecision::allow();
        }

        let safe_result = if self.config.log_results {
            Some(self.redact_and_truncate(result, self.config.max_result_bytes))
        } else {
            None
        };

        tracing::info!(
            event = "tool_call_end",
            request_id = %ctx.request_id,
            tool = %ctx.tool_name,
            duration_ms = duration_ms,
            result = ?safe_result,
        );
        metrics::counter!(
            "mcpg_call_logger_emits_total",
            "phase" => "post",
            "outcome" => "emitted",
        )
        .increment(1);

        GateDecision::allow()
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: CallLoggerPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| CallLoggerPlugin::from_config_json(cfg),
        }
    ],
}

/// Credential key names whose *values* are ALWAYS redacted
/// (case-insensitive), independent of the operator's `redact_fields`.
/// Mirrors the audit plugin's `REDACT_KEYS` so a misconfigured (or
/// empty) `redact_fields` can never leak Authorization / Cookie /
/// api-key / token values into the log stream.
const BUILTIN_REDACT_KEYS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api_key",
    "api-key",
    "apikey",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
];

/// Recursively redact: (a) any key the operator named in `fields`,
/// (b) any key matching a built-in credential name, and (c) any string
/// *value* that looks like a credential. (b) and (c) are always applied
/// — the operator's list is purely additive — so the logger fails safe
/// even when `redact_fields` is empty (the default) or omits a header.
fn redact_fields(value: &Value, fields: &[String]) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let redact_key = fields.iter().any(|f| f.eq_ignore_ascii_case(k))
                    || BUILTIN_REDACT_KEYS
                        .iter()
                        .any(|needle| k.eq_ignore_ascii_case(needle));
                if redact_key {
                    out.insert(k.clone(), Value::String("[REDACTED]".to_owned()));
                } else {
                    out.insert(k.clone(), redact_fields(v, fields));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| redact_fields(v, fields)).collect()),
        Value::String(s) => {
            if looks_like_credential(s) {
                Value::String("[REDACTED]".to_owned())
            } else {
                // Whole-value heuristic missed it, but a value may still
                // embed a credential in a URL's userinfo — scrub those.
                Value::String(mcpg_plugin_protocol::redact::redact_in_text(s))
            }
        }
        other => other.clone(),
    }
}

/// Heuristic value scan for secrets that arrive without a tell-tale key
/// (e.g. a bare `Authorization: Bearer …` value, cloud provider key
/// prefixes, PEM private keys, or a JWT-shaped triple). Mirrors the
/// audit plugin's `looks_like_credential`.
fn looks_like_credential(s: &str) -> bool {
    let lower = s.trim_start().to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") || lower.starts_with("dpop ") {
        return true;
    }
    if s.starts_with("sk_")
        || s.starts_with("pk_")
        || s.starts_with("AKIA")
        || s.starts_with("AIza")
        || s.starts_with("ya29.")
        || s.starts_with("ghp_")
        || s.starts_with("xoxb-")
        || s.starts_with("xoxp-")
    {
        return true;
    }
    if s.contains("-----BEGIN ") && s.contains(" PRIVATE KEY-----") {
        return true;
    }
    // JWT-shaped: three non-empty base64url segments, first two ≥ 8 chars.
    if s.matches('.').count() == 2 {
        let segs: Vec<&str> = s.split('.').collect();
        if segs.iter().all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        }) && segs[0].len() >= 8
            && segs[1].len() >= 8
        {
            return true;
        }
    }
    false
}

/// Simple pseudo-random f64 in [0, 1) using thread-local state.
fn rand_f64() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let hash = hasher.finish();
    (hash as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;

    fn test_ctx() -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-001".to_owned(),
            session_id: Some("sess-001".to_owned()),
            tool_name: "test_tool".to_owned(),
            identity: PluginIdentity {
                kind: "verified".to_owned(),
                subject_id: Some("user@example.com".to_owned()),
                trust_level: "verified".to_owned(),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            },
            transport: "http".to_owned(),
        }
    }

    #[test]
    fn redacts_sensitive_fields() {
        let input = serde_json::json!({
            "city": "London",
            "password": "secret123",
            "nested": {
                "token": "tok_abc",
                "safe": "value"
            }
        });
        let result = redact_fields(&input, &["password".to_owned(), "token".to_owned()]);
        assert_eq!(result["city"], "London");
        assert_eq!(result["password"], "[REDACTED]");
        assert_eq!(result["nested"]["token"], "[REDACTED]");
        assert_eq!(result["nested"]["safe"], "value");
    }

    #[test]
    fn redacts_nested_arrays() {
        let input = serde_json::json!([
            {"password": "secret"},
            {"safe": "ok"}
        ]);
        let result = redact_fields(&input, &["password".to_owned()]);
        assert_eq!(result[0]["password"], "[REDACTED]");
        assert_eq!(result[1]["safe"], "ok");
    }

    #[test]
    fn truncates_large_values() {
        let plugin = CallLoggerPlugin::new(CallLoggerPluginConfig::default());
        let large = serde_json::json!({"data": "x".repeat(10000)});
        let result = plugin.redact_and_truncate(&large, 100);
        assert!(result.len() <= 120);
        assert!(result.ends_with("...[truncated]"));
    }

    #[test]
    fn sampling_zero_never_logs() {
        let plugin = CallLoggerPlugin::new(CallLoggerPluginConfig {
            sample_rate: 0.0,
            ..Default::default()
        });
        assert!(!plugin.should_sample());
    }

    #[test]
    fn sampling_one_always_logs() {
        let plugin = CallLoggerPlugin::new(CallLoggerPluginConfig {
            sample_rate: 1.0,
            ..Default::default()
        });
        assert!(plugin.should_sample());
    }

    #[test]
    fn always_returns_allow_pre() {
        let plugin = CallLoggerPlugin::new(Default::default());
        let ctx = test_ctx();
        let args = serde_json::json!({"city": "London"});
        let decision = plugin.evaluate_pre(&ctx, &args, None, &Value::Null);
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[test]
    fn always_returns_allow_post() {
        let plugin = CallLoggerPlugin::new(Default::default());
        let ctx = test_ctx();
        let args = serde_json::json!({"city": "London"});
        let result = serde_json::json!({"temp": 15});
        let decision = plugin.evaluate_post(&ctx, &args, &result, 100, &Value::Null);
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[test]
    fn disabled_arguments_not_logged() {
        let plugin = CallLoggerPlugin::new(CallLoggerPluginConfig {
            log_arguments: false,
            ..Default::default()
        });
        assert!(!plugin.config.log_arguments);
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = CallLoggerPlugin::new(Default::default());
        let m = SyncToolGate::manifest(&plugin);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
    }

    #[test]
    fn from_config_json_parses_full_config() {
        let json = r#"{"sample_rate":0.5,"log_arguments":false,"redact_fields":["k"]}"#;
        let plugin = CallLoggerPlugin::from_config_json(json);
        assert_eq!(plugin.config.sample_rate, 0.5);
        assert!(!plugin.config.log_arguments);
        assert_eq!(plugin.config.redact_fields, vec!["k".to_owned()]);
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn from_config_json_fails_closed_on_malformed() {
        // A present-but-malformed config must REFUSE the plugin (fail
        // closed), not silently degrade to defaults.
        let _ = CallLoggerPlugin::from_config_json("not json");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn from_config_json_fails_closed_on_unknown_key() {
        // A stray / renamed / typo'd config key must REFUSE the plugin
        // (deny_unknown_fields → parse error → fail closed), not be
        // silently ignored.
        let json = r#"{"sample_rate":0.5,"sampl_rate":0.9}"#;
        let _ = CallLoggerPlugin::from_config_json(json);
    }

    #[test]
    fn from_config_json_empty_yields_defaults() {
        // An empty / absent config block is an opt-out, not a typo: it
        // still uses Default.
        for empty in ["", "{}", "null"] {
            let plugin = CallLoggerPlugin::from_config_json(empty);
            assert_eq!(plugin.config.sample_rate, 1.0);
            assert!(plugin.config.log_arguments);
            assert!(plugin.config.log_results);
            assert_eq!(plugin.config.max_argument_bytes, 4096);
            assert_eq!(plugin.config.max_result_bytes, 8192);
            assert!(plugin.config.redact_fields.is_empty());
        }
    }

    // ----- multibyte-UTF-8 truncation must not panic -----

    #[test]
    fn truncate_on_char_boundary_does_not_panic() {
        // A value whose serialized form straddles `max_bytes` mid-codepoint
        // must truncate cleanly (not panic → Deny). "€" is 3 bytes; build a
        // string that puts a multibyte char across every plausible boundary.
        let plugin = CallLoggerPlugin::new(CallLoggerPluginConfig::default());
        let big = "€".repeat(5000);
        let val = serde_json::json!({ "data": big });
        for max in [10usize, 11, 12, 13, 99, 100, 101, 4096] {
            let out = plugin.redact_and_truncate(&val, max);
            assert!(out.ends_with("...[truncated]"), "max={max}");
            // The kept prefix is valid UTF-8 by construction (we sliced on a
            // char boundary); reaching here without a panic is the assertion.
            assert!(out.len() <= max + "...[truncated]".len() + 4, "max={max}");
        }
    }

    #[test]
    fn truncate_boundary_below_first_char() {
        // If even the first char doesn't fit, we truncate to empty (end=0)
        // rather than panicking.
        let plugin = CallLoggerPlugin::new(CallLoggerPluginConfig::default());
        let val = serde_json::json!("€€€");
        let out = plugin.redact_and_truncate(&val, 2); // serialized starts with `"` then `€`
        assert!(out.ends_with("...[truncated]"));
    }

    // ----- built-in credential redaction independent of config -----

    #[test]
    fn redacts_builtin_credential_keys_without_operator_config() {
        // redact_fields defaults to empty; built-in keys must still redact.
        let input = serde_json::json!({
            "Authorization": "Bearer abc.def.ghijklmnop",
            "Cookie": "session=xyz",
            "x-api-key": "k-123",
            "city": "London",
            "nested": { "client_secret": "shh", "safe": "ok" }
        });
        let out = redact_fields(&input, &[]);
        assert_eq!(out["Authorization"], "[REDACTED]");
        assert_eq!(out["Cookie"], "[REDACTED]");
        assert_eq!(out["x-api-key"], "[REDACTED]");
        assert_eq!(out["city"], "London");
        assert_eq!(out["nested"]["client_secret"], "[REDACTED]");
        assert_eq!(out["nested"]["safe"], "ok");
    }

    #[test]
    fn redacts_credential_shaped_values_by_heuristic() {
        // A secret carried under an innocuous key (no redact_fields entry)
        // is caught by the value scan.
        let input = serde_json::json!({
            "header": "Bearer sk_live_0123456789",
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "jwt": "eyJhbGciOi.eyJzdWIiOi.signature1",
            "plain": "just a normal value"
        });
        let out = redact_fields(&input, &[]);
        assert_eq!(out["header"], "[REDACTED]");
        assert_eq!(out["aws"], "[REDACTED]");
        assert_eq!(out["jwt"], "[REDACTED]");
        assert_eq!(out["plain"], "just a normal value");
    }
}
