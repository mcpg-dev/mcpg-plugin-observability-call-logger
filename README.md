# Call Logger — `dev.mcpg.call-logger`

> class `tool_gate` · `native` · package `mcpg-plugin-observability-call-logger` · artifact `libmcpg_plugin_observability_call_logger.so` · Apache-2.0

Structured per-call logging for an MCP gateway. The plugin sits in the tool-gate
chain and emits a `tool_call_start` entry before dispatch and a `tool_call_end`
entry after it, each carrying the request id, tool name, caller identity, and —
when you opt in — the redacted, size-capped argument and result payloads. It
always returns `Allow`, so it observes traffic without ever shaping it. Reach
for it when you are debugging what a client actually sends and what a backend
actually returns, and you want that visible in your existing log pipeline
rather than in a separate audit store.

## What it does
- Emits two `tracing` events per call — `tool_call_start` (request id, tool,
  transport, identity kind / subject / trust level, arguments) and
  `tool_call_end` (request id, tool, duration, result).
- Always returns `Allow`; a payload that cannot be rendered never turns into a
  denial.
- Samples with `sample_rate`. The draw is made independently for each phase, so
  a rate below `1.0` can log a call's start without its end; use `1.0` when you
  need both halves of every entry.
- Redacts before it serialises, and truncates on a UTF-8 character boundary so
  a multi-byte payload cannot corrupt a log line.
- Records `mcpg_call_logger_emits_total` through the `metrics` crate, labelled
  by `phase` (`pre` / `post`) and `outcome` (`emitted` / `sampled_out`), so
  sampling can be accounted for rather than guessed at.
- Declares no required capabilities — it writes to the process's `tracing`
  subscriber and opens nothing.

## Configuration
Loaded from the flat top-level `plugins:` list. Its output goes wherever the
gateway's `observability.logs.sinks[]` already points; the plugin has no sink
configuration of its own.

```yaml
plugins:
  - id: dev.mcpg.call-logger
    kind: native
    class: tool_gate
    source:
      path: ./plugins/libmcpg_plugin_observability_call_logger.so
    config:
      sample_rate: 1.0
      log_arguments: true
      log_results: true
      max_argument_bytes: 4096
      max_result_bytes: 8192
      redact_fields: ["ssn", "date_of_birth"]
```

| Field | Type | Default | Description |
|---|---|---|---|
| `sample_rate` | float | `1.0` | Fraction of calls logged. `>= 1.0` always logs, `<= 0.0` never logs, values in between draw per phase. |
| `log_arguments` | bool | `true` | Include the redacted, truncated argument object in `tool_call_start`. |
| `log_results` | bool | `true` | Include the redacted, truncated result object in `tool_call_end`. |
| `max_argument_bytes` | integer | `4096` | Byte cap for the serialised arguments; longer values are cut on a character boundary and suffixed `...[truncated]`. |
| `max_result_bytes` | integer | `8192` | Byte cap for the serialised result, same truncation rule. |
| `redact_fields` | string[] | `[]` | Extra field names to redact, matched case-insensitively. Additive to the built-in list. |

Unknown fields are rejected. A `config:` block that is present but does not
parse refuses the plugin at boot rather than silently reverting to defaults; an
absent or empty block yields the defaults above.

## Security
Enabling `log_arguments` or `log_results` puts request and response payloads
into your log stream. The plugin logs a warning at construction — carrying both
flags and the sampling rate — to make that explicit, and increments
`mcpg_call_logger_beta_warning_total`. Secure the log sink accordingly, and
prefer `libs/plugins/observability/audit` when you need a tamper-evident record
rather than debug output.

Redaction runs on three independent layers, and the last two apply even when
`redact_fields` is empty:

- **Operator field names.** Any key you list in `redact_fields`, at any depth.
- **Built-in credential keys.** `authorization`, `proxy-authorization`,
  `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `api_key`, `api-key`,
  `apikey`, `password`, `secret`, `token`, `access_token`, `refresh_token`,
  `client_secret`.
- **Value shape.** A string value is redacted when it starts with a `Bearer` /
  `Basic` / `DPoP` scheme, carries a known key prefix (`sk_`, `pk_`, `AKIA`,
  `AIza`, `ya29.`, `ghp_`, `xoxb-`, `xoxp-`), contains a PEM private-key
  header, or is shaped like a three-segment JWT. Strings the shape check does
  not flag are kept, with any URL userinfo stripped out of them.

Redacted leaves are replaced with the literal `[REDACTED]`. Redaction happens
before truncation, so a secret can never survive by sitting past the byte cap.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; naming the feature explicitly keeps the command
unambiguous:

```bash
cargo build -p mcpg-plugin-observability-call-logger --features cdylib-export --release   # → target/release/libmcpg_plugin_observability_call_logger.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the loading contract: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Where gateway log output goes: <https://mcpg.dev/docs/reference/configuration>
- Compliance-grade call records instead of debug logs: `libs/plugins/observability/audit`
- Shipping the resulting log stream to a collector: `libs/plugins/observability/syslog`
