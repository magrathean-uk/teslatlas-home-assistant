# Security Review: teslatlas-home-assistant

## Scope

Offline Standard scan of Teslatlas Home Assistant integration at current HEAD.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_ecbfe603c7e50cfed3fd9814b149ee9245a27a450bd2f3e7d3c237183d782185
- Revision: fd45cf15556e628f78e1ece011e2e077cd578090
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: custom_components/teslatlas_hub, docs/architecture, docs/guides, .github/SECURITY.md, tests

Limitations and exclusions:
- No installed HA, Hub network, live pairing or interception test.
- Integration is unpublished/parked, and repo review is partial.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 1 |
| Severity mix | medium: 1 |
| Confidence mix | medium: 1 |
| Coverage | partial |
| Validation mode | static_source_trace |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Teslatlas Home Assistant is an operator-configured read-only consumer of Hub HTTP. It probes Hub discovery, claims a one-time pairing invitation, stores a scoped device credential in HA config entries, polls current vehicle data, rotates credentials and produces redacted diagnostics.

### Assets

- Pairing invitation secret and scoped device bearer
- Hub identity, endpoint, TLS leaf pin and HA config entry
- Private vehicle/current-state data displayed as sensors
- Diagnostics export and logs

### Trust Boundaries

- Operator-entered endpoint and optional TLS choice to network requests
- Public Hub discovery/identity to sending saved bearer or invitation secret
- TLS CA/hostname validation and optional leaf pin to actual request transport
- Issued bearer to durable HA config entry and polling client
- Hub responses to sensors, logs and diagnostics

### Attacker Capabilities

- Network observer or active on-path actor can intercept a configured plaintext endpoint
- Malicious endpoint can provide discovery and response JSON, subject to identity checks
- A person with HA config storage access may read saved credentials under HA permissions

### Security Objectives

- Never expose pairing or bearer credentials to unauthenticated transport/origin
- Bind saved credentials to expected Hub identity and TLS channel
- Reject redirects and oversized/invalid responses
- Persist rotated credentials before activating them
- Redact private fields in diagnostics

### Assumptions

- Offline static review; no HA runtime, Hub network, private lab or real credentials.
- TLS is default, but config permits HTTP; actual first-party Hub plaintext mode has distinct local-token semantics.
- App is parked/unpublished; runtime deployment not confirmed.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Disabling TLS sends Hub pairing secrets over plaintext HTTP](#finding-1) | medium | medium | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Disabling TLS sends Hub pairing secrets over plaintext HTTP

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | medium |
| Confidence rationale | Plaintext send path is explicit and repeatable in source; real deployment of HTTP or successful invitation redemption was not exercised. |
| Category | cleartext_credentials |
| CWE | CWE-319 |
| Affected lines | custom_components/teslatlas_hub/config_flow.py:320, custom_components/teslatlas_hub/current_hub_client.py:213, custom_components/teslatlas_hub/current_hub_client.py:447 |

#### Summary

The setup form permits a non-TLS endpoint and the client sends a one-time pairing secret to its HTTP URL after only a public Hub-ID probe. An active on-path actor could impersonate that plaintext probe and capture an invitation for redemption against the real TLS Hub. Existing HTTP-configured entries also transmit saved bearers in headers. This is conditional on an explicitly selected insecure endpoint; the first-party Hub does not normally pair over plaintext.

#### Root Cause

The UI and client allow credential-bearing flows when use_tls is false, and a public Hub ID is not an authenticated transport binding.

**choice** — `custom_components/teslatlas_hub/config_flow.py:77-85`

UI permits TLS to be disabled, although default is enabled.

```python
vol.Required(CONF_USE_TLS, default=defaults.get(CONF_USE_TLS, True)): BooleanSelector()
```

**accept** — `custom_components/teslatlas_hub/config_flow.py:315-327`

Chosen plaintext endpoint enters setup without fail-closed rejection.

```python
endpoint = HubEndpoint(... use_tls=user_input[CONF_USE_TLS], ...); result = await self._async_accept_endpoint(endpoint)
```

**scheme** — `custom_components/teslatlas_hub/current_hub_client.py:213-224`

Client constructs an HTTP origin when TLS is disabled.

```python
scheme = "https" if self.endpoint.use_tls else "http"
```

**send** — `custom_components/teslatlas_hub/current_hub_client.py:235-266`

Credential header or JSON body is sent to the selected origin.

```python
headers["Authorization"] = f"Bearer {self._bearer_token}"; self._session.request(... self._base_url + path, headers=headers, json=body, allow_redirects=False)
```

**claim** — `custom_components/teslatlas_hub/current_hub_client.py:435-450`

After public discovery identity check, one-time invitation secret is sent in the request body.

```python
info = await self.async_probe(); ... body={"secret": secret, "device_name": device_name}
```

#### Validation

Traced configuration choice through URL construction, public identity probe, claim body, bearer header and rotation.

Validation method: static_source_trace

**choice** — `custom_components/teslatlas_hub/config_flow.py:77-85`

UI permits TLS to be disabled, although default is enabled.

```python
vol.Required(CONF_USE_TLS, default=defaults.get(CONF_USE_TLS, True)): BooleanSelector()
```

**accept** — `custom_components/teslatlas_hub/config_flow.py:315-327`

Chosen plaintext endpoint enters setup without fail-closed rejection.

```python
endpoint = HubEndpoint(... use_tls=user_input[CONF_USE_TLS], ...); result = await self._async_accept_endpoint(endpoint)
```

**scheme** — `custom_components/teslatlas_hub/current_hub_client.py:213-224`

Client constructs an HTTP origin when TLS is disabled.

```python
scheme = "https" if self.endpoint.use_tls else "http"
```

**send** — `custom_components/teslatlas_hub/current_hub_client.py:235-266`

Credential header or JSON body is sent to the selected origin.

```python
headers["Authorization"] = f"Bearer {self._bearer_token}"; self._session.request(... self._base_url + path, headers=headers, json=body, allow_redirects=False)
```

**claim** — `custom_components/teslatlas_hub/current_hub_client.py:435-450`

After public discovery identity check, one-time invitation secret is sent in the request body.

```python
info = await self.async_probe(); ... body={"secret": secret, "device_name": device_name}
```

**rotate** — `custom_components/teslatlas_hub/current_hub_client.py:465-472`

An HTTP-configured existing entry would also send bearer during rotation.

```python
info = await self.async_probe(); ... self._async_json("POST", "/v1/device/rotate", authenticated=True)
```

Counterevidence and remaining uncertainty:
- TLS defaults on; pinned HTTPS verifies leaf on active connection and normal CA/hostname validation remains enabled.
- Redirects are disabled.
- First-party Hub disables pairing/device auth on its plaintext loopback route; exploitation relies on an insecure selected/proxied/spoofed endpoint.

Limitations:
- Static offline review; no real deployment or attacker interception verified.

#### Dataflow

The client builds an http:// URL and sends JSON/headers to it.

- **Source:** User-selected use_tls=false and pairing secret

- **Sink:** HTTP request body (or Authorization header for existing HTTP entries)

- **Outcome:** On-path observer can read credential material

**choice** — `custom_components/teslatlas_hub/config_flow.py:77-85`

UI permits TLS to be disabled, although default is enabled.

```python
vol.Required(CONF_USE_TLS, default=defaults.get(CONF_USE_TLS, True)): BooleanSelector()
```

**accept** — `custom_components/teslatlas_hub/config_flow.py:315-327`

Chosen plaintext endpoint enters setup without fail-closed rejection.

```python
endpoint = HubEndpoint(... use_tls=user_input[CONF_USE_TLS], ...); result = await self._async_accept_endpoint(endpoint)
```

**scheme** — `custom_components/teslatlas_hub/current_hub_client.py:213-224`

Client constructs an HTTP origin when TLS is disabled.

```python
scheme = "https" if self.endpoint.use_tls else "http"
```

**send** — `custom_components/teslatlas_hub/current_hub_client.py:235-266`

Credential header or JSON body is sent to the selected origin.

```python
headers["Authorization"] = f"Bearer {self._bearer_token}"; self._session.request(... self._base_url + path, headers=headers, json=body, allow_redirects=False)
```

**claim** — `custom_components/teslatlas_hub/current_hub_client.py:435-450`

After public discovery identity check, one-time invitation secret is sent in the request body.

```python
info = await self.async_probe(); ... body={"secret": secret, "device_name": device_name}
```

**rotate** — `custom_components/teslatlas_hub/current_hub_client.py:465-472`

An HTTP-configured existing entry would also send bearer during rotation.

```python
info = await self.async_probe(); ... self._async_json("POST", "/v1/device/rotate", authenticated=True)
```

#### Reachability

Public Hub-ID discovery can be replayed over an unauthenticated channel before the secret-bearing request.

- **Attacker:** Active on-path actor or controller of the selected plaintext endpoint

- **Entry point:** Operator-selected HTTP Hub setup endpoint

- **Outcome:** Disclosure and possible redemption of scoped pairing authority

Preconditions:
- User explicitly disables TLS and enters a valid unexpired Hub pairing invitation
- Attacker can intercept or impersonate that HTTP endpoint and can reach the real Hub TLS claim endpoint before invitation expiry

Limitations:
- Normal first-party Hub rejects remote plaintext pairing; no supported HTTP setup was demonstrated.
- No network interception or real invitation was used.

#### Severity

**Medium** — A stolen invitation can yield device-scoped vehicle read access, but the user must select nondefault HTTP and an on-path/endpoint attacker must intercept before expiry. Normal first-party Hub setup uses HTTPS.

Lower if plaintext mode is removed or proven unreachable in every supported workflow; raise if deployed HTTP proxies or existing saved HTTP entries are common.

#### Remediation

Require HTTPS for pairing, saved-bearer reads and rotation; reject or migrate existing HTTP entries before any credential send. Keep normal CA/hostname validation and optional leaf pinning. If a loopback-only development exception is retained, prohibit real invitation/bearer material on it.

Tests:
- With use_tls=false and any non-loopback host, assert pairing and authenticated requests fail before transport dispatch.
- Exercise an existing HTTP config entry and assert no saved bearer or invitation leaves the process.
- Retain HTTPS pin, redirect-rejection and identity-binding regression tests.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Packaging and HA lifecycle | Packaging and HA lifecycle | Needs follow-up | Source lifecycle sampled; installed HA runtime and current Hub integration unverified. |
| Endpoint and TLS admission | Endpoint and TLS admission | Reported | Conditional plaintext credential path; HTTPS pin and redirect controls reviewed. |
| Pairing and reauthentication | Pairing and reauthentication | Reported | One-time invitation sent after public identity probe; normal HTTPS path validates issued bearer before save. |
| Polling and rotation | Polling and rotation | No issue found | Concurrency/backoff and persist-before-use rotation reviewed; HTTP issue captured on endpoint surface. |
| Response parsing and diagnostics | Response parsing and diagnostics | No issue found | 10s/1MiB response bounds and diagnostics redaction reviewed. |

## Open Questions And Follow Up

- No installed HA runtime, network interception, or first-party/proxy deployment test; packaging and version compatibility not exhaustively reviewed.
  - Follow-up prompt: Review deferred unit ha-runtime-followup and close its stated proof gap. Paths: custom_components/teslatlas_hub, docs, tests.
