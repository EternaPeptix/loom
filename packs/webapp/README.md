# The `webapp` pack: live bug-bounty & web AppSec

`webapp` is a domain pack designed for live authorized bug-bounty and web application security assessments. Unlike `ctf` and `redteam`, it requires **no local `.ferret/security-oracle.json`**, and natively integrates Ferret's HTTPS MITM capture, passive signal analyzer, multi-principal authorization replay (`http_authz_matrix`), OAST blind-callback broker (`oast_mint` / `oast_poll`), scoped read-only inbox (`inbox_read`), noise pacing, and `[box]` proxy bridge.

## Roles

| Role | Ends by | Writes / Exec | Spawns | Job |
|---|---|---|---|---|
| `lead` | `finish` (judge-gated) | yes | `recon_mapper`, `authz_tester`, `exploit_worker`, `triage_judge` | Owns the engagement, scope, delegation, structured `fn-*` findings, and coverage. |
| `recon_mapper` | `finish` / `hand_off` | yes (`max_steps = 25`) | none | Maps attack surfaces, ingests OpenAPI/GraphQL/JS-sourcemap artifacts, reviews passive MITM signals. |
| `authz_tester` | `finish` / `hand_off` | yes (`max_steps = 30`) | none | Multi-principal BOLA/IDOR/BFLA specialist using `http_authz_matrix` and `traffic_diff`. |
| `exploit_worker` | `finish` / `hand_off` | yes (`max_steps = 35`) | none | Active vulnerability reproduction, benign control checks, OAST blind-OOB verification, `inbox_read`, `[box]`. |
| `triage_judge` | `verdict` | no (`read_only = true`, `max_steps = 15`) | none | Strictly read-only verifier auditing scope, `security_query`, `traffic_query`/`traffic_diff`, and `out:` handles. |

## Running an assessment

```bash
ferret run --pack webapp --target <target> -w <workspace> "Assess authorized web scope …"
```

- **Restricted network & MITM capture:** `requires_restricted_network = true` and `intercept = true` are enabled by default; sessions refuse to start under `[network] mode = "open"`.
- **Multi-principal authz:** Mount named credential profiles (`user_a`, `user_b`, `admin`, etc.) so `http_authz_matrix`, `http_send`, and `http_repeat` inject credentials via proxy without exposing raw secrets to model context.
- **OAST & Mail (optional):** Configure `[oast]` for blind SSRF/XXE/XSS/SSTI callback verification and `[mail]` for read-only OTP/activation link verification via `inbox_read`.
- **Container bridge (optional):** Enable `[box] proxy_bridge = true` so `box_exec` tools inherit the mission egress proxy and MITM CA bundle.
