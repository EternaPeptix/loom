# Redteam pack

Opt-in roles for explicitly authorized, scope-restricted lab engagements. The commander has zero
direct execution starts. Recon/tactical roles have 25/30-step slices; the lateral role additionally
requires explicit `asset` and `credential` assignment fields. Runtime checks their canonical IDs,
correspondence and credential expiry before starting a child. Discovery never grants network scope.

Install/configure this pack as described for [ctf](../ctf/README.md), using `redteam` / `commander`.
Provide Rules of Engagement, target scope, rate/lockout/data constraints and an operator-pinned
acceptance contract. No credential spraying, target discovery, guest provisioning, tunnel staging,
exfiltration or remote deployment happens merely by loading the pack.

Use typed asset/credential/foothold records, coverage dispositions and blocked/unlocked conditions.
`security_query` path suggestions are bounded investigation hints over explicit evidence-linked
relations, not validated exploit chains. A credential record holds a secret output handle; it is not
an authorization grant or proof that the credential works. Read the underlying evidence before use.
Scanner imports do not promote findings into vulnerabilities or infer exploitable BloodHound ACLs.

The independent `op_judge` checks operator-contract receipts, controls and scope before acceptance.
Privilege claims require a trusted signed supervisor that measures the actual target session/effect;
PTY UID strings and the supervisor's own UID are insufficient. Every mandatory surface is tested with
execution evidence or explicitly deferred. Structured verdict disqualifiers mechanically override an
accepting model. Blockers/budget exhaustion preserve partial results without asserting success.

Linux subprocess networking is currently deny-all; structured HTTP uses explicit scoped proxy
grants. A secure interactive SSH/TCP bridge is a deployment integration that remains unsupported by
Bubblewrap mode. Do not enable mode `none` to obtain a claimed verified result. Configure named
solver/judge profiles explicitly when using heterogeneous review.
