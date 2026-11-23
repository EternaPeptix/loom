# Durable security state

Security state is an additive projection of the sealed mission journal. Existing journals and ledger
snapshots remain readable. New `security` journal entries contain a typed `action`; an older Loom
build refuses to append after an unknown action rather than dropping it. No security observation
grants network scope, approves an action, or establishes a vulnerability by itself.

Packs opt into `security_record`, `security_query`, and `security_ingest`. Observation writes cite existing
attested mission evidence. These tools use the same sealed append and recorded-tool pipeline as the
other ledger tools. `security_query` never writes or executes a target. Planning, aliases, rule
installation, and retraction reasons do not themselves constitute observations.

## Assets, credentials, footholds, and coverage

`security_record` accepts one `operation` object:

```json
{"operation":{"action":"asset_upsert","asset":{"kind":"host","locator":"Example.TEST.","evidence":["e1"],"mandatory":true}}}
```

Its result names what the write changed, not the whole state: the journal `entry`, the touched records
in full under `recorded` (their ids and a count per collection when they are many), `removed` ids, the
size of each collection under `counts`, and where to read the rest (`security_query`).

Asset kinds are `host`, `service`, `endpoint`, `file`, and `identity`. Host/IP spelling and URL scheme,
host, and default port are canonicalized. URL paths, query strings, and identity/file locators retain
case. URL credentials are rejected. IDs are full SHA-256 hashes of length-delimited typed tuples, so
deduplication is deterministic across machines. Repeated observations merge their evidence; they
cannot change an asset's parent or downgrade mandatory coverage. A parent creates a `contains`
relation automatically. `alias_add {alias,target}` provides human-readable aliases. Tool inputs accept
exact aliases or unique prefixes of at least four characters; ambiguity is an error.

`credential_add` takes `credential` with `asset`, `principal`, `secret_handle`, `evidence`, optional
`unlocks` and `expires_ms`. `secret_handle` must resolve to an existing output blob and is recorded in
full canonical form. Passwords, private keys, and tokens do not belong in this field. `foothold_add`
takes `foothold` with `asset`, `principal`, `access`, `evidence`, optional `unlocks` and `expires_ms`.
Credentials and footholds are deduplicated, evidence-linked observations; they do not prove that a
login or operation will still work. Reobserving a record updates its expiry and merges evidence.

Every mandatory asset starts with `coverage.status=untested`. `coverage_set` requires an asset ID and
one of these dispositions:

```json
{"status":"tested","evidence":["e2"]}
{"status":"deferred","reason":"The required fixture is not available in this mission."}
{"status":"untested"}
```

Missing/unattested evidence and blank deferral reasons are rejected. `mandatory_open()` supplies the
finish gate with remaining asset IDs. Tested coverage records that an observation exists; it does
not mechanically establish exhaustive testing of the asset.

Every evidence record carries the grade the harness gave the output it quotes (`docs/DESIGN.md` §7):
`run`, `analysis` (`dep_scan`, `bin_decompile`, `bin_xrefs`), `read`, or `reference` (`cve_lookup`,
`cve_search`, `advisory_lookup`, a reference-host `web_fetch`). Security records cite evidence ids and
accept any attested grade. The goal-met conclusion, a verifier's objection and stuck detection accept
only a run, so a scanner verdict, a decompilation, an imported scan or an advisory can locate a lead
and support a claim, but cannot by itself show that the goal is met.

## How `security_record` reads near misses

Logged missions refused many `security_record` calls for shape rather than substance, so the tool reads
an operation where its meaning is unambiguous and says exactly what it did. Each rewrite is one
sentence under `normalized` in the result (`{"entry": n, "normalized": [...], "state": ...}`; the key is
absent when nothing was rewritten). What is read:

- `ops` or `items` for a batch's `operations`; a batch element is read on its own and a failing element
  is named, whichever check refuses it ("Operation 2 of 3 in the batch (asset_upsert): ..."). A batch stays one atomic append.
- Wrapper fields for `asset_upsert`, `credential_add`, `foothold_add`, `relation_add` given at the top
  level, `evidence` given beside the wrapper, `username`/`user` for `principal`.
- A host locator written with a scheme, port, path or credentials is recorded as the host. A service or
  endpoint locator without a scheme gets `https://` when its port is 443 and `http://` otherwise. A locator
  loses a leading HTTP method and any text after the URL, and a path is joined to the URL of its
  `parent` when the scheme, host and port stay the same. User information in a given value is never quoted back. A description after
  a relative path is cut like one after a URL, and `ftp:21`-style host names are not read as URLs.
- `ops` is read as `operations`. The asset in a `cred` or `auth` condition may be an alias or prefix; it is stored as
  the full asset ID.

What is refused, before anything is recorded and with the shape to send: an action that belongs to
another tool, an unknown action, a removed operation (`hypothesis_*`, `rule_*`: "Hypotheses are not recorded in the
security state any more: write the idea as a note (`note` with kind `decision`) or test it and record what
the run showed."), a condition that is not a typed `{kind, value}`, a
service or endpoint locator that is a bare path with no parent. Evidence must
still exist and be attested, authority is still checked by the tool and the core, and these records
never authorize network access. The tool description lists the exact shape of every action and differs

## Conditions, revisits, and crashes

`blocked_on {target,conditions}` associates an existing claim/dead-end ID with typed prerequisites:
each condition is `{kind,value}` where kind is `auth`, `cred`, `role`, `leak`, `offset`, or `key`.
`condition_unlock {conditions,evidence}` records explicit satisfaction. Credentials automatically
satisfy `cred:<asset ID>`; footholds satisfy `auth:<asset ID>`, in addition to their explicit unlocks.
`security_query {view:"revisit",now_ms:...}` excludes expired credential/foothold observations and
lists only routes whose entire prerequisite set is available. `revisit_acknowledge {target}` removes
a handled notification; setting `blocked_on` again makes the route eligible for another notification.
The pure `newly_unlocked()` API uses time zero; callers that need current validity use
`newly_unlocked_at(now_ms)`.

`crash_record` takes `signature` and `attempt`. A signature has a sanitizer class, one to three
`{function,file,line?}` frames, and outcome `crash`. Only frame zero's line participates in its ID;
caller lines do not. Timeout, OOM, no-crash, and libFuzzer exit-71 outcomes cannot be crash signatures.
Each signature keeps a total attempt count and its six most recent compact attempts. Attempts cite
attested evidence. This is structured signature deduplication, not a parser that trusts arbitrary
sanitizer prose or a determination that a crash matches the requested vulnerability.

Hypotheses and the rule engine are not part of the harness: the operations `hypothesis_open`,
`hypothesis_priority`, `hypothesis_evidence`, `hypothesis_verdict`, `rule_install` and `rule_retract` are
refused when new, and older journals that hold them still load (they change nothing when the state is
read). Deciding what is probably true and what follows from it is the model's work; the state keeps only
what was observed. `fact_assert {fact:{predicate,args},evidence}` records a ground string tuple with its
evidence and `fact_retract {id,reason}` deactivates it, keeping history. There is no derivation from facts,
no `why`, no `what_if` and no `path_suggest`.

## Relations

`relation_add` takes `relation:{from,to,kind,cost,evidence,expires_ms?}`. Endpoints must be existing
assets. Costs are integers 1–1000. Relations are explicit observations; nothing is searched over them.

## Scanner imports

`security_ingest {format,handle,evidence}` reads an existing observed `out:` blob. Evidence must cite
that exact blob, and the producer must be a mission observation, such as an executed command or read
file. Model prose, another agent's report, and runtime state playback are refused. Imports execute
no scanner, network request, or target code.

The supported input shapes are deliberately explicit:

| Format | Accepted shape |
| --- | --- |
| `nmap` | One `nmaprun` XML root; IPv4/IPv6 host addresses and open TCP/UDP/SCTP ports. The inert `<!DOCTYPE nmaprun>` declaration is accepted; external/entity-bearing DTDs are refused. |
| `nuclei` | JSONL objects with `matched-at` or `host`. |
| `ffuf` | JSON object with `results` array; every result has an absolute `url`. |
| `netexec` | JSON array, or `hosts`/`results` array, with `host`/`hostname`/`ip`, optional numeric `port` and documented `protocol`. Plain console output is unsupported. |
| `bloodhound` | JSON `data` array and supported `meta.type`; objects supply `Properties.name` or `ObjectIdentifier`. |

Imports are limited to 2 MiB and 500 canonical assets. Required-field, parse, or validation errors
reject the entire import. A single atomic sealed batch makes assets and their containing-host
relationships durable. Scanner severity, credentials, group membership, and exploitability claims
are not imported as verified facts. Unsupported scanner versions/formats fail visibly rather than
guessing their meaning.
