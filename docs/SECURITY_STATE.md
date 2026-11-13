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

## Conditions, revisits, crashes, and hypotheses

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

The hypothesis board deliberately separates ownership:

- The original mission lead opens a hypothesis and changes its priority.
- Contributors attach supporting evidence and counterevidence.
- An independent child with `read_only=true` and the `verdict` capability records a supported/refuted
  verdict with a note and evidence. Refutation requires counterevidence; every existing counterevidence
  ID must be acknowledged in a new verdict.
- New opposing evidence reopens a closed hypothesis and clears its current judge.

Actual runtime session capabilities enforce this division; the operation cannot declare its own
author role. Historical verdicts remain in the journal. Evidence references establish provenance,
while the independent judge remains responsible for interpreting their meaning.

## Causal rules and explanations

`fact_assert {fact:{predicate,args},evidence}` asserts ground string tuples. Variables begin with `?`
and are permitted only in rules. `rule_install {rule:{name,head,body}}` accepts body literals of the
form `{atom:{predicate,args},negated:false}`. Rules support finite, function-free, range-restricted
stratified Datalog, including positive recursion and negation-as-absence. Every head/negative variable
must occur in a positive body literal. Mixed predicate arities and recursion through negation are
rejected. There are no arithmetic expressions, aggregates, function symbols, or arbitrary code.

Automatic base predicates describe recorded `asset`, `credential`, `foothold`, `related`, and explicit
`condition` observations. These are historical observations; their presence is not a promise of
current credential/edge validity. Time-aware route suggestions and revisit queries use expiry fields
separately. Extracting a wrong base fact remains possible: deterministic derivation does not make an
observation true.

`security_query {view:"facts"}` returns the closure with `complete` and `limitation`. `why` takes a
ground `fact` and returns a deterministic explanation tree with base record IDs/evidence, rule IDs,
positive premises, and negative absence checks. Explanation depth is bounded at 128 and cut nodes
say `truncated:true`. Negation is never represented as an observed proof of nonexistence.

`fact_retract {id,reason}` and `rule_retract {id,reason}` preserve history and rebuild derived state.
`security.died` lists conclusions that disappeared after the latest retraction. Alternative support
keeps a conclusion alive. `what_if` accepts assumed ground facts and retracted base/rule IDs, returns
added/disappeared conclusions, and leaves the durable state byte-identical. The initial evaluator
recomputes a bounded closure; it does not claim Lemmalog's incremental DRed implementation or its
reported token savings. Limits are 128 active rules, eight literals/arguments, 10,000 facts, and
200,000 candidate joins. Exhaustion returns `complete:false`, never a complete negative result.

## Relations and path suggestions

`relation_add` takes `relation:{from,to,kind,cost,evidence,expires_ms?}`. Endpoints must be existing
assets. Costs are integers 1–1000. `path_suggest` takes asset IDs `from`/`to` and an explicit optional
`now_ms`; the tool defaults to current UTC time and reports the value it used. It returns at most
three simple paths with at most eight hops, excludes expired edges, and halves the cost of leaving
an asset with an unexpired recorded foothold, rounding up. Search is bounded at 10,000 expansions
and a 10,000-entry frontier. Paths are investigation hints over explicit observations, not validated
attack chains or guarantees of optimality on large graphs.

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
