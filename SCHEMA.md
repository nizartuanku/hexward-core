# Hexward Finding Schema (HFS) v1

One JSON object per finding transition, identical across every Hexward
product. Schema id: `hexward.finding/1`.

## Compatibility promise

Within version 1, fields are only ever **added**. A field is never renamed,
retyped or removed. Consumers must ignore fields they do not know. A breaking
change would ship as `hexward.finding/2`, and products would emit v1 until
you switch.

## Event

| Field | Type | Always present | Meaning |
| --- | --- | --- | --- |
| `schema` | string | yes | `hexward.finding/1` — key decoders and rules on this |
| `event` | string | yes | `opened` (new or reappeared), `resolved` (stopped appearing), `snapshot` (full export, not a transition) |
| `ts` | string | yes | Event time, RFC 3339, UTC |
| `product` | string | yes | Lower-case product id: `rulehawk`, `loglight`, `certlight`, … |
| `product_version` | string | no | Product version, e.g. `0.1.2` |
| `host` | string | no | Hostname of the emitting instance |
| `src_ip` | string | no | Present only when the finding's evidence holds a valid IP address (keys `source_ip`, `src_ip`, `src`, `actor`, `client_ip`, `ip`, in that order) |
| `finding` | object | yes | See below |

## Finding

| Field | Type | Always present | Meaning |
| --- | --- | --- | --- |
| `id` | string | no | Product-local finding id |
| `fingerprint` | string | yes | Stable identity of "this problem on this target" — dedupe on it |
| `check` | string | yes | Rule id, e.g. `rule.permissive`, `tls.expiry` |
| `title` | string | yes | One human line, never contains a newline |
| `target` | string | yes | What the finding is about, e.g. `example.com:443` |
| `severity` | string | yes | `critical`, `high`, `medium`, `low`, `info` |
| `severity_num` | int | yes | 0–10: critical 10, high 8, medium 5, low 3, info 1 |
| `status` | string | yes | `open`, `acknowledged`, `suppressed`, `resolved` |
| `remediation` | string | no | What to do, one line |
| `first_seen`, `last_seen`, `resolved_at` | string | no | RFC 3339, UTC |
| `group_id` | string | no | Tenant or client grouping (MSP use) |
| `evidence` | object | no | Redacted evidence (see below), or absent with `evidence=none` |

## Evidence redaction

Evidence leaves a product only after redaction:

- keys containing `password`, `passwd`, `passphrase`, `secret`, `token`,
  `apikey`, `api_key`, `api-key`, `private`, `credential`, `cookie`,
  `session`, `authorization`, `bearer`, `license_key`, `licence_key` or
  `signature` (case-insensitive) are **dropped**, at every nesting level;
- at most 24 keys per object, in sorted key order;
- strings are cut to 400 characters, lists to 12 items, nesting to 3 levels.

Set the product's evidence option to `none` to export no evidence at all;
`src_ip` is still populated so correlation keeps working.

## Example

```json
{"schema":"hexward.finding/1","event":"opened","ts":"2026-10-28T09:12:44Z","product":"rulehawk","product_version":"0.1.2","host":"fw-audit-01","src_ip":"203.0.113.7","finding":{"id":"f_8c1e","fingerprint":"3b9a0f1c","check":"rule.permissive","title":"Rule allows any source to RDP (3389)","target":"ftd-hq:ACP/rule 42","severity":"high","severity_num":8,"status":"open","remediation":"Restrict the source to the management VLAN. Put RDP behind an MFA VPN.","first_seen":"2026-10-28T09:12:44Z","last_seen":"2026-10-28T09:12:44Z","evidence":{"port":3389,"rule_index":42,"src_ip":"203.0.113.7"}}}
```

The byte-exact test vectors live in [`hfs/testdata`](hfs/testdata).

## Transports

| Transport | Shape |
| --- | --- |
| NDJSON file | One event per line |
| Syslog `json` | RFC 5424 (default) or 3164 header, APP-NAME `hexward`, MSG = the event JSON |
| Syslog `cef` | `CEF:0\|Hexward Labs\|<product>\|<version>\|<check>\|<title>\|<severity_num>\|rt=… act=… dvchost=… src=… externalId=… cs1=target cs2=fingerprint cs3=status cs4=severity cs5=schema msg=remediation` |
| Splunk HEC | `/services/collector/event`, sourcetype `hexward:finding`, source `hexward:<product>`, `event` = the HFS event |
| Webhook v2 | `{"version":2,"schema":"hexward.finding/1","events":[…]}`, header `X-Hexward-Token` |

Syslog severity follows the finding: critical → crit (2), high → err (3),
medium → warning (4), low → notice (5), info → info (6); `resolved` events
travel as notice (5). Facility defaults to local0.
