# hexward-core

Shared building blocks for [Hexward Labs](https://hexwardlabs.com) security
tools. Today it holds one thing: the **Hexward Finding Schema (HFS)** and the
sinks that deliver it to the systems you already run.

Every Hexward product (RuleHawk, Loglight, CertLight, Decoy, DmarcWatch,
Patchlight, TenantWatch, Attack Surface Monitor, AuditLight, TopoLight) emits the same event for
every finding it opens or resolves. Write a Wazuh rule, a Splunk search or an
Elastic query once, and it works for all of them.

- **Schema:** [`SCHEMA.md`](SCHEMA.md), `hexward.finding/1`, additive-only.
- **Package `hfs`:** build and encode events; evidence is redacted before it
  ever leaves a product.
- **Package `sink`:** NDJSON file, syslog (JSON or CEF, RFC 5424 or 3164,
  UDP, TCP or TLS), Splunk HTTP Event Collector, and webhook v2.

Ready-made integration packs:

- Wazuh: [nizartuanku/hexward-wazuh](https://github.com/nizartuanku/hexward-wazuh)
- Splunk: [nizartuanku/TA-hexward](https://github.com/nizartuanku/TA-hexward)

## Use

```go
import (
	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"
)

ev := hfs.New(hfs.KindOpened,
	hfs.Meta{Product: "rulehawk", Version: "0.1.2", Host: host},
	hfs.Source{Fingerprint: fp, Check: "rule.permissive", Title: title,
		Target: target, Severity: "high", Remediation: fix, Evidence: ev},
	time.Now(), hfs.Options{})

s := &sink.File{Path: "/var/log/hexward/rulehawk.ndjson"}
err := s.Send(ctx, []hfs.Event{ev})
```

## Guarantees

- Secret-like evidence keys (`password`, `token`, `secret`, `session`, …) are
  dropped, not masked, at every nesting level. Evidence can be switched off
  entirely.
- TLS verification is never disabled. Point the sink at a private CA with a
  CA file instead.
- Encoded events are single-line and deterministic; the byte-exact test
  vectors are in [`hfs/testdata`](hfs/testdata).
- No third-party dependencies.

## License

Apache-2.0. © Nizar Tuanku — Cybersecurity.
