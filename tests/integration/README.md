# Integration harness

Deterministic local services used by the Gluetun control plane integration
tests. Everything runs offline once the image is built: no public DNS, no
external IP echo and no real VPN provider.

## Services

| Service | Purpose | Default answer |
|---|---|---|
| `plain` | Plain DNS on port 53 (UDP and TCP) | A `198.51.100.53` |
| `dot` | DNS over TLS on port 853, self-signed CA written to `/certs` | A `198.51.100.53` |
| `echo-a` | HTTP egress source | IP `203.0.113.10` |
| `echo-b` | HTTP egress source | IP `203.0.113.11` |
| `echo-c` | HTTP egress source | IP `203.0.113.12` |
| `echo-failing` | Negative egress source, `/ip` and `/canary` return 503 | IP `203.0.113.99` |
| `vpn-wg-test` | WireGuard endpoint, writes a client config to `/shared/wg0.conf` | IP `203.0.113.20` |
| `check` | One-shot verification of every service above | exits 0 or 1 |

The DNS servers answer `A` records for any name and return `SERVFAIL` for
`servfail.test.` and `REFUSED` for `refused.test.` The echo endpoints expose:

- `GET /ip` → `{"source":"echo-a","ip":"203.0.113.10","remote":"..."}`
- `GET /canary` → `200` with `ok`
- `GET /status/<code>` → the requested status code
- `GET /delay/<ms>` → sleeps then `200`
- `GET /healthz` → `200`

## Usage

```sh
docker compose -f tests/integration/docker-compose.yml up -d --build
docker compose -f tests/integration/docker-compose.yml logs check
docker compose -f tests/integration/docker-compose.yml down -v
```

`check` validates plain DNS, DoT (with the generated CA), the `SERVFAIL`
injection, the three healthy echoes, the WireGuard client configuration, a
real WireGuard tunnel (a userspace client connects and fetches `/ip` through
`10.66.0.1`) and the WireGuard echo. The stack is ready when `check` logs
`check: all harness services are ready`.

## Fault injection

```sh
# DoT tier down
docker compose -f tests/integration/docker-compose.yml stop dot

# Plain DNS tier returns SERVFAIL instead
docker compose -f tests/integration/docker-compose.yml run --rm \
  --no-deps plain dns -mode=plain -listen=0.0.0.0:53 -fail
```

Router rollback, DNS fallback and transport ladder tests can therefore run
without Internet access and without touching a real provider.
