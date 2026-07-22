# Prewise Production Security & Resilience Plan

**Assessment date:** 2026-07-23  
**Scope:** `prewise.site`, `api.prewise.site`, web, FastAPI, MCP, PostgreSQL,
ClamAV, AI adapters, Cloudflare Tunnel, and the current GitHub Codespaces demo.

## 1. Executive conclusion

The current deployment is a strong **release/demo environment**, but it is not
yet a highly available production service.  It has useful production controls
inside the repository and at the Cloudflare edge, while the live origin is still
one 2-vCPU/8-GB Codespace with one backend process, one PostgreSQL container,
one Tunnel connector, and an inactivity timeout.

Use this exact claim in a review:

> Prewise currently protects the public edge with Cloudflare's automatic DDoS
> mitigation and an outbound-only Tunnel, then applies request-size limits,
> authentication, quotas, malware scanning, security headers, and an
> application rate-limit backstop.  The demo has passed a bounded concurrency
> probe with no errors.  It is not represented as highly available until the
> origin, database, rate limiter, backups, and monitoring meet the production
> acceptance gates in this document.

## 2. Current architecture and trust boundaries

```text
Internet
   |
Cloudflare DNS / CDN / DDoS / Free WAF
   |
Named Cloudflare Tunnel (no public origin IP)
   |
Nginx API gateway :8000     Next.js :3000
   |                             |
FastAPI :8000  -------- PostgreSQL 16
   |             |          |
MCP :3001     ClamAV      persistent volume
   |
configured AI / reputation adapters (outbound only)
```

Existing controls confirmed in the repository:

- Production configuration fails closed for unsafe secrets and SQLite.
- PostgreSQL is isolated on an internal Docker network and uses SCRAM auth.
- Alembic runs only after a custom-format database dump succeeds.
- Backend, web, MCP, and gateway containers are read-only where practical,
  use `no-new-privileges`, and use bounded `tmpfs` mounts.
- Backend upload middleware rejects oversized request bodies before parsing.
- ClamAV is private and attachment analysis has explicit time budgets.
- HSTS, frame denial, MIME sniffing protection, permissions policy, and
  no-store headers are set in production.
- API keys and sessions are stored as hashes; quota consumption is atomic.
- CORS is restricted to the Prewise web origins in production.
- API documentation is disabled in production.
- Containers use health checks and `restart: unless-stopped`.

## 3. Measured baseline (demo environment only)

The bounded probe is reproducible with `scripts/load_probe.py`.  It deliberately
caps itself at 500 requests and 25 concurrent requests and requires
`--allow-public` for a non-loopback target.

Results from the public Cloudflare path on 2026-07-23:

| Target | Requests / concurrency | Errors | Throughput | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|---:|
| `https://prewise.site/` | 100 / 10 | 0 | 90.81 req/s | 79.61 ms | 310.66 ms | 349.61 ms |
| `/v1/health` | 100 / 10 | 0 | 88.57 req/s | 84.74 ms | 341.85 ms | 379.92 ms |
| `/v1/ready` | 20 / 4 | 0 | 35.84 req/s | 76.11 ms | 223.09 ms | 227.77 ms |

These numbers prove only a short, lightweight burst from one network location.
They do **not** prove sustained scan throughput, multi-region performance, AI
capacity, database write capacity, or DDoS capacity.  Expensive URL, file,
browser-sandbox, OCR, LLM, and cloud-sandbox paths require separate workload
profiles and must be tested only against staging.

## 4. Current production-readiness scorecard

| Area | State | Evidence / gap |
|---|---|---|
| Volumetric DDoS | Partial pass | Cloudflare provides automatic unmetered L3-L7 DDoS protection on all plans. Origin IP is hidden by Tunnel. |
| WAF | Partial pass | Free Managed Ruleset is available and normally deployed by default; export/dashboard evidence must be retained for each release. |
| Edge rate limiting | Gap | Free plan permits one rate-limiting rule with restricted fields and 10-second periods. A rule for `/v1/` must be created and tested. |
| Application rate limiting | Partial | 60 requests/minute backstop exists, but counters are in one process and are not shared across replicas. Proxy-aware client identity also needs an acceptance test. |
| Payload exhaustion | Partial pass | FastAPI has endpoint-specific limits. Nginx body limits and slow-client timeouts need explicit tests for every upload route. |
| Origin isolation | Pass | Named Tunnel; public services bind to loopback at the host edge. |
| Runtime hardening | Pass for MVP | Non-root backend image, read-only containers, private networks, bounded tmpfs, no-new-privileges. |
| High availability | Fail | One Codespace, one API process, one DB, one connector, one region. |
| Database durability | Partial | Persistent volume and pre-migration dump exist; no managed HA, PITR, or automated off-host restore drill. |
| Backpressure | Partial | Timeouts, quotas and some worker bounds exist; no shared queue/circuit breaker for every expensive adapter. |
| Observability | Gap | Health endpoints exist; no external SLO monitor, centralized structured logs, metrics dashboard, or paging. |
| Disaster recovery | Gap | Design targets exist; automated off-host backups and measured restore time are not yet demonstrated. |
| Capacity evidence | Partial | Lightweight bounded baseline exists; no sustained or expensive-workload staging test. |

## 5. Threat model and required controls

| Threat | Edge control | Origin/application control | Required verification |
|---|---|---|---|
| L3/L4 flood | Cloudflare automatic DDoS | Origin reachable only through Tunnel | Confirm no public origin address/port; test from an external network. |
| HTTP request flood | Cloudflare HTTP DDoS + rate rule | Per-user quota, per-IP limiter, connection/time budgets | 429 behavior, legitimate NAT clients, IPv6, and bypass attempts. |
| Credential stuffing | WAF/custom rule, Turnstile on abuse | Per-account and per-IP login limits, generic errors, session revocation | Failed-login burst and account-enumeration tests. |
| Expensive scan abuse | Path-specific edge limit | Auth scope, daily quota, concurrency semaphore, queue, hard timeout | Saturate each workload class in staging and verify fast rejection. |
| Slowloris / slow upload | Cloudflare edge | Header/body/send timeout and connection caps at gateway | Slow-client test without consuming all workers. |
| Oversized/decompression bomb | Request body inspection | Endpoint byte caps, archive expansion cap, MIME/magic validation, ClamAV | Boundary tests at limit, limit+1, chunked transfer, malformed multipart. |
| Database exhaustion | Edge/app limits | Bounded SQLAlchemy pool, PgBouncer, statement timeout | Pool saturation test and recovery after rejected load. |
| Adapter/LLM outage | Cache and optional edge failover | Circuit breaker, bounded retries, timeout, degraded response | Inject timeout/429/5xx and confirm no cascading failure. |
| Malicious file execution | None | Private ClamAV, non-executable temporary storage, isolated sandbox workers | EICAR and safe malformed-file fixtures; never execute on API host. |
| Secret theft | Cloudflare/GitHub secret stores | No secrets in image/log/DB plaintext; rotation | Secret scan, rotation drill, revoked-key test. |
| Operator or supply-chain error | WAF managed updates | Pinned images/dependencies, CI gates, SBOM, signed release | Dependency scan and rollback exercise. |

## 6. Target production topology

```text
Cloudflare DNS/CDN/DDoS/WAF/Rate Limit/Turnstile
                  |
       two or more Tunnel connectors
                  |
        regional load balancer/gateway
          |                     |
     API replica A         API replica B
          |                     |
          +--- shared queue ----+
                     |
        isolated scan / AI workers
                     |
 Managed PostgreSQL HA + PITR + PgBouncer
                     |
    object storage for encrypted artifacts/backups
```

Requirements:

1. At least two API replicas and two Tunnel connectors on separate failure
   domains. Background schedulers run as singleton jobs, not in every replica.
2. Managed PostgreSQL with TLS verification, automated PITR, a private network,
   and a connection pool sized across all replicas.
3. Redis or an equivalent shared store for distributed rate limits, idempotency,
   short-lived cache, and queue coordination.
4. CPU-heavy OCR/browser/file/LLM work leaves the request process and runs in a
   bounded queue with per-tenant concurrency limits.
5. Static assets are cached at the edge; authenticated/API responses remain
   `no-store` unless an explicit privacy-reviewed cache key exists.
6. External probes, metrics, centralized logs, traces, alerts, and an incident
   owner exist before accepting paid production traffic.

## 7. Proposed SLO and recovery objectives

Initial paid-production targets:

- Availability: **99.9% per calendar month** for web and core API.
- Lightweight/cached API latency: **p95 <= 750 ms**, **p99 <= 1.5 s**.
- Standard local-model scan latency: define per modality from staging data;
  long-running sandbox/LLM work must return an accepted job quickly and expose
  progress rather than holding an HTTP worker indefinitely.
- Server error rate: **< 1%** over five minutes, excluding correctly rejected
  4xx requests.
- RPO: **<= 15 minutes**. RTO: **<= 60 minutes**.
- Alerting: page on 5-minute availability breach, error-budget burn, DB pool
  exhaustion, queue age, backup failure, Tunnel disconnect, and adapter outage.

## 8. Cloudflare minimum policy

Cloudflare documents automatic, unmetered DDoS protection at layers 3-7 for all
plans:
<https://developers.cloudflare.com/ddos-protection/about/>.

The Free Managed Ruleset is available on all plans:
<https://developers.cloudflare.com/waf/managed-rules/>.

The Free plan currently supports one rate-limiting rule, with a 10-second
counting period and restricted matching fields:
<https://developers.cloudflare.com/waf/rate-limiting-rules/>.

Minimum configuration for the demo/free plan:

- Keep DNS records proxied and route origins only through the named Tunnel.
- Verify the Free Managed Ruleset is deployed.
- Use the single rate rule for dynamic `/v1/` traffic, starting in log/challenge
  mode when possible, observing false positives before blocking.
- Exclude verified bots only where appropriate; never exempt arbitrary user
  agents or query parameters.
- Add Turnstile to registration, password reset, and repeated failed login after
  server-side verification is implemented.
- Record screenshots/exports of DNS, Tunnel health, WAF rules, and security
  events as release evidence.

Do not claim that Cloudflare makes the origin infinitely scalable.  It absorbs
and filters attacks at the edge; cache misses and allowed expensive requests can
still exhaust a single origin.

## 9. Load and resilience test program

Run only against a staging environment with representative data and isolated
adapter accounts.

1. **Smoke:** 20 requests, concurrency 1-4; all status/schema checks pass.
2. **Ramp:** 5 minutes each at concurrency 5, 10, 25, 50; record p50/p95/p99,
   RPS, CPU, RAM, DB pool, queue depth, and adapter calls.
3. **Sustained:** expected peak traffic for 60 minutes; no memory growth and no
   error-budget breach.
4. **Spike:** 5x expected peak for 60 seconds; overload returns 429/503 quickly,
   not timeouts, and recovery occurs within two minutes.
5. **Soak:** normal peak for 6-12 hours; validate retention jobs and connection
   recycling.
6. **Failure injection:** stop one API replica, one Tunnel connector, one adapter,
   and a DB connection; verify graceful degradation and alerts.
7. **Restore drill:** restore the latest backup into a clean staging database,
   run migrations and release gates, and record measured RPO/RTO.

Test each workload separately: static web, health/readiness, cached URL scan,
uncached URL scan, text/prompt, file/ClamAV/OCR, browser sandbox, MCP stream,
and LLM/adapter calls. Never infer expensive-path capacity from `/v1/health`.

## 10. Production acceptance gates

The service may be described as production-ready only when all gates pass:

- [ ] Origin is not directly reachable; two healthy Tunnel connectors exist.
- [ ] WAF and edge rate-limit configuration is versioned or exported and tested.
- [ ] Real client identity is preserved through Cloudflare/gateway without
      trusting spoofable headers from untrusted peers.
- [ ] Rate limits are distributed across API replicas and separated by endpoint
      cost, account, API key, and IP.
- [ ] At least two stateless API replicas pass failover tests.
- [ ] Managed PostgreSQL HA/PITR is enabled and a restore drill meets RPO/RTO.
- [ ] Expensive work uses bounded queues, concurrency limits, and circuit breakers.
- [ ] External uptime, metrics, logs, traces, alerts, and on-call ownership exist.
- [ ] SAST, dependency scan, secret scan, container scan, SBOM, migrations,
      integration tests, and production readiness run in CI.
- [ ] The staging ramp, sustained, spike, soak, failure, and restore tests pass.
- [ ] Incident response, rollback, secret rotation, and data-retention runbooks
      have named owners and have been exercised.
- [ ] Codespaces is no longer the production origin.

## 11. Honest answers for a security review

**Can Prewise resist DDoS?**  
The public edge is protected by Cloudflare's automatic L3-L7 DDoS mitigation and
the origin is hidden behind a named Tunnel. Application-layer abuse is further
bounded by quotas, request-size limits and rate limiting. The current demo still
has a single origin, so edge protection does not equal high availability.

**How much load can it handle?**  
The current demo passed a bounded 100-request, concurrency-10 probe at about
89-91 lightweight requests/second with zero errors. This is a baseline, not a
capacity promise. Production capacity will be published only after representative
staging ramp, sustained, spike, and soak tests.

**What happens if a server fails?**  
Containers restart on process failure, but the current Codespace is one host.
The production target uses multiple API replicas and Tunnel connectors plus a
managed HA database, and must pass a failover drill.

**Will data be lost?**  
The current stack performs a PostgreSQL dump before migrations and keeps a
persistent volume. Production requires off-host encrypted backups, PITR, and a
measured restore drill meeting RPO 15 minutes and RTO 60 minutes.

**Why not claim production now?**  
Security controls are already meaningful, but production is an operational
property demonstrated by redundancy, monitoring, load evidence, recovery tests,
and accountable incident response—not only by application code.
