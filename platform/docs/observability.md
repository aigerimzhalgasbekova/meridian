# Observability

## What exists today

Every service logs structured JSON to stdout/stderr via Go's `log/slog`
(portal: plain console logging). No service emits metrics or traces — that is
deliberate; see the upgrade path below before retrofitting anything.

### Logs

`awslogs` driver → one CloudWatch log group per service
(`/ecs/meridian-dev-<service>`, 30-day retention). slog's JSON output is
directly queryable with CloudWatch Logs Insights, e.g. keysmith's key
lifecycle audit trail:

```
fields @timestamp, op, key_id, alg
| filter component = "keystore-audit"
| sort @timestamp desc
```

### Metrics (infrastructure-derived, zero code)

The `observability` module builds everything from ALB and ECS metrics, so
services need no instrumentation:

- **Dashboard** `meridian-dev`: per exposed service p99 `TargetResponseTime` +
  5xx count; per service ECS CPU.
- **Alarms → SNS** (email subscription optional):
  - `HealthyHostCount` < 1 for 3 min (per exposed service) — the down-detector.
    Every other alarm below watches a metric that only exists while a task is
    registered and treats missing data as OK, so a service at zero tasks would
    otherwise be silent. This is the one alarm with
    `treat_missing_data = "breaching"`, which is why `scripts/pause.sh`
    disables just these for the duration of a pause and `resume.sh` re-arms them.
  - 5xx from targets ≥ 10 / 5 min (per exposed service)
  - `UnHealthyHostCount` ≥ 1 for 3 min
  - p99 latency > 1.5 s over 2×5 min
  - ECS CPU > 85% sustained 15 min (all seven services — the autoscaling
    ceiling signal)
- **Container Insights** is enabled on the cluster for task-level
  memory/CPU/network without code changes.

This covers the questions a pager actually asks (is it up, is it slow, is it
erroring) without touching a single service.

## X-Ray (wired, dormant)

The service module has an `enable_xray` flag: it adds the X-Ray daemon
sidecar (UDP 2000) and `AWSXRayDaemonWriteAccess` on the task role. It is
**off everywhere** because no service emits segments — turning it on today
would ship a sidecar that receives nothing. Flip it per service in
`envs/dev/main.tf` the moment that service is instrumented.

## Upgrade path: OTel per service

Do not hand-roll X-Ray SDK calls; instrument with OpenTelemetry and let the
collector translate. Per service:

1. **Go services (keysmith, idp, sessiond, sentinel, bridge, console)** —
   wrap the root handler with `otelhttp.NewHandler(srv.Handler(), name)` and
   the outbound clients (idp→keysmith is the one hop that matters today) with
   `otelhttp.NewTransport`. Configure via standard `OTEL_EXPORTER_OTLP_*` env
   vars — no new flags in the services.
2. **portal (TS)** — `@opentelemetry/auto-instrumentations-node` via
   `NODE_OPTIONS=--require @opentelemetry/auto-instrumentations-node/register`;
   Express and `pg` are auto-instrumented.
3. **Collector** — swap the X-Ray daemon sidecar for the ADOT collector image
   (`public.ecr.aws/aws-observability/aws-otel-collector`) in the service
   module; it accepts OTLP and exports traces to X-Ray and metrics to
   CloudWatch EMF. That is a one-place change (the `xray_container` local).
4. **Order of adoption** — idp first (it owns the only multi-service request
   path: browser → idp → keysmith), then portal (queue latency), then the rest
   as needed. Instrumenting all seven up front is effort without a consumer.

Log correlation comes along for free once traces exist: put the OTel trace ID
into slog via a small `slog.Handler` wrapper, then Logs Insights joins logs to
traces on `trace_id`.
