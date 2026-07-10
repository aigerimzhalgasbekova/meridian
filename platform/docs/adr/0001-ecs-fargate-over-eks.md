# ADR 0001 — ECS Fargate over EKS (and over EC2-backed ECS)

**Status:** accepted · 2026-07-10

## Context

Seven small HTTP services, one team, no existing Kubernetes investment. The
platform must be cheap to run continuously as a portfolio demo and honest
about what a mid-size company would actually pick for this workload.

## Decision

ECS on Fargate: one cluster, one task definition per service, Cloud Map for
service-to-service DNS, a single shared ALB with host-based routing.

## Rationale

- **No control plane to pay for or patch.** EKS is ~$73/mo before the first
  pod, plus node management or Fargate-on-EKS pricing anyway. For 7 stateless
  containers, Kubernetes buys nothing we use: no operators, no CRDs, no
  multi-team RBAC on the orchestrator itself.
- **Less YAML between the container and the load balancer.** Task definition +
  service + target group is the whole story, all in Terraform, one language.
  The K8s equivalent (Deployment/Service/Ingress + controller + IAM-for-SA)
  is three more moving parts to threat-model.
- **Fargate over EC2 launch type**: no AMI patching, no capacity planning,
  per-second billing, and the security win of no shared host we manage.
- **Exit cost is low.** Everything is a plain OCI image with 12-factor env
  config; moving to EKS later is re-plumbing, not re-architecting.

## Consequences

- No daemonsets/sidecar injection ecosystem — observability sidecars (X-Ray,
  ADOT) are opted into per task definition (`enable_xray` flag).
- Stateful oddities (keysmith's file keystore, sentinel's audit chain) ride
  EFS with `max_count = 1` instead of a StatefulSet; acceptable at this scale,
  and the real fix is service-level (shared-store backends), not orchestration.
- Scale-out is target-tracking on CPU only; anything fancier (per-endpoint
  concurrency, KEDA-style event scaling) would push toward EKS.
