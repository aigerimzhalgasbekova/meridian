#!/usr/bin/env bash
# Resume the dev stack after pause.sh: start RDS, wait for it, then scale
# every service back to 1 (and restore the autoscaling floor).
set -euo pipefail
CLUSTER=meridian-dev
SERVICES=(idp keysmith sessiond sentinel bridge portal console)

aws rds start-db-instance --db-instance-identifier meridian-dev-postgres --query 'DBInstance.DBInstanceStatus' --output text || true
echo "waiting for RDS to become available (~3-5 min)..."
aws rds wait db-instance-available --db-instance-identifier meridian-dev-postgres

for s in "${SERVICES[@]}"; do
  aws application-autoscaling register-scalable-target --service-namespace ecs \
    --resource-id "service/$CLUSTER/$s" --scalable-dimension ecs:service:DesiredCount \
    --min-capacity 1 >/dev/null
  aws ecs update-service --cluster "$CLUSTER" --service "$s" --desired-count 1 --query 'service.serviceName' --output text
done

# Re-arm the down-detectors pause.sh silenced. Wait for stability first so the
# warm-up does not page; `|| true` because a stack that never stabilises is
# precisely when those alarms need to be back on.
echo "waiting for services to stabilise before re-arming down alarms..."
aws ecs wait services-stable --cluster "$CLUSTER" --services "${SERVICES[@]}" || true

# Discovery happens HERE, not at the top: bringing a paused stack back must
# never be blocked by a CloudWatch read. Same discovery as pause.sh — the set
# follows terraform, not this script — and the same stdout-only capture, so an
# expired token is not reported as "no alarms exist" and a warning on aws's
# stderr never becomes an alarm name.
if ! found=$(aws cloudwatch describe-alarms --alarm-name-prefix "$CLUSTER-" \
  --query 'MetricAlarms[?ends_with(AlarmName, `-no-healthy-hosts`)].AlarmName' --output text); then
  echo "stack is UP but describe-alarms failed (credentials? IAM? see the error above)" >&2
  echo "down alarms are still silenced — re-run resume.sh once the API works." >&2
  exit 1
fi
read -r -a DOWN_ALARMS <<<"$found"
[ ${#DOWN_ALARMS[@]} -gt 0 ] || {
  echo "stack is UP but no $CLUSTER-*-no-healthy-hosts alarms found; is observability applied?" >&2
  exit 1
}

aws cloudwatch enable-alarm-actions --alarm-names "${DOWN_ALARMS[@]}"

# CloudWatch invokes an alarm action only on a state TRANSITION. After a pause
# these are already sitting in ALARM, so re-arming them notifies nobody if the
# stack did not come back — the exact case they exist for. Bounce the state so
# CloudWatch re-evaluates and re-enters ALARM (firing the action) if still down.
for a in "${DOWN_ALARMS[@]}"; do
  aws cloudwatch set-alarm-state --alarm-name "$a" \
    --state-value INSUFFICIENT_DATA --state-reason "resume.sh: forcing re-evaluation"
done

echo "resumed. Give services ~2 min to pass health checks."
