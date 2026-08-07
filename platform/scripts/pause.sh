#!/usr/bin/env bash
# Pause the dev stack to stretch free-plan credits: scale every ECS service
# to 0 (autoscaling min first, or it scales them right back) and stop RDS.
# The portfolio site (CloudFront + S3) stays up. Idle cost ~$1.5-2/day
# (ALB + Redis + WAF + storage). Resume with resume.sh (~5 min).
set -euo pipefail
CLUSTER=meridian-dev
# The *-no-healthy-hosts alarms treat missing data as breaching, which is the
# whole point of them — but a paused stack is exactly that state on purpose.
# Silence just those; every other alarm stays armed. resume.sh re-arms them.
# Discovered, not hardcoded: an ALB service added to envs/dev later would
# otherwise page through every pause with nothing pointing at the omission.
read -r -a DOWN_ALARMS <<<"$(aws cloudwatch describe-alarms --alarm-name-prefix "$CLUSTER-" \
  --query 'MetricAlarms[?ends_with(AlarmName, `-no-healthy-hosts`)].AlarmName' --output text)"
[ ${#DOWN_ALARMS[@]} -gt 0 ] || { echo "no $CLUSTER-*-no-healthy-hosts alarms found; is observability applied?" >&2; exit 1; }

aws cloudwatch disable-alarm-actions --alarm-names "${DOWN_ALARMS[@]}"

for s in idp keysmith sessiond sentinel bridge portal console; do
  aws application-autoscaling register-scalable-target --service-namespace ecs \
    --resource-id "service/$CLUSTER/$s" --scalable-dimension ecs:service:DesiredCount \
    --min-capacity 0 >/dev/null
  aws ecs update-service --cluster "$CLUSTER" --service "$s" --desired-count 0 --query 'service.serviceName' --output text
done

aws rds stop-db-instance --db-instance-identifier meridian-dev-postgres --query 'DBInstance.DBInstanceStatus' --output text
echo "paused. NOTE: AWS auto-restarts a stopped RDS after 7 days — re-run pause.sh weekly if idle longer."
