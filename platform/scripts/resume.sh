#!/usr/bin/env bash
# Resume the dev stack after pause.sh: start RDS, wait for it, then scale
# every service back to 1 (and restore the autoscaling floor).
set -euo pipefail
CLUSTER=meridian-dev

aws rds start-db-instance --db-instance-identifier meridian-dev-postgres --query 'DBInstance.DBInstanceStatus' --output text || true
echo "waiting for RDS to become available (~3-5 min)..."
aws rds wait db-instance-available --db-instance-identifier meridian-dev-postgres

for s in idp keysmith sessiond sentinel bridge portal console; do
  aws application-autoscaling register-scalable-target --service-namespace ecs \
    --resource-id "service/$CLUSTER/$s" --scalable-dimension ecs:service:DesiredCount \
    --min-capacity 1 >/dev/null
  aws ecs update-service --cluster "$CLUSTER" --service "$s" --desired-count 1 --query 'service.serviceName' --output text
done

echo "resumed. Give services ~2 min to pass health checks."
