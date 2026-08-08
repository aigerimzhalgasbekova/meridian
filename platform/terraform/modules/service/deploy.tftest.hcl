# Pins the EFS/stop-before-start pairing. keysmith flocks its keystore and
# sentinel its audit chain, so the task holds an exclusive file: on the default
# 100/200 rolling deploy the replacement boots while the old task still holds
# the lock — a crash-looping deploy, or (before the locks existed) a silently
# lost write. Run with `terraform init && terraform test` in this directory.

mock_provider "aws" {
  # The provider validates assume_role_policy as JSON at plan time, and a
  # mocked data source returns a placeholder string. Give it a real document.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name                           = "keysmith"
  env_name                       = "meridian-test"
  cluster_arn                    = "arn:aws:ecs:eu-west-1:123456789012:cluster/meridian-test"
  vpc_id                         = "vpc-0123456789abcdef0"
  subnet_ids                     = ["subnet-0123456789abcdef0"]
  image                          = "123456789012.dkr.ecr.eu-west-1.amazonaws.com/meridian/keysmith:test"
  container_port                 = 8081
  service_discovery_namespace_id = "ns-0123456789abcdef"
  region                         = "eu-west-1"

  efs = {
    file_system_id  = "fs-0123456789abcdef0"
    access_point_id = "fsap-0123456789abcdef0"
    container_path  = "/data"
  }
}

run "efs_mount_without_stop_before_start_is_rejected" {
  command = plan

  variables {
    stop_before_start = false
  }

  expect_failures = [aws_ecs_service.this]
}

run "efs_mount_with_stop_before_start_drains_first" {
  command = plan

  variables {
    stop_before_start = true
  }

  assert {
    condition = (aws_ecs_service.this.deployment_minimum_healthy_percent == 0 &&
    aws_ecs_service.this.deployment_maximum_percent == 100)
    error_message = "stop_before_start must deploy 0/100 so the old task releases the lock before the new one boots."
  }
}

# A SIGKILLed EFS task leaves its NFSv4 lock lease held for ~90s. Replacements
# exit instantly on the LOCK_NB while it drains, and at desired_count = 1 three
# of those trip the breaker's floor on a perfectly good image. Rolling back then
# runs an image nobody shipped; not rolling back leaves the only signer at zero
# tasks. The breaker must be off here so ECS retries until the lease expires.
run "efs_mount_has_no_circuit_breaker" {
  command = plan

  variables {
    stop_before_start = true
  }

  assert {
    condition = (!aws_ecs_service.this.deployment_circuit_breaker[0].enable &&
    !aws_ecs_service.this.deployment_circuit_breaker[0].rollback)
    error_message = "A service holding an EFS flock must retry the shipped image, never stall at zero tasks or auto-revert."
  }
}

run "no_efs_still_rolls_start_before_stop" {
  command = plan

  variables {
    efs               = null
    stop_before_start = false
  }

  assert {
    condition = (aws_ecs_service.this.deployment_minimum_healthy_percent == 100 &&
    aws_ecs_service.this.deployment_maximum_percent == 200)
    error_message = "Services without an exclusive resource keep the zero-downtime rolling deploy."
  }

  assert {
    condition     = aws_ecs_service.this.deployment_circuit_breaker[0].rollback
    error_message = "Without an exclusive file there is no lock lease to race, so keep the automatic rollback."
  }
}
