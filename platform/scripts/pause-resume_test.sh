#!/usr/bin/env bash
# Self-check for pause.sh / resume.sh alarm discovery. Runs both scripts against
# a stub `aws` on PATH — no AWS account, no network. Run: ./pause-resume_test.sh
#
# Pins two things the here-string version got wrong:
#   1. a failed describe-alarms is reported as a failure, not as "no alarms".
#   2. resume.sh brings the stack back BEFORE it touches CloudWatch, so a
#      monitoring hiccup can never leave RDS stopped and every service at 0.
#   3. a warning on aws's stderr never becomes an alarm name (the stub emits
#      one on every successful describe-alarms).
set -uo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT

cat >"$STUB/aws" <<'STUBEOF'
#!/usr/bin/env bash
echo "$*" >>"$AWS_STUB_LOG"
if [ "$1" = cloudwatch ] && [ "$2" = describe-alarms ]; then
  if [ "${AWS_STUB_ALARMS:-ok}" = fail ]; then
    echo "ExpiredToken: the security token included in the request is expired" >&2
    exit 255
  fi
  # A pip-installed CLI warns on stderr and still exits 0.
  echo "urllib3/__init__.py:35: NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+" >&2
  echo "meridian-dev-idp-no-healthy-hosts	meridian-dev-bridge-no-healthy-hosts"
fi
exit 0
STUBEOF
chmod +x "$STUB/aws"
export PATH="$STUB:$PATH"

fails=0
check() { # check <label> <condition-result>
  if [ "$2" = 0 ]; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi
}

# 1. pause.sh must name the real cause, not "no alarms found".
export AWS_STUB_LOG="$STUB/pause-fail.log" AWS_STUB_ALARMS=fail
: >"$AWS_STUB_LOG"
out=$("$HERE/pause.sh" 2>&1)
rc=$?
[ "$rc" -ne 0 ] && [[ $out == *"describe-alarms failed"* ]] && [[ $out != *"no meridian-dev-"* ]]
check "pause.sh reports an API failure as a failure" $?

# 2. pause.sh must still refuse to scale anything down when discovery fails —
#    silencing nothing and then pausing would page through the whole pause.
! grep -q "ecs update-service" "$AWS_STUB_LOG"
check "pause.sh scales nothing when discovery fails" $?

# 3. resume.sh must have already started RDS and scaled the services back up.
export AWS_STUB_LOG="$STUB/resume-fail.log"
: >"$AWS_STUB_LOG"
out=$("$HERE/resume.sh" 2>&1)
rc=$?
grep -q "rds start-db-instance" "$AWS_STUB_LOG" &&
  [ "$(grep -c 'ecs update-service' "$AWS_STUB_LOG")" -eq 7 ] &&
  [ "$rc" -ne 0 ] && [[ $out == *"describe-alarms failed"* ]]
check "resume.sh resumes the stack before the CloudWatch read can block it" $?

# 4. Happy path still re-arms the alarms it discovered.
export AWS_STUB_LOG="$STUB/resume-ok.log" AWS_STUB_ALARMS=ok
: >"$AWS_STUB_LOG"
"$HERE/resume.sh" >/dev/null 2>&1 &&
  grep -q "enable-alarm-actions --alarm-names meridian-dev-idp-no-healthy-hosts meridian-dev-bridge-no-healthy-hosts" "$AWS_STUB_LOG"
check "resume.sh re-arms both discovered alarms on the happy path" $?

# 5. Happy path silences exactly the two real alarms — not the stderr warning.
export AWS_STUB_LOG="$STUB/pause-ok.log"
: >"$AWS_STUB_LOG"
"$HERE/pause.sh" >/dev/null 2>&1 &&
  grep -qx "cloudwatch disable-alarm-actions --alarm-names meridian-dev-idp-no-healthy-hosts meridian-dev-bridge-no-healthy-hosts" "$AWS_STUB_LOG"
check "pause.sh silences exactly the discovered alarms" $?

[ "$fails" -eq 0 ] || { echo "$fails check(s) failed"; exit 1; }
echo "all checks passed"
