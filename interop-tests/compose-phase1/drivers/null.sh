#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
# SPDX-License-Identifier: Apache-2.0

# Development-only mock lane driver for the Compose Phase 1 evidence runner.
#
# It boots no guest. It exists so the harness can exercise the driver contract
# and the read-only sandbox without a VM. A driver speaks to the runner ONLY by
# writing the bounded result-contract file at $BASIL_DRIVER_RESULT; it never
# writes JSONL events, manifests, or anything outside its scratch directory. The
# runner refuses this lane under --qualification before this script ever runs.

set -euo pipefail
IFS=$'\n\t'
umask 077

result=${BASIL_DRIVER_RESULT:?BASIL_DRIVER_RESULT must be set by the runner}
schema=${BASIL_DRIVER_RESULT_SCHEMA:-basil.compose.phase1.driver-result}
schema_version=${BASIL_DRIVER_RESULT_SCHEMA_VERSION:-1}

# Confirm the read-only sandbox: a write outside the scratch directory must fail.
sandbox_status=PASS
sandbox_reason=SANDBOX_READ_ONLY
if ( : >/basil-null-driver-write-probe ) 2>/dev/null; then
  rm -f /basil-null-driver-write-probe 2>/dev/null || true
  sandbox_status=TEST_FAIL
  sandbox_reason=SANDBOX_ROOT_WRITABLE
fi

# Emit the bounded result contract. Values are controlled by the runner and this
# script, so the fixed template cannot be injected through untrusted input.
printf '{"schema":"%s","schema_version":%s,"driver":"null","results":[{"test_id":"dev.result-contract","status":"PASS","reason_code":"MOCK_CONTRACT_OK","message":"development null driver result contract"},{"test_id":"dev.sandbox-readonly","status":"%s","reason_code":"%s"}]}\n' \
  "$schema" "$schema_version" "$sandbox_status" "$sandbox_reason" >"$result"
