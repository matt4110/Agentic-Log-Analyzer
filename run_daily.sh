#!/usr/bin/env bash
#
# run_daily.sh - single entry point for the whole Agentic-Log-Analyzer pipeline.
# Run this one script (or let cron run it); it executes all 7 steps in order,
# stops immediately if any step fails, and logs everything to a dated file.
#
# Manual use:   /opt/Agentic-Log-Analyzer/run_daily.sh
# Cron use:     see the cron.d entry at the bottom of this file's comments.

set -euo pipefail       # -e: stop on any error  -u: error on unset vars  -o pipefail: catch errors mid-pipe

# --- Configuration ---------------------------------------------------------
PROJECT_DIR="/opt/Agentic-Log-Analyzer"
PYTHON="/usr/bin/python3"          # system python (no venv, libs installed system-wide)
LOG_DIR="${PROJECT_DIR}/run_logs"  # where this wrapper's own run logs go
NOTIFIER="${PROJECT_DIR}/notify_discord.py"
ENV_FILE="${PROJECT_DIR}/.env"

# Load secrets/keys from .env into the environment so EVERY step sees them -
# main.py's threat-intel enrichment (GREYNOISE/ABUSEIPDB/THREATFOX keys) and
# the Discord notifier (DISCORD_WEBHOOK_URL) all read os.environ. A .env file
# on disk is NOT automatically in the environment; it must be sourced. Doing
# it here means the script behaves identically run by hand or by cron, so the
# cron entry no longer needs to source .env itself.
if [[ -f "${ENV_FILE}" ]]; then
    set -a               # export everything defined while sourcing
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
else
    echo "[warn] ${ENV_FILE} not found - API keys and Discord webhook will be unset"
fi

# Date the run is FOR. The pipeline names its files/dirs with this date, and
# main.py creates ioc_output/<DATE>/. Computing it once here is what prevents
# the chunker/analyzer date-mismatch bug. Uses UTC to match your midnight-UTC
# logrotate and main.py's own UTC dating.
RUN_DATE="$(date -u +%F)"          # e.g. 2026-07-21

OUTPUT_DIR="${PROJECT_DIR}/ioc_output/${RUN_DATE}"
REPORT_JSON="${OUTPUT_DIR}/ioc_report_${RUN_DATE}.json"
CHUNK_DIR="${OUTPUT_DIR}/chunks"
DAILY_REPORT="${OUTPUT_DIR}/daily_report_${RUN_DATE}.md"

# --- Setup -----------------------------------------------------------------
mkdir -p "${LOG_DIR}"
RUN_LOG="${LOG_DIR}/run_${RUN_DATE}.log"

# Send all stdout+stderr from here on to BOTH the console and the run log.
exec > >(tee -a "${RUN_LOG}") 2>&1

echo "=============================================================="
echo "Agentic-Log-Analyzer daily run  |  date=${RUN_DATE}  |  $(date -u)"
echo "=============================================================="

cd "${PROJECT_DIR}"    # scripts use paths relative to the project root

# Small helper so each step is announced and timed, and a failure names the step.
step() {
    local label="$1"; shift
    echo ""
    echo "----- [${label}] $(date -u +%T) -----"
    if ! "$@"; then
        echo "!!! STEP FAILED: ${label} (command: $*)"
        echo "!!! Aborting run for ${RUN_DATE}. See ${RUN_LOG}"
        # ping Discord that the pipeline broke (a failed run is not an all-clear)
        "${PYTHON}" "${NOTIFIER}" failure --step "${label}" \
            --logfile "${RUN_LOG}" --date "${RUN_DATE}" || true
        exit 1
    fi
}

# --- Pipeline (the 7 steps, in order) --------------------------------------
step "parse auditd"    "${PYTHON}" LogProcessing/auditd-log-parser.py
step "parse auth"      "${PYTHON}" LogProcessing/auth-log-parser.py
step "parse safeline"  "${PYTHON}" LogProcessing/safeline-log-parser.py
step "parse ufw"       "${PYTHON}" LogProcessing/ufw-log-parser.py

step "detect+correlate (main)" "${PYTHON}" ioc_hunter/main.py

# Sanity-check main.py actually produced the report before chunking, so a
# silent upstream problem doesn't cascade into confusing downstream errors.
if [[ ! -f "${REPORT_JSON}" ]]; then
    echo "!!! Expected report not found: ${REPORT_JSON}"
    echo "!!! main.py may have written a different path - check its output above."
    "${PYTHON}" "${NOTIFIER}" failure --step "verify report exists" \
        --logfile "${RUN_LOG}" --date "${RUN_DATE}" || true
    exit 1
fi

step "chunk report"    "${PYTHON}" ioc_hunter/chunk_report.py "${REPORT_JSON}"
step "llm analyze"     "${PYTHON}" ioc_hunter/llm_analyze.py "${CHUNK_DIR}/" --out "${DAILY_REPORT}"

echo ""
echo "----- [notify discord] $(date -u +%T) -----"
"${PYTHON}" "${NOTIFIER}" success --report "${DAILY_REPORT}" --date "${RUN_DATE}" || \
    echo "(notification failed, but the run itself succeeded - report is at ${DAILY_REPORT})"

echo ""
echo "=============================================================="
echo "DONE ${RUN_DATE}  |  report: ${DAILY_REPORT}"
echo "=============================================================="