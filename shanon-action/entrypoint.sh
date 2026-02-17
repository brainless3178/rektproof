#!/bin/bash
# ──────────────────────────────────────────────────────────
# Shanon GitHub Action — Entrypoint
# Runs security scan + guard + optional PR annotation
# ──────────────────────────────────────────────────────────
set -eo pipefail

PROGRAM_PATH="${1:-.}"
FAIL_ON="${2:-critical,high}"
PROVE="${3:-false}"
GUARD="${4:-true}"
ANNOTATE="${5:-true}"
FORMAT="${6:-json}"
GITHUB_TOKEN="${7:-}"

echo ""
echo "🛡️  Shanon Security Scan"
echo "─────────────────────────────────────"
echo "  Program Path:  ${PROGRAM_PATH}"
echo "  Fail On:       ${FAIL_ON}"
echo "  Guard:         ${GUARD}"
echo "  Annotate:      ${ANNOTATE}"
echo "─────────────────────────────────────"
echo ""

# ─── Run vulnerability scan ─────────────────────────────

SCAN_JSON=""
SCAN_EXIT=0

if [ -d "$PROGRAM_PATH" ]; then
    echo "::group::🔍 Running Shanon Security Scan"
    SCAN_JSON=$(shanon scan "$PROGRAM_PATH" --format json 2>/dev/null) || SCAN_EXIT=$?
    echo "$SCAN_JSON" | jq '.' 2>/dev/null || echo "$SCAN_JSON"
    echo "::endgroup::"
else
    echo "::warning::Program path '$PROGRAM_PATH' not found — skipping scan"
    SCAN_JSON='[]'
fi

# ─── Run dependency guard ───────────────────────────────

GUARD_JSON=""
GUARD_EXIT=0

if [ "$GUARD" = "true" ]; then
    echo "::group::🛡️ Running Shanon Guard (Dependency Firewall)"
    GUARD_JSON=$(shanon guard --path "$PROGRAM_PATH" --format json 2>/dev/null) || GUARD_EXIT=$?
    echo "$GUARD_JSON" | jq '.' 2>/dev/null || echo "$GUARD_JSON"
    echo "::endgroup::"
fi

# ─── Parse results ──────────────────────────────────────

# Count findings by severity from scan results
TOTAL_FINDINGS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

if [ -n "$SCAN_JSON" ] && [ "$SCAN_JSON" != "[]" ]; then
    TOTAL_FINDINGS=$(echo "$SCAN_JSON" | jq 'length // 0' 2>/dev/null || echo "0")
    CRITICAL_COUNT=$(echo "$SCAN_JSON" | jq '[.[] | select(.severity_label == "CRITICAL")] | length // 0' 2>/dev/null || echo "0")
    HIGH_COUNT=$(echo "$SCAN_JSON" | jq '[.[] | select(.severity_label == "HIGH")] | length // 0' 2>/dev/null || echo "0")
    MEDIUM_COUNT=$(echo "$SCAN_JSON" | jq '[.[] | select(.severity_label == "MEDIUM")] | length // 0' 2>/dev/null || echo "0")
    LOW_COUNT=$(echo "$SCAN_JSON" | jq '[.[] | select(.severity_label == "LOW")] | length // 0' 2>/dev/null || echo "0")
fi

# Guard risk score
GUARD_RISK=0
GUARD_FINDINGS=0
if [ -n "$GUARD_JSON" ]; then
    GUARD_RISK=$(echo "$GUARD_JSON" | jq '.risk_score // 0' 2>/dev/null || echo "0")
    GUARD_CARGO=$(echo "$GUARD_JSON" | jq '.cargo_findings | length // 0' 2>/dev/null || echo "0")
    GUARD_NPM=$(echo "$GUARD_JSON" | jq '.npm_findings | length // 0' 2>/dev/null || echo "0")
    GUARD_BEHAVIOR=$(echo "$GUARD_JSON" | jq '.behavioral_findings | length // 0' 2>/dev/null || echo "0")
    GUARD_FINDINGS=$((GUARD_CARGO + GUARD_NPM + GUARD_BEHAVIOR))
fi

# Calculate overall risk score (simple: higher of scan severity or guard risk)
RISK_SCORE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then
    RISK_SCORE=90
elif [ "$HIGH_COUNT" -gt 0 ]; then
    RISK_SCORE=70
elif [ "$MEDIUM_COUNT" -gt 0 ]; then
    RISK_SCORE=40
elif [ "$LOW_COUNT" -gt 0 ]; then
    RISK_SCORE=20
fi
if [ "$GUARD_RISK" -gt "$RISK_SCORE" ]; then
    RISK_SCORE=$GUARD_RISK
fi

ALL_FINDINGS=$((TOTAL_FINDINGS + GUARD_FINDINGS))

# ─── Set GitHub Action outputs ──────────────────────────

if [ -n "$GITHUB_OUTPUT" ]; then
    echo "risk-score=${RISK_SCORE}" >> "$GITHUB_OUTPUT"
    echo "findings-count=${ALL_FINDINGS}" >> "$GITHUB_OUTPUT"
    echo "critical-count=${CRITICAL_COUNT}" >> "$GITHUB_OUTPUT"
    echo "high-count=${HIGH_COUNT}" >> "$GITHUB_OUTPUT"
fi

# ─── Write job summary ─────────────────────────────────

if [ -n "$GITHUB_STEP_SUMMARY" ]; then
    cat >> "$GITHUB_STEP_SUMMARY" <<EOF
## 🛡️ Shanon Security Scan Results

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${CRITICAL_COUNT} |
| 🟠 High | ${HIGH_COUNT} |
| 🟡 Medium | ${MEDIUM_COUNT} |
| 🔵 Low | ${LOW_COUNT} |

**Risk Score: ${RISK_SCORE}/100**

### Dependency Firewall
| Metric | Value |
|--------|-------|
| Supply Chain Risk Score | ${GUARD_RISK}/100 |
| Dependency Findings | ${GUARD_FINDINGS} |

---
*Powered by [Shanon Security Oracle](https://shanon.security) • 52+ detectors • Z3 formal proofs*
EOF
fi

# ─── GitHub annotations (warning/error markers) ────────

if [ -n "$SCAN_JSON" ] && [ "$SCAN_JSON" != "[]" ] && [ "$TOTAL_FINDINGS" -gt 0 ]; then
    echo "$SCAN_JSON" | jq -r '.[] | 
        if .severity_label == "CRITICAL" then
            "::error file=\(.location),title=\(.id) \(.vuln_type)::\(.description)"
        elif .severity_label == "HIGH" then
            "::error file=\(.location),title=\(.id) \(.vuln_type)::\(.description)"
        else
            "::warning file=\(.location),title=\(.id) \(.vuln_type)::\(.description)"
        end' 2>/dev/null || true
fi

# ─── PR comment annotation ─────────────────────────────

if [ "$ANNOTATE" = "true" ] && [ -n "$GITHUB_EVENT_PATH" ] && [ -n "$GITHUB_TOKEN" ]; then
    # Combine scan + guard results for the annotator
    COMBINED=$(jq -n \
        --argjson scan "${SCAN_JSON:-[]}" \
        --argjson guard "${GUARD_JSON:-{}}" \
        --argjson risk "$RISK_SCORE" \
        --argjson critical "$CRITICAL_COUNT" \
        --argjson high "$HIGH_COUNT" \
        --argjson medium "$MEDIUM_COUNT" \
        --argjson low "$LOW_COUNT" \
        --argjson guard_risk "$GUARD_RISK" \
        '{
            findings: $scan,
            guard: $guard,
            risk_score: $risk,
            critical_count: $critical,
            high_count: $high,
            medium_count: $medium,
            low_count: $low,
            guard_risk_score: $guard_risk
        }' 2>/dev/null)

    if [ -n "$COMBINED" ]; then
        GITHUB_TOKEN="$GITHUB_TOKEN" node /annotate.js "$COMBINED" 2>/dev/null || \
            echo "::warning::PR annotation failed (non-fatal)"
    fi
fi

# ─── Print summary ─────────────────────────────────────

echo ""
echo "─────────────────────────────────────"
echo "  📊 Results Summary"
echo "─────────────────────────────────────"
echo "  Risk Score:      ${RISK_SCORE}/100"
echo "  Total Findings:  ${ALL_FINDINGS}"
echo "  Critical:        ${CRITICAL_COUNT}"
echo "  High:            ${HIGH_COUNT}"
echo "  Medium:          ${MEDIUM_COUNT}"
echo "  Low:             ${LOW_COUNT}"
echo "  Guard Risk:      ${GUARD_RISK}/100"
echo "─────────────────────────────────────"
echo ""

# ─── Determine exit code ───────────────────────────────

SHOULD_FAIL=0

if echo "$FAIL_ON" | grep -qi "critical" && [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "::error::Shanon found ${CRITICAL_COUNT} critical vulnerabilities"
    SHOULD_FAIL=1
fi

if echo "$FAIL_ON" | grep -qi "high" && [ "$HIGH_COUNT" -gt 0 ]; then
    echo "::error::Shanon found ${HIGH_COUNT} high-severity vulnerabilities"
    SHOULD_FAIL=1
fi

if echo "$FAIL_ON" | grep -qi "medium" && [ "$MEDIUM_COUNT" -gt 0 ]; then
    echo "::error::Shanon found ${MEDIUM_COUNT} medium-severity vulnerabilities"
    SHOULD_FAIL=1
fi

exit $SHOULD_FAIL
