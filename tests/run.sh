#!/usr/bin/env bash
# run.sh — regression harness for plugin-auditor's mechanical scan helpers.
#
# Runs each scan_*.sh against the safe and malicious fixtures and checks their
# output against the contract in tests/expectations.md:
#   - safe-fixture: every helper must return zero findings.
#   - malicious-fixture: each planted category must be reported at least N times.
#
# Read-only: never installs anything, never executes fixture code. Exit 0 on
# success, 1 on any regression.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
SCRIPTS="${ROOT}/skills/audit/scripts"
SAFE="${HERE}/fixtures/safe-fixture"
MAL="${HERE}/fixtures/malicious-fixture"

PASS=0
FAIL=0

green() { printf '  ok   %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL %s\n' "$1"; FAIL=$((FAIL + 1)); }

# count_cat <output> <category-substring>: counts non-doc hits only.
count_cat() { grep -v '^doc:' <<<"$1" | grep -c -- "$2" 2>/dev/null || true; }

echo "== safe-fixture: expect zero findings from every helper =="
for s in scan_secrets scan_obfuscation scan_network scan_binaries scan_unicode scan_trust_surface; do
  out="$(bash "${SCRIPTS}/${s}.sh" "${SAFE}" 2>/dev/null || true)"
  # scan_network emits RFC1918 / link-local addresses under a "local:" host key.
  # Those are context for the sub-agent (CAUTION at most), not exfiltration
  # destinations, so they do not count as findings against the safe fixture.
  if [[ "${s}" == "scan_network" ]]; then
    out="$(grep -v '^local:' <<<"${out}" 2>/dev/null || true)"
  fi
  # doc: lines are documentation context (docs/threat-notes.md), not findings.
  out="$(grep -v '^doc:' <<<"${out}" 2>/dev/null || true)"
  n="$(grep -c . <<<"${out}" 2>/dev/null || true)"
  # grep -c on empty input returns 0 but with a trailing state; normalise.
  [[ -z "${out}" ]] && n=0
  if [[ "${n}" -eq 0 ]]; then
    green "${s}: 0 findings"
  else
    red "${s}: expected 0, got ${n}"
    printf '%s\n' "${out}" | sed 's/^/       /'
  fi
done

echo "== malicious-fixture: expect planted categories present =="

SEC="$(bash "${SCRIPTS}/scan_secrets.sh" "${MAL}" 2>/dev/null || true)"
OBF="$(bash "${SCRIPTS}/scan_obfuscation.sh" "${MAL}" 2>/dev/null || true)"
NET="$(bash "${SCRIPTS}/scan_network.sh" "${MAL}" 2>/dev/null || true)"
UNI="$(bash "${SCRIPTS}/scan_unicode.sh" "${MAL}" 2>/dev/null || true)"
BIN="$(bash "${SCRIPTS}/scan_binaries.sh" "${MAL}" 2>/dev/null || true)"
TRS="$(bash "${SCRIPTS}/scan_trust_surface.sh" "${MAL}" 2>/dev/null || true)"

# assert <label> <actual> <min>
assert() {
  local label="$1" actual="$2" min="$3"
  if [[ "${actual}" -ge "${min}" ]]; then
    green "${label}: ${actual} >= ${min}"
  else
    red "${label}: ${actual} < ${min}"
  fi
}

# Secrets: prefix catalogue (any of the well-known categories) >= 2.
prefix_hits=0
for c in openai_key anthropic_key github_pat_classic aws_access_key stripe_live sendgrid_key; do
  prefix_hits=$((prefix_hits + $(count_cat "${SEC}" ":${c}:")))
done
assert "secrets prefix-catalogue" "${prefix_hits}" 2
assert "secrets generic_high_entropy_assignment" "$(count_cat "${SEC}" ":generic_high_entropy_assignment:")" 1
assert "secrets generic_bearer" "$(count_cat "${SEC}" ":generic_bearer:")" 1

# Obfuscation.
blob_hits=$(( $(count_cat "${OBF}" ":base64_blob:") + $(count_cat "${OBF}" ":hex_blob:") + $(count_cat "${OBF}" ":base32_blob:") ))
assert "obfuscation encoded-blob" "${blob_hits}" 1
decode_hits=$(( $(count_cat "${OBF}" ":decode_exec:") + $(count_cat "${OBF}" ":decode_exec_multiline:") ))
assert "obfuscation decode->exec" "${decode_hits}" 1
assert "obfuscation reverse_shell" "$(count_cat "${OBF}" ":reverse_shell:")" 1

# Network. Host column is field 1; match on the host token.
assert "network duckdns host" "$(grep -c 'duckdns' <<<"${NET}" 2>/dev/null || true)" 1
assert "network bare IP:port" "$(grep -cE '^203\.0\.113\.7:8443' <<<"${NET}" 2>/dev/null || true)" 1
assert "network ws:// host" "$(grep -c 'c2.evasion-host.example' <<<"${NET}" 2>/dev/null || true)" 1
assert "network dns-query host" "$(grep -c 'attacker-dns.example' <<<"${NET}" 2>/dev/null || true)" 1

# Unicode: at least one zero-width and one bidi-override finding.
assert "unicode zero_width" "$(count_cat "${UNI}" ":zero_width:")" 1
assert "unicode bidi_override" "$(count_cat "${UNI}" ":bidi_override:")" 1

# Binaries: the committed payload.exe must be reported.
assert "binaries committed" "$(grep -c 'payload.exe' <<<"${BIN}" 2>/dev/null || true)" 1

# Trust surface: every category, plus the specific planted files that motivated it.
for c in config_write git_exec_config py_stdlib_shadow py_pth sandbox_weaken pre_trust \
         cred_reach lateral_movement exfil_channel llm_router nondefault_index lifecycle_script; do
  assert "trust ${c}" "$(count_cat "${TRS}" ":${c}:")" 1
done
assert "trust gitspawn fsmonitor" "$(grep -c 'dot-git/config:[0-9]*:git_exec_config:fsmonitor' <<<"${TRS}" 2>/dev/null || true)" 1
assert "trust settings.local.json write" "$(grep -c 'vendor-sync.sh:[0-9]*:config_write:.*settings.local.json' <<<"${TRS}" 2>/dev/null || true)" 1
assert "trust npm prepare swap" "$(grep -c 'config_write:npm pkg set scripts[.]prepare' <<<"${TRS}" 2>/dev/null || true)" 1
assert "trust docker socket" "$(grep -c 'sandbox_weaken:.*docker[.]sock' <<<"${TRS}" 2>/dev/null || true)" 2


echo "== documentation tagging =="
SAFE_DOC="$( (bash "${SCRIPTS}/scan_obfuscation.sh" "${SAFE}"; bash "${SCRIPTS}/scan_network.sh" "${SAFE}"; bash "${SCRIPTS}/scan_trust_surface.sh" "${SAFE}") 2>/dev/null | grep -c '^doc:' || true)"
assert "safe docs tagged doc: (obfuscation, network, trust)" "${SAFE_DOC}" 3
assert "malicious README hit tagged doc:" "$(grep -c '^doc:.*malicious-fixture/README.md:[0-9]*:cred_reach' <<<"${TRS}" 2>/dev/null || true)" 1
assert "instruction file never tagged doc:" "$(grep -c '^[^d].*skills/hotfix/SKILL.md:[0-9]*:nondefault_index' <<<"${TRS}" 2>/dev/null || true)" 1

echo "== self-scan: helpers must not match their own pattern source =="
for s in scan_obfuscation scan_trust_surface; do
  n="$(bash "${SCRIPTS}/${s}.sh" "${SCRIPTS}" 2>/dev/null | grep -v '^doc:' | grep -c . || true)"
  if [[ "${n}" -eq 0 ]]; then green "${s} on scripts/: 0"; else red "${s} on scripts/: ${n}"; fi
done

echo "== sub-agents have no shell =="
n="$(grep -lE '^tools:.*\bBash\b' "${ROOT}"/agents/*.md 2>/dev/null | wc -l | tr -d ' ')"
if [[ "${n}" -eq 0 ]]; then green "no agent lists Bash in tools"; else red "${n} agent(s) list Bash in tools"; fi

n="$(grep -cE 'Bash\(bash [^)]*/scripts/\*\)' "${ROOT}/skills/audit/SKILL.md" || true)"
if [[ "${n}" -eq 0 ]]; then green "no directory-wildcard script grant in SKILL.md"; else red "${n} directory-wildcard script grant(s)"; fi

echo "== git on the target runs with exec-capable config pinned =="
TRAP="$(mktemp -d)"
(
  cd "${TRAP}" && mkdir repo hooks && cd repo && git init -q \
    && git -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m one \
    && echo x > f && git add f && git -c user.email=t@example.invalid -c user.name=t commit -q -m two
) >/dev/null 2>&1
for k in fsmonitor diff pager hook; do printf '#!/bin/sh\ntouch "%s/fired-%s"\n' "${TRAP}" "${k}" > "${TRAP}/${k}.sh"; chmod +x "${TRAP}/${k}.sh"; done
cp "${TRAP}/hook.sh" "${TRAP}/hooks/post-checkout"
printf '[core]\n\tfsmonitor = %s/fsmonitor.sh\n\thooksPath = %s/hooks\n\tpager = %s/pager.sh\n[diff]\n\texternal = %s/diff.sh\n' \
  "${TRAP}" "${TRAP}" "${TRAP}" "${TRAP}" >> "${TRAP}/repo/.git/config"
PREV="$(git -C "${TRAP}/repo" -c core.fsmonitor=false rev-parse HEAD~1 2>/dev/null)"
bash "${SCRIPTS}/git_head.sh" "${TRAP}/repo" >/dev/null 2>&1 || true
bash "${SCRIPTS}/compute_delta.sh" "${TRAP}/repo" "${PREV}" >/dev/null 2>&1 || true
# status and a full diff do reach fsmonitor, pager and diff.external, so they prove the wrapper.
( source "${SCRIPTS}/lib_git.sh"; git_safe -C "${TRAP}/repo" status; git_safe -C "${TRAP}/repo" diff HEAD~1 ) >/dev/null 2>&1 || true
fired="$(find "${TRAP}" -maxdepth 1 -name 'fired-*' | wc -l | tr -d ' ')"
if [[ "${fired}" -eq 0 ]]; then green "git_safe wrapper, git_head.sh, compute_delta.sh fired no canary"; else red "${fired} canary command(s) ran"; fi
rm -rf "${TRAP}"

echo
echo "== summary =="
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]] || exit 1
