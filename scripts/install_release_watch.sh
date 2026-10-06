#!/bin/bash
# Install (or refresh) the release-channel watcher on this Mac as two
# launchd user agents (RELEASE_SIGNING_PLAN.md §10, Phase E):
#
#   com.permaevidence.briglia-release-watch.check      hourly at :07 → release_watch.py check
#   com.permaevidence.briglia-release-watch.heartbeat  hourly at :37 → release_heartbeat.py
#
# The watcher runs from a SNAPSHOT under ~/.config/briglia-release-watch/bin
# (release_watch.py, watch_audit.py, sentinel_site.py, release_heartbeat.py,
# py/release_verify.py copied from
# this checkout and recorded with the git commit), never from the working
# tree — editing the repo must not silently change what the monitor does.
#
# Deployment is atomic and verified, in this order:
#   1. both agents are unloaded and any running watcher process is waited
#      for (nothing runs while files change; the deploy refuses to proceed
#      if a run does not finish);
#   2. the new snapshot is staged completely in bin.new (copied, compiled,
#      commit recorded), then swapped in with one rename (bin → bin.old);
#   3. the CHECKER is run once in the foreground from the new snapshot and
#      must complete (exit 0 or 2 — findings are the checker working; exit 1
#      = it could not run); only then
#   4. the HEARTBEAT is run once in the foreground and must report healthy
#      (the check it just watched completed seconds ago);
#   5. only after both pass are the plists staged, linted and swapped in
#      (previous ones kept as .old) and the agents bootstrapped — checker
#      first, then heartbeat, without RunAtLoad (they already ran).
#   Any failure in 3–5 rolls back: whatever was loaded is booted out, the
#   previous plists and bin.old are restored, the previous agents reloaded.
#
#   scripts/install_release_watch.sh            # install / refresh
#   scripts/install_release_watch.sh --uninstall
#
# Alerts go to the Telegram chat configured in the env file named by the
# watcher config (default ~/.claude/channels/telegram/.env — the same bot
# Claude Code uses on this Mac). Logs: ~/Library/Logs/briglia-release-watch/.
# Test hooks (selftest only): BRIGLIA_WATCH_HOME overrides $HOME; launchctl is
# resolved through PATH so a shim can stand in for it.
set -euo pipefail
cd "$(dirname "$0")/.."

LABEL_BASE="com.permaevidence.briglia-release-watch"
HOME_DIR="${BRIGLIA_WATCH_HOME:-${HOME:?}}"
ROOT="$HOME_DIR/.config/briglia-release-watch"
BIN="$ROOT/bin"
LOGS="$HOME_DIR/Library/Logs/briglia-release-watch"
AGENTS="$HOME_DIR/Library/LaunchAgents"
CONFIG="$ROOT/config.json"
PY="$(command -v python3)"
UID_NUM="$(id -u)"

unload() {
    for kind in check heartbeat; do
        launchctl bootout "gui/$UID_NUM/$LABEL_BASE.$kind" 2>/dev/null || true
    done
}

wait_idle() {
    # Wait for any watcher process running from the installed snapshot to
    # finish; refuse to deploy over a run that will not end.
    local i
    for i in $(seq 1 120); do
        pgrep -f "$BIN/release_watch.py|$BIN/release_heartbeat.py" >/dev/null 2>&1 || return 0
        sleep 1
    done
    echo "✖ a watcher process from $BIN is still running after 120 s — not deploying over it" >&2
    return 1
}

load_agents() {
    # checker first, then heartbeat; each must be loaded before the next.
    # Explicit returns: this runs inside `||` chains where set -e is suspended.
    local kind
    for kind in check heartbeat; do
        launchctl bootstrap "gui/$UID_NUM" "$AGENTS/$LABEL_BASE.$kind.plist" || return 1
        launchctl print "gui/$UID_NUM/$LABEL_BASE.$kind" >/dev/null || return 1
    done
}

restore_plists() {
    # Undo a partial activation: drop staged .new files, put the previous
    # plists back (or remove ours entirely on a fresh install).
    local kind
    for kind in check heartbeat; do
        rm -f "$AGENTS/$LABEL_BASE.$kind.plist.new"
        if [ -f "$AGENTS/$LABEL_BASE.$kind.plist.old" ]; then
            mv -f "$AGENTS/$LABEL_BASE.$kind.plist.old" "$AGENTS/$LABEL_BASE.$kind.plist"
        elif [ "${HAD_AGENTS:-0}" = 0 ]; then
            rm -f "$AGENTS/$LABEL_BASE.$kind.plist"
        fi
    done
}

if [ "${1:-}" = "--uninstall" ]; then
    unload
    rm -f "$AGENTS/$LABEL_BASE.check.plist" "$AGENTS/$LABEL_BASE.heartbeat.plist"
    echo "✔ agents removed (state kept in $ROOT — delete it yourself if you mean it)"
    exit 0
fi

[ "$(uname)" = "Darwin" ] || { echo "✖ launchd installer is macOS-only (cron/systemd elsewhere)"; exit 1; }
[ -f scripts/release_watch.py ] && [ -f scripts/release_heartbeat.py ] && [ -f scripts/watch_audit.py ] \
    && [ -f scripts/sentinel_site.py ] && [ -f py/release_verify.py ] \
    || { echo "✖ run from a briglia-ut checkout"; exit 1; }

mkdir -p "$ROOT" "$LOGS" "$AGENTS"
chmod 700 "$ROOT"

# --- config: production defaults live in the script; the file only pins
# the state dir and can carry overrides (e.g. a transition manifest).
if [ ! -f "$CONFIG" ]; then
    cat > "$CONFIG" <<EOF
{
  "state_dir": "$ROOT",
  "channels": {}
}
EOF
    chmod 600 "$CONFIG"
    echo "✔ wrote $CONFIG"
fi

# --- 1. stop everything before any file changes
HAD_AGENTS=0
[ -f "$AGENTS/$LABEL_BASE.check.plist" ] && HAD_AGENTS=1
unload
wait_idle

# --- 2. stage the complete snapshot, then swap it in with one rename
rm -rf "$BIN.new"
mkdir -p "$BIN.new/py"
for pair in "scripts/release_watch.py:$BIN.new/release_watch.py" \
            "scripts/release_heartbeat.py:$BIN.new/release_heartbeat.py" \
            "scripts/watch_audit.py:$BIN.new/watch_audit.py" \
            "scripts/sentinel_site.py:$BIN.new/sentinel_site.py" \
            "py/release_verify.py:$BIN.new/py/release_verify.py"; do
    src="${pair%%:*}"; dst="${pair#*:}"
    old="$BIN/${dst#$BIN.new/}"
    if [ -f "$old" ] && ! cmp -s "$src" "$old"; then
        echo "— $src changed since the installed snapshot:"
        diff -u "$old" "$src" | head -40 || true
    fi
    install -m 0644 "$src" "$dst"
done
git rev-parse HEAD > "$BIN.new/SNAPSHOT_COMMIT" 2>/dev/null || echo unknown > "$BIN.new/SNAPSHOT_COMMIT"
"$PY" -m py_compile "$BIN.new/release_watch.py" "$BIN.new/release_heartbeat.py" "$BIN.new/watch_audit.py" \
    "$BIN.new/sentinel_site.py" "$BIN.new/py/release_verify.py"
rm -rf "$BIN.old"
[ -d "$BIN" ] && mv "$BIN" "$BIN.old"
mv "$BIN.new" "$BIN"

rollback() {
    echo "✖ $1 — rolling back" >&2
    unload                # boot out anything the failed activation loaded
    restore_plists        # previous plists back (no-op before activation)
    rm -rf "$BIN.failed"
    mv "$BIN" "$BIN.failed"
    if [ -d "$BIN.old" ]; then
        mv "$BIN.old" "$BIN"
        if [ "$HAD_AGENTS" = 1 ]; then
            load_agents || echo "  ✖ could not reload the previous agents — run 'launchctl bootstrap gui/$UID_NUM $AGENTS/$LABEL_BASE.{check,heartbeat}.plist' by hand" >&2
        fi
        echo "  previous snapshot restored ($(cut -c1-12 "$BIN/SNAPSHOT_COMMIT" 2>/dev/null || echo unknown)); failed one kept in $BIN.failed" >&2
    else
        echo "  no previous snapshot; failed one kept in $BIN.failed, no agents loaded" >&2
    fi
    exit 1
}

# --- 3. verify the checker from the new snapshot (foreground, sequential)
set +e
"$PY" "$BIN/release_watch.py" check --config "$CONFIG" >> "$LOGS/check.log" 2>&1
rc=$?
set -e
case "$rc" in
    0) echo "✔ checker verified from the new snapshot (clean)";;
    2) echo "✔ checker verified from the new snapshot (it reported findings — see $LOGS/check.log)";;
    *) rollback "checker exited $rc from the new snapshot (see $LOGS/check.log)";;
esac

# --- 4. verify the heartbeat (must be healthy: the check just completed)
set +e
"$PY" "$BIN/release_heartbeat.py" --config "$CONFIG" >> "$LOGS/heartbeat.log" 2>&1
rc=$?
set -e
[ "$rc" = 0 ] && echo "✔ heartbeat verified from the new snapshot" \
    || rollback "heartbeat exited $rc right after a completed check (see $LOGS/heartbeat.log)"

# --- 5. agents (no RunAtLoad: both just ran; the calendar takes it from here)
plist() {  # label logname minute program-args...
    local label="$1" logname="$2" minute="$3"; shift 3
    local args="" a
    for a in "$@"; do args="$args<string>$a</string>"; done
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>$args</array>
  <key>StartCalendarInterval</key><dict><key>Minute</key><integer>$minute</integer></dict>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>$LOGS/$logname.log</string>
  <key>StandardErrorPath</key><string>$LOGS/$logname.log</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
</dict></plist>
EOF
}
activate() {
    # The activation is part of the transaction: stage both plists, lint
    # them, swap them in (previous ones kept as .old), bootstrap checker
    # then heartbeat. Any failure → the caller rolls everything back.
    local kind
    plist "$LABEL_BASE.check" check 7 "$PY" "$BIN/release_watch.py" check --config "$CONFIG" > "$AGENTS/$LABEL_BASE.check.plist.new" || return 1
    plist "$LABEL_BASE.heartbeat" heartbeat 37 "$PY" "$BIN/release_heartbeat.py" --config "$CONFIG" > "$AGENTS/$LABEL_BASE.heartbeat.plist.new" || return 1
    for kind in check heartbeat; do
        plutil -lint -s "$AGENTS/$LABEL_BASE.$kind.plist.new" || return 1
    done
    for kind in check heartbeat; do
        if [ -f "$AGENTS/$LABEL_BASE.$kind.plist" ]; then
            mv -f "$AGENTS/$LABEL_BASE.$kind.plist" "$AGENTS/$LABEL_BASE.$kind.plist.old" || return 1
        fi
        mv -f "$AGENTS/$LABEL_BASE.$kind.plist.new" "$AGENTS/$LABEL_BASE.$kind.plist" || return 1
    done
    load_agents || return 1
    rm -f "$AGENTS/$LABEL_BASE.check.plist.old" "$AGENTS/$LABEL_BASE.heartbeat.plist.old"
}
activate || rollback "agent activation failed (plist write/lint or launchctl bootstrap/print)"
rm -rf "$BIN.old"
echo "✔ installed: check at :07 every hour, heartbeat at :37 every hour (both verified once in the foreground just now)"
echo "  snapshot $(cut -c1-12 "$BIN/SNAPSHOT_COMMIT") in $BIN, logs in $LOGS"
echo "  status:   launchctl print gui/$UID_NUM/$LABEL_BASE.check | grep -E 'state|last exit'"
echo "  state:    $PY $BIN/release_watch.py status --config $CONFIG"
echo "  beacon:   $PY $BIN/release_heartbeat.py --status --config $CONFIG"
