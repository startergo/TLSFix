#!/bin/bash
# Install and manage a self-hosted anisette server on a modern Mac, for
# AquaTransport clients whose own AOSKit can no longer mint device
# authentication data. See docs/ICLOUD.md, "Self-hosted anisette".
#
#   tools/anisette-host.sh install [ssh-host]   build, install launch agents,
#                                               start serving on 127.0.0.1:9724
#                                               and tunnel it to ssh-host
#   tools/anisette-host.sh status               agents, tunnel, local fetch
#   tools/anisette-host.sh stop                 stop both agents
#   tools/anisette-host.sh uninstall            stop and remove everything
#
# The server binds loopback only. The client machine reaches it through a
# reverse SSH tunnel, so the URL the client configures stays a loopback
# address -- plain HTTP on loopback is what AquaTransport's GSA adapter
# accepts without a certificate it would have to trust.
#
# On the client, the URL is:
#   /usr/share/aquatransport/config/gsa-anisette-url.txt
#     -> http://127.0.0.1:9724/anisette
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HOME/Library/Application Support/AquaTransport"
AGENTS="$HOME/Library/LaunchAgents"
LOGDIR="$HOME/Library/Logs"
LOG="$LOGDIR/aquatransport-anisette.log"
PORT=9724
SERVER_LABEL=com.aquatransport.anisette-server
TUNNEL_LABEL=com.aquatransport.anisette-tunnel
SSH_HOST=""

plist_server="$AGENTS/$SERVER_LABEL.plist"
plist_tunnel="$AGENTS/$TUNNEL_LABEL.plist"

uid="$(id -u)"

load() { launchctl bootstrap "gui/$uid" "$1" 2>/dev/null || launchctl load "$1"; }
unload() { launchctl bootout "gui/$uid/$1" 2>/dev/null || launchctl remove "$1" 2>/dev/null || true; }

write_server_plist() {
    cat > "$plist_server" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$SERVER_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DEST/anisette-server</string>
        <string>$PORT</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$LOG</string>
    <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
PLIST
}

write_tunnel_plist() {
    cat > "$plist_tunnel" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$TUNNEL_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>while true; do /usr/bin/ssh -N -R $PORT:127.0.0.1:$PORT -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o BatchMode=yes $SSH_HOST; sleep 10; done</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST
}

case "${1:-}" in
install)
    # The host name is interpolated into a bash -c command inside a launchd
    # plist, so anything beyond host-name characters would be shell or XML
    # injection; and there is no universal default -- an ssh alias local to
    # one machine means nothing on another. Require the argument.
    [ $# -ge 2 ] || { echo 'usage: anisette-host.sh install <ssh-host-or-alias>'; exit 1; }
    SSH_HOST="$2"
    case "$SSH_HOST" in
        *[!A-Za-z0-9._-]*) echo "invalid host name: $SSH_HOST"; exit 1 ;;
    esac
    mkdir -p "$DEST" "$AGENTS" "$LOGDIR"
    echo "Building anisette-server..."
    cc -O2 -Wall -framework Foundation "$DIR/tools/anisette-server.m" -o "$DEST/anisette-server"
    write_server_plist
    write_tunnel_plist
    unload "$SERVER_LABEL"; unload "$TUNNEL_LABEL"
    load "$plist_server"; load "$plist_tunnel"
    sleep 1
    echo "Server and tunnel agents loaded (port $PORT, host $SSH_HOST)."
    echo "Configure the client with:"
    echo "  echo http://127.0.0.1:$PORT/anisette | sudo tee /usr/share/aquatransport/config/gsa-anisette-url.txt"
    ;;
status)
    echo "--- agents ---"
    launchctl print "gui/$uid/$SERVER_LABEL" 2>/dev/null | grep -E "state|pid" || echo "$SERVER_LABEL not loaded"
    launchctl print "gui/$uid/$TUNNEL_LABEL" 2>/dev/null | grep -E "state|pid" || echo "$TUNNEL_LABEL not loaded"
    echo "--- local fetch ---"
    curl -sS -m 8 -o /dev/null -w "HTTP %{http_code}\n" "http://127.0.0.1:$PORT/anisette" || true
    echo "--- log (last 5) ---"
    tail -5 "$LOG" 2>/dev/null || echo "no log yet"
    ;;
stop)
    unload "$SERVER_LABEL"; unload "$TUNNEL_LABEL"
    echo "Stopped."
    ;;
uninstall)
    unload "$SERVER_LABEL"; unload "$TUNNEL_LABEL"
    rm -f "$plist_server" "$plist_tunnel" "$DEST/anisette-server"
    echo "Removed agents and binary. Log kept at $LOG"
    echo "Remove the client override too:"
    echo "  sudo rm /usr/share/aquatransport/config/gsa-anisette-url.txt"
    ;;
*)
    sed -n '2,12p' "$0"; exit 1 ;;
esac
