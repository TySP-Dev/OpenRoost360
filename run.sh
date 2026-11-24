#!/usr/bin/env bash
# Run OpenRoost360 without Docker: web app + API on https://:8443 (:8362 redirects), hub listener on :8883. Data in ./data.
#   ./run.sh            start in the background (log: data/openroost.log)
#   ./run.sh stop
#   ./run.sh fg         run in the foreground
# The hub reaches the listener through Pi-hole + a port 443 -> 8883 redirect for the hub's address
# (see README.md). Docker packaging comes next.
cd "$(dirname "$0")"
umask 077                      # data, log and pid files are private (the log holds the setup code)
PID=data/openroost.pid
mkdir -p data && chmod 700 data
case "$1" in
  stop) [ -f $PID ] && kill "$(cat $PID)" 2>/dev/null; rm -f $PID; echo stopped; exit ;;
  fg)   exec python3 -m openroost --data data ;;
esac
python3 -m openroost --data data >> data/openroost.log 2>&1 &
echo $! > $PID
sleep 1.5
IP=$(ip -4 -o addr show scope global | grep -vE "proton|pvpn|tun|wg|docker|br-" | awk '{print $4}' | cut -d/ -f1 | head -1)
echo "  OpenRoost360  ->  https://$IP:8443/"
[ -f data/SETUP-CODE.txt ] && echo "  First-time setup code: $(cat data/SETUP-CODE.txt)"
