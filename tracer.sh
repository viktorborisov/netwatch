#!/bin/bash
# tracer.sh — запускает ОДИН bpftrace (all.bt) и пишет события
# в общий JSONL, который читает Flask-контейнер.
#
# Почему один bpftrace, а не три: каждый инстанс bpftrace держит
# ~112MB RSS (libbpf/LLVM). Три = 337MB, это OOM на 868MB VPS.
# Один процесс с тремя probe = ~112MB и меньше bash-потомков.
#
# Вход:  TYPE|nsecs|pid|comm|rest
# Выход: {"ts":<ms>,"type":"net|proc|file","pid":N,"comm":"...","data":{...}}

set -u
DIR="/opt/netwatch"
OUT="$DIR/logs/events.jsonl"
mkdir -p "$DIR/logs"
: > "$OUT"
echo "[tracer] starting all.bt -> $OUT"

bpftrace "$DIR/bt/all.bt" 2>/dev/null | while IFS="|" read -r type nsecs pid comm rest; do
  case "$type" in
    CONNECT) daddr="${rest%%|*}"; dport="${rest##*|}"
      printf "{\"ts\":%d,\"type\":\"net\",\"pid\":%s,\"comm\":\"%s\",\"data\":{\"daddr\":\"%s\",\"dport\":%s}}\n" \
        "$((nsecs / 1000000))" "$pid" "$comm" "$daddr" "$dport" >> "$OUT" ;;
    EXEC) printf "{\"ts\":%d,\"type\":\"proc\",\"pid\":%s,\"comm\":\"%s\",\"data\":{\"file\":\"%s\"}}\n" \
        "$((nsecs / 1000000))" "$pid" "$comm" "$rest" >> "$OUT" ;;
    OPEN) printf "{\"ts\":%d,\"type\":\"file\",\"pid\":%s,\"comm\":\"%s\",\"data\":{\"file\":\"%s\"}}\n" \
        "$((nsecs / 1000000))" "$pid" "$comm" "$rest" >> "$OUT" ;;
  esac
done
