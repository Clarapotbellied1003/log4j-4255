.PHONY: run build clean

# Full reproduction: fetch+verify jars, compile, run all 7 scenarios.
run:
	./run.sh

# Alias — run.sh compiles as part of its flow; this just runs it.
build: run

# Remove downloaded jars, compiled classes, proof/log artifacts, and the docker network.
clean:
	rm -rf .jars .victim_classes .attacker_classes .proof
	-docker network rm log4j4255-net 2>/dev/null
	-docker rm -f recv 2>/dev/null
	@echo "cleaned"
