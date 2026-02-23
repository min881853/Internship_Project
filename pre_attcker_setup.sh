#!/usr/bin/env bash

# start-attackers-prep.sh
# Automates only:
#   - Copying attacker_server2.py and botnet.py to all attacker containers
#   - Fixing DNS (Google public DNS) in all attacker containers

set -euo pipefail  # exit on error, undefined vars, pipe failures

# === Configuration ===
SCRIPT_SERVER="attacker_server2.py"
SCRIPT_BOTNET="botnet.py"
CONTAINERS=("mn.attacker1" "mn.attacker2" "mn.attacker3")  # edit if needed

echo "=== Preparing all attacker containers ==="
echo "(Copying files + fixing DNS — you will start python scripts manually)"
echo ""

for container in "${CONTAINERS[@]}"; do
    echo ""
    echo "→ Processing $container"

    # Skip if container is not running
    if ! sudo docker ps --filter "name=^${container}$" --format '{{.Status}}' | grep -q "Up"; then
        echo "  WARNING: $container is not running → skipping"
        continue
    fi

    # 1. Copy scripts (only if files exist on host)
    if [ -f "$SCRIPT_SERVER" ]; then
        echo "  Copying $SCRIPT_SERVER ..."
        sudo docker cp "$SCRIPT_SERVER" "$container:/$SCRIPT_SERVER"
    else
        echo "  Warning: $SCRIPT_SERVER not found on host → skipping copy"
    fi

    if [ -f "$SCRIPT_BOTNET" ]; then
        echo "  Copying $SCRIPT_BOTNET ..."
        sudo docker cp "$SCRIPT_BOTNET" "$container:/$SCRIPT_BOTNET"
    else
        echo "  Warning: $SCRIPT_BOTNET not found on host → skipping copy"
    fi

    # 2. Fix DNS (Google DNS) — always safe to overwrite
    echo "  Setting Google DNS ..."
    sudo docker exec "$container" bash -c "
        echo 'nameserver 8.8.8.8' > /etc/resolv.conf
        echo 'nameserver 8.8.4.4' >> /etc/resolv.conf
        echo '✅ DNS set'
    "

    echo "  → $container prepared"
done

echo ""
echo "All containers prepared!"
echo ""
echo "Next steps (do these manually in separate terminals):"
echo ""
echo "Terminal 1 – C&C server (attacker1):"
echo "  sudo docker exec -it mn.attacker1 python3 attacker_server2.py"
echo ""
echo "Terminal 2 – Botnet (attacker2):"
echo "  sudo docker exec -it mn.attacker2 python3 botnet.py"
echo ""
echo "Terminal 3 – Botnet (attacker3):"
echo "  sudo docker exec -it mn.attacker3 python3 botnet.py"
echo ""
echo "After they are running, you can attach to attacker1 to type commands:"
echo "  sudo docker attach mn.attacker1"
echo ""
echo "To see logs later (without attaching):"
echo "  sudo docker logs -f mn.attacker1"
echo ""
echo "Done. You can now open your terminals and start the python processes manually."
