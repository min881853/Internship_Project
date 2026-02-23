#!/usr/bin/env bash

# debug-nginx-interactive.sh
# Opens interactive bash inside mn.server1 and runs nginx test + start

CONTAINER="mn.server1"

if ! sudo docker ps --filter "name=^${CONTAINER}$" --format '{{.Status}}' | grep -q "Up"; then
    echo "Error: Container $CONTAINER is not running"
    exit 1
fi

echo "=== Opening interactive shell in $CONTAINER ==="
echo "Inside the shell you can run:"
echo "  nginx -t"
echo "  nginx -g 'daemon off;'"
echo "  (press Ctrl+C to stop nginx)"
echo ""

# This will drop you directly into bash inside the container
sudo docker exec -it "$CONTAINER" bash
