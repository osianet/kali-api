#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="$(dirname "$0")/.env"

# Create .env from example if it doesn't exist yet
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$(dirname "$0")/.env.example" "$ENV_FILE"
fi

NEW_KEY=$(openssl rand -hex 32)

# Replace or append KALI_API_KEY in .env
if grep -q "^KALI_API_KEY=" "$ENV_FILE"; then
    sed -i "s|^KALI_API_KEY=.*|KALI_API_KEY=${NEW_KEY}|" "$ENV_FILE"
else
    echo "KALI_API_KEY=${NEW_KEY}" >> "$ENV_FILE"
fi

echo "New API key: ${NEW_KEY}"
echo "Written to:  ${ENV_FILE}"

# Restart the container if it's running so it picks up the new key
if docker compose -f "$(dirname "$0")/docker-compose.yml" ps --status running | grep -q "kali-api"; then
    echo "Restarting kali-api..."
    docker compose -f "$(dirname "$0")/docker-compose.yml" up -d
    echo "Done."
else
    echo "Container not running — start it with: docker compose up -d --build"
fi
