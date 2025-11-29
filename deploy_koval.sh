#!/bin/bash

set -e

# --- Configuration ---
REGISTRY="registry.k8s.energyhack.cz"
USERNAME="maksym.koval"
PASSWORD="KsVpgRQsXea3CSyCDulU"
PROJECT="nuclear-elephants/galactic-energy-exchange"
PLATFORM=${PLATFORM:-"linux/amd64"} # force AMD64 by default

TAG=${1:-"v1"}
FULL_IMAGE_NAME="$REGISTRY/$PROJECT:$TAG"

echo "--- Starting Deployment for $FULL_IMAGE_NAME ---"

echo "1. Logging in..."
echo "$PASSWORD" | docker login "$REGISTRY" -u "$USERNAME" --password-stdin

echo "2. Preparing buildx builder..."
# создаём билдера, если его ещё нет
if ! docker buildx inspect energyhack-builder >/dev/null 2>&1; then
  docker buildx create --name energyhack-builder --use >/dev/null
else
  docker buildx use energyhack-builder >/dev/null
fi
docker buildx inspect --bootstrap >/dev/null

echo "3. Building and pushing image for platform: $PLATFORM ..."
docker buildx build \
  --platform "$PLATFORM" \
  --provenance=false \
  --sbom=false \
  -t "$FULL_IMAGE_NAME" \
  --push .

echo "--- Success! Deployed $FULL_IMAGE_NAME ---"
