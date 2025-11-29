#!/bin/bash

set -e

# --- Configuration ---
REGISTRY="registry.k8s.energyhack.cz"
USERNAME="maksym.koval"
PASSWORD="KsVpgRQsXea3CSyCDulU"
PROJECT="nuclear-elephants/galactic-energy-exchange"

TAG=${1:-"v1"}
FULL_IMAGE_NAME="$REGISTRY/$PROJECT:$TAG"

echo "--- Starting Deployment for $FULL_IMAGE_NAME ---"

echo "1. Logging in..."
echo "$PASSWORD" | docker login "$REGISTRY" -u "$USERNAME" --password-stdin

echo "2. Preparing buildx builder..."
# создаём билдера, если его ещё нет
docker buildx create --name energyhack-builder --use >/dev/null 2>&1 || docker buildx use energyhack-builder
docker buildx inspect >/dev/null 2>&1 || docker buildx inspect --bootstrap

echo "3. Building and pushing multi-arch image..."
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "$FULL_IMAGE_NAME" \
  --push .

echo "--- Success! Deployed $FULL_IMAGE_NAME ---"
