#!/usr/bin/env bash
# Cupcake C2 - Server + Frontend (Linux / macOS)
# frontend-v2 → server/web/dist (//go:embed web/dist/*)
# go build ./cmd/server → server/cupcake-server
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'

SKIP_FRONTEND=0
OUTPUT_NAME="cupcake-server"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-frontend) SKIP_FRONTEND=1; shift ;;
    --output) OUTPUT_NAME="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--skip-frontend] [--output name]"
      exit 0
      ;;
    *) echo -e "${RED}unknown arg: $1${NC}"; exit 1 ;;
  esac
done

cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)
SERVER_DIR="$PROJECT_ROOT/server"
FRONTEND_DIR="$SERVER_DIR/frontend-v2"
VITE_OUT="$SERVER_DIR/dist"
EMBED_OUT="$SERVER_DIR/web/dist"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}   Cupcake C2 - Server + Frontend        ${NC}"
echo -e "${BLUE}=========================================${NC}"

command -v go >/dev/null || { echo -e "${RED}Go not found${NC}"; exit 1; }
echo -e "${GREEN}  [OK] $(go version)${NC}"

mkdir -p "$SERVER_DIR/storage/"{payloads,backups,logs,modules} "$SERVER_DIR/assets" "$EMBED_OUT"

if [[ "$SKIP_FRONTEND" -eq 0 ]]; then
  command -v npm >/dev/null || { echo -e "${RED}npm not found${NC}"; exit 1; }
  echo -e "${YELLOW}[*] [1/2] frontend-v2 → web/dist${NC}"
  [[ -d "$FRONTEND_DIR" ]] || { echo -e "${RED}missing $FRONTEND_DIR${NC}"; exit 1; }
  cd "$FRONTEND_DIR"
  if [[ ! -d node_modules ]]; then
    if [[ -f package-lock.json ]]; then npm ci; else npm install; fi
  fi
  npm run build
  cd "$PROJECT_ROOT"
  [[ -f "$VITE_OUT/index.html" ]] || { echo -e "${RED}vite out missing${NC}"; exit 1; }
  rm -rf "$EMBED_OUT"
  mkdir -p "$EMBED_OUT"
  cp -a "$VITE_OUT"/. "$EMBED_OUT"/
  echo -e "${GREEN}  [OK] embed tree: $EMBED_OUT${NC}"
else
  [[ -f "$EMBED_OUT/index.html" ]] || { echo -e "${RED}--skip-frontend but no web/dist${NC}"; exit 1; }
  echo -e "${YELLOW}[*] skip frontend${NC}"
fi

echo -e "${YELLOW}[*] [2/2] go build ./cmd/server → $OUTPUT_NAME${NC}"
cd "$SERVER_DIR"
export CGO_ENABLED=0
go build -ldflags='-s -w' -buildvcs=false -trimpath -o "$OUTPUT_NAME" ./cmd/server
cd "$PROJECT_ROOT"
OUT="$SERVER_DIR/$OUTPUT_NAME"
[[ -f "$OUT" ]] || { echo -e "${RED}missing $OUT${NC}"; exit 1; }
chmod +x "$OUT"
SIZE=$(du -h "$OUT" | cut -f1)
echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}[DONE] $OUT ($SIZE)${NC}"
echo -e "${GREEN}[+] embed: $EMBED_OUT${NC}"
echo -e "${BLUE}=========================================${NC}"
