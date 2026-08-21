#!/usr/bin/env bash
# Cupcake C2 - Windows agent templates (Linux cross-compile via mingw)
# Product features: <transport>,minimal  |  bin: cupcake-agent.exe
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'

PROFILE="${1:-product}"   # product | core

cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)
CLIENT_DIR="$PROJECT_ROOT/Client"
ASSETS_DIR="$PROJECT_ROOT/server/assets"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}   Cupcake C2 - Windows Cross-Compiler   ${NC}"
echo -e "${BLUE}=========================================${NC}"

command -v cargo >/dev/null || { echo -e "${RED}cargo not found${NC}"; exit 1; }

if ! command -v x86_64-w64-mingw32-gcc >/dev/null; then
  echo -e "${YELLOW}[*] installing mingw-w64...${NC}"
  sudo apt-get update && sudo apt-get install -y gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
fi

mkdir -p "$ASSETS_DIR"

# Prefer config.json / env wire seed
if [[ -z "${CUPCAKE_WIRE_SEED:-}" && -f "$PROJECT_ROOT/server/config.json" ]]; then
  CUPCAKE_WIRE_SEED=$(python3 -c "import json;print(json.load(open('server/config.json')).get('wire_seed',''))" 2>/dev/null || true)
  export CUPCAKE_WIRE_SEED
fi
[[ -n "${CUPCAKE_WIRE_SEED:-}" ]] && echo -e "${GREEN}  [OK] wire_seed=$CUPCAKE_WIRE_SEED${NC}"

find_agent_bin() {
  local target="$1"
  local dir="$CLIENT_DIR/target/$target/release"
  for n in cupcake-agent.exe cupcake-core.exe; do
    [[ -f "$dir/$n" ]] && { echo "$dir/$n"; return 0; }
  done
  return 1
}

build_windows_template() {
  local arch="$1" transport="$2" output_name="$3"
  local target features
  if [[ "$arch" == "x64" ]]; then
    target="x86_64-pc-windows-gnu"
  else
    target="i686-pc-windows-gnu"
    command -v i686-w64-mingw32-gcc >/dev/null || sudo apt-get install -y gcc-mingw-w64-i686 g++-mingw-w64-i686
  fi
  features="${transport},minimal"
  echo -e "${YELLOW}[*] $output_name  features=$features${NC}"
  rustup target add "$target" >/dev/null 2>&1 || true
  cd "$CLIENT_DIR"
  export RUSTFLAGS="--remap-path-prefix $CLIENT_DIR=."
  cargo build -p cupcake-core --release --target "$target" \
    --no-default-features --features "$features"
  local src
  src=$(find_agent_bin "$target") || { echo -e "${RED}binary missing${NC}"; exit 1; }
  cp "$src" "$ASSETS_DIR/$output_name"
  echo -e "${GREEN}[+] $output_name${NC}"
  cd "$PROJECT_ROOT"
}

echo -e "${YELLOW}[*] profile=$PROFILE${NC}"

case "$PROFILE" in
  core)
    build_windows_template x64 ws client_template_windows.exe
    ;;
  product|all|*)
    build_windows_template x64 ws client_template_windows.exe
    build_windows_template x86 ws client_template_windows_x86.exe
    build_windows_template x64 tcp client_template_windows_tcp.exe
    cp -f "$ASSETS_DIR/client_template_windows_tcp.exe" \
          "$ASSETS_DIR/client_template_windows_tcp_minimal.exe"
    build_windows_template x64 tcp_bind client_template_windows_bind.exe
    build_windows_template x64 dns client_template_windows_dns.exe
    ;;
esac

echo -e "${BLUE}-----------------------------------------${NC}"
echo -e "${GREEN}[DONE] Windows templates → $ASSETS_DIR${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"
