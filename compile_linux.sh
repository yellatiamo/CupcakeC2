#!/usr/bin/env bash
# Cupcake C2 - Linux agent templates → server/assets
# Product features: <transport>,minimal  |  bin: cupcake-agent
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'

PROFILE="${1:-product}"   # product | core

cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)
CLIENT_DIR="$PROJECT_ROOT/Client"
ASSETS_DIR="$PROJECT_ROOT/server/assets"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}    Cupcake C2 - Linux Template Compiler ${NC}"
echo -e "${BLUE}=========================================${NC}"

command -v cargo >/dev/null || { echo -e "${RED}cargo not found${NC}"; exit 1; }

# musl toolchain for static-ish x64
if ! command -v musl-gcc >/dev/null && ! command -v x86_64-linux-musl-gcc >/dev/null; then
  echo -e "${YELLOW}[*] installing musl-tools...${NC}"
  if [[ -f /etc/debian_version ]] || grep -qi 'ubuntu\|debian\|kali' /etc/os-release 2>/dev/null; then
    sudo apt-get update -y
    sudo apt-get install -y musl-tools musl-dev
  elif grep -qi 'centos\|fedora\|rhel' /etc/os-release 2>/dev/null; then
    sudo yum install -y musl musl-devel musl-gcc || true
  else
    echo -e "${RED}install musl-gcc manually${NC}"; exit 1
  fi
fi

if [[ -z "${CUPCAKE_WIRE_SEED:-}" && -f "$PROJECT_ROOT/server/config.json" ]]; then
  CUPCAKE_WIRE_SEED=$(python3 -c "import json;print(json.load(open('server/config.json')).get('wire_seed',''))" 2>/dev/null || true)
  export CUPCAKE_WIRE_SEED
fi
[[ -n "${CUPCAKE_WIRE_SEED:-}" ]] && echo -e "${GREEN}  [OK] wire_seed=$CUPCAKE_WIRE_SEED${NC}"

mkdir -p "$ASSETS_DIR"

find_agent_bin() {
  local target="$1"
  local dir="$CLIENT_DIR/target/$target/release"
  for n in cupcake-agent cupcake-core; do
    [[ -f "$dir/$n" ]] && { echo "$dir/$n"; return 0; }
  done
  return 1
}

build_linux_template() {
  local arch="$1" transport="$2" output_name="$3"
  local target features
  features="${transport},minimal"

  if [[ "$arch" == "x64" ]]; then
    target="x86_64-unknown-linux-musl"
  else
    target="aarch64-unknown-linux-gnu"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    command -v aarch64-linux-gnu-gcc >/dev/null || {
      echo -e "${YELLOW}[*] installing aarch64 cross gcc...${NC}"
      sudo apt-get install -y gcc-aarch64-linux-gnu || true
    }
  fi

  echo -e "${YELLOW}[*] $output_name  features=$features target=$target${NC}"
  rustup target add "$target" >/dev/null 2>&1 || true
  cd "$CLIENT_DIR"
  export RUSTFLAGS="--remap-path-prefix $CLIENT_DIR=."
  cargo build -p cupcake-core --release --target "$target" \
    --no-default-features --features "$features"
  local src
  src=$(find_agent_bin "$target") || { echo -e "${RED}binary missing${NC}"; exit 1; }
  cp "$src" "$ASSETS_DIR/$output_name"
  chmod +x "$ASSETS_DIR/$output_name"
  echo -e "${GREEN}[+] $output_name${NC}"
  cd "$PROJECT_ROOT"
}

echo -e "${YELLOW}[*] profile=$PROFILE${NC}"

case "$PROFILE" in
  core)
    build_linux_template x64 ws client_template_linux
    ;;
  product|all|*)
    build_linux_template x64 ws client_template_linux
    build_linux_template x64 tcp client_template_linux_tcp
    cp -f "$ASSETS_DIR/client_template_linux_tcp" \
          "$ASSETS_DIR/client_template_linux_tcp_minimal"
    build_linux_template x64 dns client_template_linux_dns
    build_linux_template x64 tcp_bind client_template_linux_bind
    build_linux_template arm64 ws client_template_linux_arm64
    ;;
esac

echo -e "${BLUE}-----------------------------------------${NC}"
echo -e "${GREEN}[DONE] Linux templates → $ASSETS_DIR${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"
