#!/usr/bin/env sh
# Sabueso-Framework — instalador para Linux y macOS / installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/Sabueso-Framework/main/install/install.sh | sh
#   sh install/install.sh --with-memory --workspace ~/Casos
#   sh install/install.sh --uninstall
#
# Crea un entorno aislado en ~/.local/share/sabueso, instala el framework y enlaza
# la orden "sabueso" en ~/.local/bin. No necesita root.
# Creates an isolated environment in ~/.local/share/sabueso, installs the framework and
# links the "sabueso" command into ~/.local/bin. No root needed.
set -eu

REPO="Ruby570bocadito/Sabueso-Framework"
PREFIX="${SABUESO_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/sabueso}"
BIN_DIR="${SABUESO_BIN:-$HOME/.local/bin}"
WORKSPACE="$HOME/Sabueso"
SOURCE=""
REF=""
MEMORY=0
UNINSTALL=0

case "${LANG:-}${LC_ALL:-}" in es*|*es_*) ES=1 ;; *) ES=0 ;; esac
say() { if [ "$ES" = 1 ]; then printf '==> %s\n' "$1"; else printf '==> %s\n' "$2"; fi; }
fail() { if [ "$ES" = 1 ]; then printf 'ERROR: %s\n' "$1" >&2; else printf 'ERROR: %s\n' "$2" >&2; fi; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --workspace) WORKSPACE="$2"; shift 2 ;;
        --source) SOURCE="$2"; shift 2 ;;
        --ref) REF="$2"; shift 2 ;;
        --with-memory) MEMORY=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) fail "opción desconocida: $1" "unknown option: $1" ;;
    esac
done

VENV="$PREFIX/venv"

if [ "$UNINSTALL" = 1 ]; then
    say "Desinstalando (los casos no se tocan)…" "Uninstalling (cases are left untouched)…"
    if [ -L "$BIN_DIR/sabueso" ]; then rm -f "$BIN_DIR/sabueso"; fi
    rm -rf "$VENV"
    rmdir "$PREFIX" 2>/dev/null || true
    say "Hecho." "Done."
    exit 0
fi

# -- Python 3.10+ ------------------------------------------------------------------------------
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PYTHON="$(command -v "$candidate")"
        break
    fi
done
[ -n "$PYTHON" ] || fail "se necesita Python 3.10 o superior (p. ej. apt install python3 python3-venv)" \
                        "Python 3.10 or later is required (e.g. apt install python3 python3-venv)"
"$PYTHON" -c 'import venv, ensurepip' 2>/dev/null ||
    fail "falta el módulo venv de Python (Debian/Ubuntu: apt install python3-venv)" \
         "the Python venv module is missing (Debian/Ubuntu: apt install python3-venv)"
say "Python: $PYTHON" "Python: $PYTHON"

# -- source ---------------------------------------------------------------------------------------
if [ -z "$SOURCE" ]; then
    HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
    if [ -n "$HERE" ] && [ -f "$HERE/../pyproject.toml" ]; then
        SOURCE="$(cd "$HERE/.." && pwd)"
    else
        for ref in ${REF:-main}; do
            url="https://github.com/$REPO/archive/refs/heads/$ref.zip"
            if command -v curl >/dev/null 2>&1 && curl -fsIL "$url" >/dev/null 2>&1; then SOURCE="$url"; break; fi
            if command -v wget >/dev/null 2>&1 && wget -q --spider "$url"; then SOURCE="$url"; break; fi
        done
        [ -n "$SOURCE" ] || fail "no se pudo acceder a GitHub ($REPO)" "could not reach GitHub ($REPO)"
    fi
fi
if [ -e "$SOURCE" ]; then
    PACKAGE="$SOURCE"; [ "$MEMORY" = 1 ] && PACKAGE="${SOURCE}[memory]"
else
    PACKAGE="$SOURCE"; [ "$MEMORY" = 1 ] && PACKAGE="sabueso-framework[memory] @ $SOURCE"
fi

# -- environment and package ------------------------------------------------------------------------
say "Creando el entorno en $VENV…" "Creating the environment in $VENV…"
mkdir -p "$PREFIX" "$BIN_DIR" "$WORKSPACE"
[ -x "$VENV/bin/python" ] || "$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip install --disable-pip-version-check --quiet --upgrade pip
say "Instalando Sabueso-Framework desde $SOURCE…" "Installing Sabueso-Framework from $SOURCE…"
"$VENV/bin/python" -m pip install --disable-pip-version-check --upgrade "$PACKAGE" ||
    fail "pip no pudo instalar el paquete (sin ruedas binarias para esta plataforma puede necesitar un compilador: build-essential / Xcode CLT)" \
         "pip could not install the package (without binary wheels for this platform a compiler may be needed: build-essential / Xcode CLT)"

ln -sf "$VENV/bin/sabueso" "$BIN_DIR/sabueso"
CONFIG="$("$VENV/bin/sabueso" config path)"
[ -f "$CONFIG" ] || "$VENV/bin/sabueso" config init --workspace "$WORKSPACE" >/dev/null

say "Comprobando la instalación…" "Checking the installation…"
"$VENV/bin/sabueso" doctor || true
echo
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "Añada $BIN_DIR al PATH, p. ej.: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" \
           "Add $BIN_DIR to PATH, e.g.: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" ;;
esac
say "Listo: sabueso --help · interfaz web: sabueso web --open (casos en $WORKSPACE)" \
    "Done: sabueso --help · web interface: sabueso web --open (cases in $WORKSPACE)"
