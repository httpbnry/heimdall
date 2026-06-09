#!/bin/bash
# ==============================================================================
# Heimdall.sh - Plesk Email Password Auditor (Shell version)
#
# Audita contraseñas de cuentas de correo Plesk contra HaveIBeenPwned
# usando k-Anonymity. Sin dependencias externas (usa curl, sha1sum, openssl).
#
# Uso:
#   ./heimdall.sh                      # auditoría en vivo
#   ./heimdall.sh --txt reporte.txt    # guardar reporte
#   ./heimdall.sh --dry-run            # solo consola
# ==============================================================================

set -euo pipefail

# ── Configuración ──────────────────────────────────────────────────────────

readonly HIBP_API_URL="https://api.pwnedpasswords.com/range/"
readonly MAIL_AUTH_VIEW="/usr/psa/admin/sbin/mail_auth_view"
readonly RATE_LIMIT=1.5            # segundos entre peticiones HIBP
readonly HIBP_TIMEOUT=10           # timeout curl en segundos
readonly VERSION="1.0.0"

# Colores ANSI
readonly RED='\033[0;91m'
readonly GREEN='\033[0;92m'
readonly YELLOW='\033[0;93m'
readonly CYAN='\033[0;96m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Contadores globales
TOTAL=0
COMPROMISED=0
ERRORS=0
REPORT_LINES=()


# ── Funciones auxiliares ────────────────────────────────────────────────────

usage() {
    echo -e "${BOLD}Heimdall.sh${NC} - Plesk Email Password Auditor v${VERSION}"
    echo ""
    echo -e "${BOLD}Uso:${NC}"
    echo -e "  $(basename "$0")                         Auditoría en vivo (consola)"
    echo -e "  $(basename "$0") --txt <archivo>         Auditoría + reporte .txt"
    echo -e "  $(basename "$0") --dry-run               Solo consola, sin guardar"
    echo -e "  $(basename "$0") -h                      Esta ayuda"
    echo ""
    echo -e "${BOLD}Ejemplos:${NC}"
    echo -e "  $(basename "$0") --txt /var/log/heimdall/mensual.txt"
    echo -e "  $(basename "$0") --dry-run"
    exit 0
}


log() {
    local level="$1" msg="$2"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${level} ${msg}" >&2
}


die() {
    log "${RED}FATAL${NC}" "$1"
    exit 1
}


# ── 1. Extraer cuentas ─────────────────────────────────────────────────────

extract_accounts() {
    if [[ ! -x "$MAIL_AUTH_VIEW" ]]; then
        die "No se encuentra $MAIL_AUTH_VIEW. ¿Esto es un servidor Plesk?"
    fi

    "$MAIL_AUTH_VIEW" 2>/dev/null || die "$MAIL_AUTH_VIEW falló (código $?)"
}


# ── 2. SHA-1 + HIBP k-Anonymity ───────────────────────────────────────────

sha1_hex() {
    local password="$1"
    # Preferimos openssl por disponibilidad; fallback a sha1sum
    if command -v openssl &>/dev/null; then
        printf '%s' "$password" | openssl dgst -sha1 | cut -d' ' -f2 | tr 'a-f' 'A-F'
    elif command -v sha1sum &>/dev/null; then
        printf '%s' "$password" | sha1sum | cut -d' ' -f1 | tr 'a-f' 'A-F'
    else
        die "No se encontró openssl ni sha1sum para calcular SHA-1"
    fi
}


check_hibp() {
    local password="$1"
    local full_hash prefix suffix resp

    full_hash=$(sha1_hex "$password")
    prefix="${full_hash:0:5}"
    suffix="${full_hash:5}"

    sleep "$RATE_LIMIT"

    resp=$(curl -sS --max-time "$HIBP_TIMEOUT" \
                -A "Heimdall-Plesk-Auditor/${VERSION}" \
                "${HIBP_API_URL}${prefix}" 2>/dev/null) || {
        echo "ERROR|${full_hash}"
        return
    }

    while IFS=: read -r returned_suffix count_str; do
        returned_suffix=$(echo "$returned_suffix" | tr 'a-f' 'A-F' | xargs)
        if [[ "$returned_suffix" == "$suffix" ]]; then
            echo "COMPROMISED|${full_hash}|${count_str}"
            return
        fi
    done <<< "$resp"

    echo "SAFE|${full_hash}|0"
}


# ── 3. Banner ──────────────────────────────────────────────────────────────

print_banner() {
    echo ""
    echo -e "  ${CYAN}╔════════════════════════════════════╗${NC}"
    echo -e "  ${CYAN}║     ${BOLD}Heimdall${NC}${CYAN} - Plesk Auditor     ║${NC}"
    echo -e "  ${CYAN}║     v${VERSION}                         ║${NC}"
    echo -e "  ${CYAN}╚════════════════════════════════════╝${NC}"
    echo ""
}


# ── 4. Reporte .txt ────────────────────────────────────────────────────────

build_report_txt() {
    local fecha
    fecha=$(date '+%Y-%m-%d %H:%M:%S')
    local report=()
    report+=("============================================================")
    report+=("Heimdall - Reporte de auditoría ($fecha)")
    report+=("============================================================")
    report+=("")

    if (( COMPROMISED == 0 )); then
        report+=("[OK] Ninguna contraseña comprometida encontrada.")
    else
        report+=("[!] ${COMPROMISED} cuenta(s) COMPROMETIDA(S):")
        report+=("")
        for entry in "${REPORT_LINES[@]}"; do
            IFS='|' read -r tipo email hash ocurrencias <<< "$entry"
            if [[ "$tipo" == "COMPROMISED" ]]; then
                report+=("  - $email")
                report+=("    Hash SHA-1: $hash")
                report+=("    Filtrada ${ocurrencias} vez/veces")
                report+=("")
            fi
        done
    fi

    if (( ERRORS > 0 )); then
        report+=("[?] ${ERRORS} error(es) durante la auditoría:")
        for entry in "${REPORT_LINES[@]}"; do
            IFS='|' read -r tipo email hash ocurrencias <<< "$entry"
            if [[ "$tipo" == "ERROR" ]]; then
                report+=("  - $email")
            fi
        done
        report+=("")
    fi

    report+=("Resumen: ${TOTAL} auditadas | ${COMPROMISED} comprometidas | ${ERRORS} errores")

    printf '%s\n' "${report[@]}"
}


save_report() {
    local file="$1"
    local dir
    dir=$(dirname "$file")

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" 2>/dev/null || die "No se pudo crear el directorio $dir"
    fi

    build_report_txt > "$file"
    echo -e "\n  ${CYAN}Reporte guardado: ${file}${NC}"
}


# ── Main ───────────────────────────────────────────────────────────────────

main() {
    local txt_output="" accounts line email password result status hash ocurrencias

    # Parsear argumentos
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage ;;
            --txt)     txt_output="$2"; shift 2 ;;
            --dry-run) txt_output=""; shift ;;
            *)         echo "Opción desconocida: $1"; usage ;;
        esac
    done

    print_banner

    # Extraer cuentas
    accounts=$(extract_accounts) || exit 1

    if [[ -z "$accounts" ]]; then
        echo -e "  ${YELLOW}No hay cuentas de correo que auditar.${NC}"
        echo ""
        exit 0
    fi

    TOTAL=$(echo "$accounts" | wc -l)
    echo -e "  Auditando ${BOLD}${TOTAL}${NC} cuenta(s)...\n"

    i=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        # Saltar líneas que no tengan formato email:password
        if [[ "$line" != *@*:* ]]; then
            log "${YELLOW}WARN${NC}" "Línea ignorada (formato inesperado): ${line:0:80}"
            continue
        fi

        # Extraer email y password
        email="${line%%:*}"
        password="${line#*:}"

        # Quitar posibles espacios alrededor
        email=$(echo "$email" | xargs)
        password=$(echo "$password" | xargs)

        ((i++))
        printf "  [%d/%d] %-40s " "$i" "$TOTAL" "$email"

        result=$(check_hibp "$password") || true

        # Parsear resultado: STATUS|HASH|COUNT
        status="${result%%|*}"
        rest="${result#*|}"
        hash="${rest%%|*}"
        ocurrencias="${rest#*|}"

        case "$status" in
            COMPROMISED)
                echo -e "${RED}[COMPROMISIDA] (filtrada ${ocurrencias}x)${NC}"
                ((COMPROMISED++))
                REPORT_LINES+=("COMPROMISED|${email}|${hash}|${ocurrencias}")
                ;;
            SAFE)
                echo -e "${GREEN}[SEGURA]${NC}"
                REPORT_LINES+=("SAFE|${email}|${hash}|0")
                ;;
            ERROR|*)
                echo -e "${YELLOW}[ERROR]${NC}"
                ((ERRORS++))
                REPORT_LINES+=("ERROR|${email}|||")
                ;;
        esac

    done <<< "$accounts"

    # Resumen
    local safe=$(( TOTAL - COMPROMISED - ERRORS ))
    echo ""
    echo -e "  ${BOLD}==================================================${NC}"
    echo -e "   Total          : ${TOTAL}"
    echo -e "   Seguras        : ${GREEN}${safe}${NC}"
    echo -e "   Comprometidas  : ${RED}${COMPROMISED}${NC}"
    echo -e "   Errores        : ${YELLOW}${ERRORS}${NC}"
    echo -e "  ${BOLD}==================================================${NC}"
    echo ""

    # Guardar reporte si se indicó
    if [[ -n "$txt_output" ]]; then
        save_report "$txt_output"
    fi

    exit $(( COMPROMISED > 0 ? 2 : 0 ))
}


main "$@"
