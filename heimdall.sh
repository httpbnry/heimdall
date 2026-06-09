#!/bin/bash
# ==============================================================================
# Heimdall.sh — Plesk Email Password Auditor
# Optimizado: agrupa por prefijo SHA-1, 1 llamada API por prefijo.
# Sin dependencias: curl + openssl/sha1sum.
# ==============================================================================

set -euo pipefail

readonly HIBP_API_URL="https://api.pwnedpasswords.com/range/"
readonly MAIL_AUTH_VIEW="/usr/psa/admin/sbin/mail_auth_view"
readonly RATE_LIMIT=1.5
readonly HIBP_TIMEOUT=10
readonly VERSION="2.0"

RED='\033[0;91m'; GREEN='\033[0;92m'; YELLOW='\033[0;93m'
CYAN='\033[0;96m'; BOLD='\033[1m'; NC='\033[0m'


usage() {
    echo -e "${BOLD}Heimdall.sh${NC} v${VERSION} — Plesk Password Auditor"
    echo ""
    echo -e "${BOLD}Uso:${NC}"
    echo -e "  $(basename "$0")                         Auditoría en vivo"
    echo -e "  $(basename "$0") --txt <archivo>         + reporte .txt"
    echo -e "  $(basename "$0") --dry-run               Solo consola"
    echo -e "  $(basename "$0") -h                      Ayuda"
    exit 0
}


die() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}FATAL${NC} $1" >&2; exit 1; }


sha1_hex() {
    if command -v openssl &>/dev/null; then
        printf '%s' "$1" | openssl dgst -sha1 | cut -d' ' -f2 | tr 'a-f' 'A-F'
    elif command -v sha1sum &>/dev/null; then
        printf '%s' "$1" | sha1sum | cut -d' ' -f1 | tr 'a-f' 'A-F'
    else
        die "No hay openssl ni sha1sum"
    fi
}


fetch_prefix() {
    sleep "$RATE_LIMIT"
    curl -sS --max-time "$HIBP_TIMEOUT" \
         -A "Heimdall-Plesk-Auditor/${VERSION}" \
         "${HIBP_API_URL}${1}" 2>/dev/null || echo ""
}


print_banner() {
    echo ""
    echo -e "  ${CYAN}╔════════════════════════════════════╗${NC}"
    echo -e "  ${CYAN}║     ${BOLD}Heimdall${NC}${CYAN} — Plesk Auditor     ║${NC}"
    echo -e "  ${CYAN}║     v${VERSION}                         ║${NC}"
    echo -e "  ${CYAN}╚════════════════════════════════════╝${NC}"
    echo ""
}


main() {
    local txt_output="" prefix suffix email password hash line
    local total_prefixes prefix_count=0 total=0 unicas=0 comp=0 errs=0 duplicados=0
    local hash_file report_file cur_prefix

    while [[ $# -gt 0 ]]; do
        case "$1" in -h|--help) usage ;;
            --txt) txt_output="$2"; shift 2 ;;
            --dry-run) txt_output=""; shift ;;
            *) die "Opción: $1" ;;
        esac
    done

    print_banner
    [[ -x "$MAIL_AUTH_VIEW" ]] || die "No encontrado: $MAIL_AUTH_VIEW"

    hash_file=$(mktemp); report_file=$(mktemp)
    trap "rm -f $hash_file $report_file" EXIT

    # Fase 1: extraer cuentas y calcular hash SHA-1
    while IFS= read -r line; do
        [[ -z "$line" || "$line" != *@*:* ]] && continue
        email="${line%%:*}"
        password="${line#*:}"
        email=$(echo "$email" | xargs)
        password=$(echo "$password" | xargs)
        [[ -z "$password" ]] && continue
        hash=$(sha1_hex "$password")
        echo "${hash:0:5}|${hash:5}|$email" >> "$hash_file"
    done < <("$MAIL_AUTH_VIEW" 2>/dev/null || die "$MAIL_AUTH_VIEW falló")

    total=$(wc -l < "$hash_file")
    [[ "$total" -eq 0 ]] && { echo -e "  ${YELLOW}Sin cuentas.${NC}\n"; exit 0; }

    # Deduplicar por hash completo
    local dedup_file
    dedup_file=$(mktemp); trap "rm -f $dedup_file $hash_file $report_file" EXIT
    sort -t'|' -k1,2 -u "$hash_file" > "$dedup_file"
    unicas=$(wc -l < "$dedup_file")
    duplicados=$(( total - unicas ))

    # Agrupar por prefijo
    total_prefixes=$(cut -d'|' -f1 "$dedup_file" | sort -u | wc -l)

    echo -e "  Cuentas: ${BOLD}${total}${NC} | Únicas: ${BOLD}${unicas}${NC} | Prefijos: ${BOLD}${total_prefixes}${NC} | Ahorro: ${GREEN}$(( duplicados + (unicas - total_prefixes) )) llamadas${NC}"
    echo ""

    cur_prefix=""
    prefix_count=0
    # Variables para acumular entradas del prefijo actual
    declare -a cur_emails=()
    declare -a cur_suffixes=()

    flush_prefix() {
        local resp s count_line srv c found
        [[ -z "$cur_prefix" ]] && return
        ((prefix_count++))
        printf "  [%d/%d] Prefijo %s (%d pwd) ... " "$prefix_count" "$total_prefixes" "$cur_prefix" "${#cur_suffixes[@]}"

        resp=$(fetch_prefix "$cur_prefix")
        if [[ -z "$resp" ]]; then
            echo -e "${RED}ERROR${NC}"
            for i in "${!cur_suffixes[@]}"; do
                echo "ERROR|${cur_emails[$i]}|${cur_prefix}${cur_suffixes[$i]}" >> "$report_file"
                ((errs++))
            done
            return
        fi
        echo -e "${GREEN}OK${NC}"

        # Construir array asociativo de comprometidos
        declare -A cmap
        while IFS=: read -r s c; do
            s=$(echo "$s" | tr 'a-f' 'A-F' | xargs)
            cmap["$s"]="$c"
        done <<< "$resp"

        for i in "${!cur_suffixes[@]}"; do
            s="${cur_suffixes[$i]}"
            e="${cur_emails[$i]}"
            if [[ -n "${cmap[$s]:-}" ]]; then
                echo "COMPROMISED|$e|${cur_prefix}${s}|${cmap[$s]}" >> "$report_file"
                ((comp++))
            else
                echo "SAFE|$e|${cur_prefix}${s}|0" >> "$report_file"
            fi
        done

        cur_prefix=""
        cur_emails=()
        cur_suffixes=()
    }

    # Procesar líneas ordenadas por prefijo
    while IFS='|' read -r prefix suffix email; do
        if [[ "$prefix" != "$cur_prefix" && -n "$cur_prefix" ]]; then
            flush_prefix
        fi
        cur_prefix="$prefix"
        cur_emails+=("$email")
        cur_suffixes+=("$suffix")
    done < <(sort -t'|' -k1,1 -k2,2 "$dedup_file")

    # Último prefijo
    flush_prefix

    # Resumen
    safe=$(( total - comp - errs ))
    echo ""
    echo -e "  ${BOLD}==================================================${NC}"
    echo -e "   Cuentas        : ${total}"
    echo -e "   Únicas         : ${unicas}"
    echo -e "   Prefijos API   : ${total_prefixes}  (ahorro: ${GREEN}$(( duplicados + (unicas - total_prefixes) ))${NC})"
    echo -e "   Seguras        : ${GREEN}${safe}${NC}"
    echo -e "   Comprometidas  : ${RED}${comp}${NC}"
    echo -e "   Errores        : ${YELLOW}${errs}${NC}"
    echo -e "  ${BOLD}==================================================${NC}"
    echo ""

    # Reporte .txt
    if [[ -n "$txt_output" ]]; then
        local dir
        dir=$(dirname "$txt_output")
        [[ "$dir" != "." ]] && mkdir -p "$dir" 2>/dev/null || true
        {
            echo "============================================================"
            echo "Heimdall - Reporte ($(date '+%Y-%m-%d %H:%M:%S'))"
            echo "============================================================"
            echo ""
            if (( comp == 0 )); then
                echo "[OK] 0 comprometidas."
            else
                echo "[!] ${comp} comprometida(s):"
                echo ""
                while IFS='|' read -r tipo email hash_full ocurrencias; do
                    [[ "$tipo" != "COMPROMISED" ]] && continue
                    echo "  - $email"
                    echo "    SHA-1: $hash_full"
                    echo "    Filtrada ${ocurrencias}x"
                    echo ""
                done < "$report_file"
            fi
            if (( errs > 0 )); then
                echo "[?] ${errs} error(es):"
                while IFS='|' read -r tipo email hash_full; do
                    [[ "$tipo" != "ERROR" ]] && continue
                    echo "  - $email"
                done < "$report_file"
                echo ""
            fi
            echo "Total: ${total} | Comp: ${comp} | Err: ${errs}"
        } > "$txt_output"
        echo -e "  ${CYAN}Reporte: ${txt_output}${NC}"
        echo ""
    fi

    exit $(( comp > 0 ? 2 : 0 ))
}


main "$@"
