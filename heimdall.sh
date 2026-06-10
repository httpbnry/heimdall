#!/bin/bash
# ==============================================================================
# Heimdall.sh — Plesk Email Password Auditor
# Optimizado: agrupa por prefijo SHA-1, 1 llamada API por prefijo.
# Sin dependencias: curl + openssl/sha1sum.
# ==============================================================================

set -euo pipefail

readonly HIBP_API_URL="https://api.pwnedpasswords.com/range/"
readonly MAIL_AUTH_VIEW_PATHS=(
    /usr/local/psa/admin/sbin/mail_auth_view
    /usr/psa/admin/sbin/mail_auth_view
)
readonly RATE_LIMIT=1.5
readonly HIBP_TIMEOUT=10
readonly VERSION="2.0"

RED='\033[0;91m'; GREEN='\033[0;92m'; YELLOW='\033[0;93m'
CYAN='\033[0;96m'; BOLD='\033[1m'; NC='\033[0m'


usage() {
    echo -e "${BOLD}Heimdall.sh${NC} v${VERSION} — Plesk Password Auditor"
    echo ""
    echo -e "${BOLD}Uso:${NC}"
    echo -e "  $(basename "$0")                              Auditoría en vivo"
    echo -e "  $(basename "$0") --txt <archivo>              + reporte .txt"
    echo -e "  $(basename "$0") --from-file cuentas.txt      Desde archivo plano"
    echo -e "  $(basename "$0") --dry-run                    Solo consola"
    echo -e "  $(basename "$0") -h                           Ayuda"
    exit 0
}


log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1 $2" >&2; }
die() { log "${RED}FATAL${NC}" "$1"; exit 1; }

PSA_SQLITE_PATHS=(
    /usr/local/psa/admin/conf/psa.db
    /usr/local/psa/var/psa.db
    /opt/psa/admin/conf/psa.db
)


# Intenta extraer email y password de una línea (formato pipe table)
parse_mail_line() {
    local line="$1" email password
    line="${line#"${line%%[![:space:]]*}"}"  # trim leading
    line="${line%"${line##*[![:space:]]}"}"   # trim trailing

    # Saltar cabeceras: guiones, address, flags
    [[ -z "$line" || "$line" == "-"* ]] && return 1
    [[ "$line" == *"address"* || "$line" == *"flags"* ]] && return 1

    # Formato tabla con pipes: | email | flags | password |
    if [[ "$line" == *"|"* ]]; then
        local IFS='|'
        local -a parts=($line)
        unset IFS
        # Limpiar espacios
        local cleaned=()
        for p in "${parts[@]}"; do
            p="${p#"${p%%[![:space:]]*}"}"; p="${p%"${p##*[![:space:]]}"}"
            [[ -n "$p" ]] && cleaned+=("$p")
        done
        if [[ "${#cleaned[@]}" -ge 3 && "${cleaned[0]}" == *@* ]]; then
            email="${cleaned[0]}"
            password="${cleaned[2]}"
            [[ -n "$password" ]] && { echo "$email|$password"; return 0; }
        fi
    fi

    # Formato email:password
    if [[ "$line" =~ ^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(.+)$ ]]; then
        email="${BASH_REMATCH[1]}"
        password="${BASH_REMATCH[2]}"
        [[ -n "$password" ]] && { echo "$email|$password"; return 0; }
    fi
    return 1
}


sha1_hex() {
    if command -v openssl &>/dev/null; then
        printf '%s' "$1" | openssl dgst -sha1 | cut -d' ' -f2 | tr 'a-f' 'A-F'
    elif command -v sha1sum &>/dev/null; then
        printf '%s' "$1" | sha1sum | cut -d' ' -f1 | tr 'a-f' 'A-F'
    else
        die "No hay openssl ni sha1sum"
    fi
}


# Intenta extraer cuentas desde SQLite (Plesk sin MySQL)
extract_sqlite() {
    local db=""
    for p in "${PSA_SQLITE_PATHS[@]}"; do
        [[ -f "$p" ]] && { db="$p"; break; }
    done
    [[ -z "$db" ]] && return 1
    command -v sqlite3 &>/dev/null || return 1

    # Intentar mail_auth_view primero (devuelve texto plano)
    local has_view
    has_view=$(sqlite3 "$db" "SELECT name FROM sqlite_master WHERE type='view' AND name='mail_auth_view';" 2>/dev/null)
    if [[ -n "$has_view" ]]; then
        sqlite3 -separator ': ' "$db" "SELECT mail_name || '@' || domain_id, password FROM mail_auth_view WHERE password IS NOT NULL AND password != '';" 2>/dev/null && return 0
    fi

    # Fallback: tabla mail + domains
    sqlite3 -separator ': ' "$db" "SELECT m.mail_name || '@' || d.name, m.password FROM mail m JOIN domains d ON m.domain_id = d.id WHERE m.password IS NOT NULL AND m.password != '';" 2>/dev/null && return 0

    return 1
}


fetch_prefix() {
    sleep "$RATE_LIMIT"
    curl -sS --max-time "$HIBP_TIMEOUT" --connect-timeout 5 \
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
    local txt_output="" from_file="" prefix suffix email password hash line
    local total_prefixes prefix_count=0 total=0 unicas=0 comp=0 errs=0 duplicados=0
    local hash_file report_file cur_prefix

    while [[ $# -gt 0 ]]; do
        case "$1" in -h|--help) usage ;;
            --txt) txt_output="$2"; shift 2 ;;
            --from-file) from_file="$2"; shift 2 ;;
            --dry-run) txt_output=""; shift ;;
            *) die "Opción: $1" ;;
        esac
    done

    print_banner

    hash_file=$(mktemp); report_file=$(mktemp)
    trap "rm -f $hash_file $report_file" EXIT

    # Fase 1: extraer cuentas
    if [[ -n "$from_file" ]]; then
        [[ -f "$from_file" ]] || die "Archivo no encontrado: $from_file"
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            parsed=$(parse_mail_line "$line") || continue
            IFS='|' read -r email password <<< "$parsed"
            hash=$(sha1_hex "$password")
            echo "${hash:0:5}|${hash:5}|$email" >> "$hash_file"
        done < "$from_file"
    else
        # Intentar SQLite primero
        local sqlite_out
        sqlite_out=$(mktemp); trap "rm -f $sqlite_out $hash_file $report_file" EXIT
        if extract_sqlite > "$sqlite_out" 2>/dev/null && [[ -s "$sqlite_out" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                parsed=$(parse_mail_line "$line") || continue
                IFS='|' read -r email password <<< "$parsed"
                hash=$(sha1_hex "$password")
                echo "${hash:0:5}|${hash:5}|$email" >> "$hash_file"
            done < "$sqlite_out"
            rm -f "$sqlite_out"
        else
            rm -f "$sqlite_out"
            local mail_bin=""
            for p in "${MAIL_AUTH_VIEW_PATHS[@]}"; do
                [[ -f "$p" ]] && { mail_bin="$p"; break; }
            done
            if [[ -z "$mail_bin" ]]; then
                die "No encontrado: ningún ${MAIL_AUTH_VIEW_PATHS[*]} ni BD SQLite. Usa --from-file."
            fi
            if ! [[ -x "$mail_bin" ]]; then
                echo -e "  ${YELLOW}[!] $mail_bin existe pero no es ejecutable${NC}"
                echo -e "  Ejecuta: sudo chmod +x $mail_bin"
                echo -e "  O usa:  heimdall.sh --from-file cuentas.txt\n"
                die "Permiso denegado"
            fi
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                parsed=$(parse_mail_line "$line") || { log "${YELLOW}WARN${NC}" "Línea no parseable: ${line:0:80}"; continue; }
                IFS='|' read -r email password <<< "$parsed"
                hash=$(sha1_hex "$password")
                echo "${hash:0:5}|${hash:5}|$email" >> "$hash_file"
            done < <("$mail_bin" 2>&1 || die "$mail_bin falló (exit code $?)")
        fi
    fi

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

    echo -e "  ${BOLD}${total}${NC} cuentas · ${BOLD}${unicas}${NC} únicas · ${BOLD}${total_prefixes}${NC} prefijos"
    echo ""

    # Fase 2: agrupar por prefijo y procesar cada grupo
    prefix_count=0
    local -a comprometidas_emails=()
    while IFS= read -r prefix; do
        [[ -z "$prefix" ]] && continue
        prefix_count=$(( prefix_count + 1 ))

        local entries buf
        entries=$(grep "^${prefix}|" "$dedup_file" || true)

        local -a emails=() suffixes=()
        while IFS='|' read -r _ s e; do
            suffixes+=("$s"); emails+=("$e")
        done <<< "$entries"
        [[ "${#emails[@]}" -eq 0 ]] && continue

        # Mostrar cada cuenta de este prefijo
        echo ""
        echo -e "  ${BOLD}-- [{prefix_count}/${total_prefixes}] Prefijo ${prefix} (${#emails[@]} pwd)${NC}"
        for i in "${!emails[@]}"; do
            e="${emails[$i]}"
            echo "    ${e}"
        done
        printf "    Consultando HIBP ... "

        buf=$(fetch_prefix "$prefix") || true
        if [[ -z "$buf" ]]; then
            echo -e "${RED}ERROR${NC}"
            for i in "${!emails[@]}"; do
                echo "ERROR|${emails[$i]}|${prefix}${suffixes[$i]}" >> "$report_file"
                errs=$(( errs + 1 ))
            done
            continue
        fi
        echo -e "${GREEN}OK${NC}"

        unset __cmap 2>/dev/null || true; declare -A __cmap
        while IFS=: read -r s c; do
            s=$(echo "$s" | tr 'a-f' 'A-F' | xargs)
            __cmap["$s"]="$c"
        done <<< "$buf"

        for i in "${!emails[@]}"; do
            s="${suffixes[$i]}"; e="${emails[$i]}"
            if [[ -n "${__cmap[$s]:-}" ]]; then
                echo "COMPROMISED|${e}|${prefix}${s}|${__cmap[$s]}" >> "$report_file"
                comp=$(( comp + 1 ))
                comprometidas_emails+=("$e")
                echo -e "    ${RED}⚠ COMPROMETIDA: ${e} (filtrada ${__cmap[$s]}x)${NC}"
            else
                echo "SAFE|${e}|${prefix}${s}|0" >> "$report_file"
            fi
        done
        echo ""
    done < <(cut -d'|' -f1 "$dedup_file" | sort -u)

    # Resumen
    safe=$(( total - comp - errs ))
    echo ""
    echo -e "  ${BOLD}==================================================${NC}"
    echo -e "  Total     : ${total}"
    echo -e "  Seguras   : ${GREEN}${safe}${NC}"
    echo -e "  Comprometidas : ${RED}${comp}${NC}"
    echo -e "  Errores   : ${YELLOW}${errs}${NC}"
    echo -e "  ${BOLD}==================================================${NC}"
    echo ""

    if (( ${#comprometidas_emails[@]} > 0 )); then
        echo -e "  ${RED}Cuentas comprometidas:${NC}"
        for email in "${comprometidas_emails[@]}"; do
            echo "    - $email"
        done
        echo ""
    fi

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
