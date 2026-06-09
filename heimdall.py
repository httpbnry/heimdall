#!/usr/bin/env python3
"""
Heimdall - Plesk Email Password Auditor
Audita contraseñas de cuentas de correo Plesk contra HaveIBeenPwned (k-Anonymity).
Usa /usr/psa/admin/sbin/mail_auth_view para extraer datos. Sin dependencia de BD.
Resultado en consola + archivo .txt. Diseñado para ejecución mensual vía cron.
"""

import os
import sys
import re
import time
import hashlib
import logging
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

import requests
from dotenv import load_dotenv


HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
MAIL_AUTH_VIEW = "/usr/psa/admin/sbin/mail_auth_view"
DEFAULT_RATE_LIMIT = 1.5
DEFAULT_HIBP_TIMEOUT = 10
SCRIPT_DIR = Path(__file__).parent.resolve()
ENV_PATH = SCRIPT_DIR / ".env"

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_RESET = "\033[0m"

# Regex para líneas tipo: usuario@dominio.com:contraseña
LINE_RE = re.compile(r"^([^@]+@[^:]+):(.+)$")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_config() -> dict:
    load_dotenv(dotenv_path=ENV_PATH if ENV_PATH.exists() else None)

    def env(key: str, default: str = "") -> str:
        return os.environ.get(key, default)

    return {
        "hibp_rate_limit": float(env("HIBP_RATE_LIMIT", str(DEFAULT_RATE_LIMIT))),
    }


# ── 1. Extraer cuentas vía mail_auth_view ─────────────────────────


def extract_mail_accounts() -> list[dict]:
    if not Path(MAIL_AUTH_VIEW).exists():
        raise RuntimeError(f"No se encuentra {MAIL_AUTH_VIEW}. ¿Esto es un servidor Plesk?")

    try:
        result = subprocess.run(
            [MAIL_AUTH_VIEW],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as e:
        raise RuntimeError(f"No se pudo ejecutar {MAIL_AUTH_VIEW}: {e}") from e
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{MAIL_AUTH_VIEW} no respondió en 30s")

    if result.returncode != 0:
        raise RuntimeError(
            f"{MAIL_AUTH_VIEW} terminó con código {result.returncode}: "
            f"{result.stderr.strip()}"
        )

    accounts = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if m:
            email, password = m.group(1), m.group(2)
            if password:
                accounts.append({"email": email, "password": password})
        else:
            logging.warning("Línea no parseable (formato inesperado): %s", line[:80])

    logging.info("Extraídas %d cuentas de %s", len(accounts), MAIL_AUTH_VIEW)
    return accounts


# ── 2. HIBP k-Anonymity ───────────────────────────────────────────


def _sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_hibp(password: str, rate_limit: float) -> dict:
    full_hash = _sha1_hex(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    time.sleep(rate_limit)

    try:
        resp = requests.get(
            HIBP_API_URL + prefix,
            timeout=DEFAULT_HIBP_TIMEOUT,
            headers={"User-Agent": "Heimdall-Plesk-Auditor/1.0"},
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        return {"compromised": False, "error": str(e), "hash": full_hash}

    for line in resp.text.splitlines():
        if ":" in line:
            returned_suffix, count_str = line.split(":", 1)
            if returned_suffix.strip().upper() == suffix:
                return {"compromised": True, "occurrences": int(count_str), "hash": full_hash}

    return {"compromised": False, "occurrences": 0, "hash": full_hash}


# ── 3. Reporte .txt ──────────────────────────────────────────────


def guardar_reporte_txt(reporte: list[dict], ruta: str):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lineas = []
    lineas.append("=" * 60)
    lineas.append(f"Heimdall - Reporte de auditoría ({fecha})")
    lineas.append("=" * 60)
    lineas.append("")

    comprometidas = [r for r in reporte if r["comprometida"]]
    errores = [r for r in reporte if r["error"]]

    if not comprometidas:
        lineas.append("[OK] Ninguna contraseña comprometida encontrada.")
    else:
        lineas.append(f"[!] {len(comprometidas)} cuenta(s) COMPROMETIDA(S):")
        lineas.append("")
        for r in comprometidas:
            lineas.append(f"  - {r['email']}")
            lineas.append(f"    Hash SHA-1: {r['hash']}")
            lineas.append(f"    Filtrada {r['ocurrencias']} vez/veces")
            lineas.append("")

    if errores:
        lineas.append(f"[?] {len(errores)} error(es) durante la auditoría:")
        for r in errores:
            lineas.append(f"  - {r['email']}: {r['error']}")
        lineas.append("")

    lineas.append(f"Resumen: {len(reporte)} auditadas | "
                  f"{len(comprometidas)} comprometidas | "
                  f"{len(errores)} errores")

    contenido = "\n".join(lineas) + "\n"

    with open(ruta, "w") as f:
        f.write(contenido)
    logging.info("Reporte guardado en %s", ruta)
    print(f"\n{COLOR_CYAN}Reporte guardado: {ruta}{COLOR_RESET}")


# ── 4. Main ───────────────────────────────────────────────────────


def run_audit(cfg: dict, txt_output: str = "") -> int:
    stats = {"total": 0, "unicas": 0, "duplicadas": 0, "comprometidas": 0, "errores": 0}
    cache: dict[str, dict] = {}
    reporte = []

    print(f"\n{COLOR_CYAN}╔════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}║      Heimdall - Plesk Auditor      ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}╚════════════════════════════════════╝{COLOR_RESET}\n")

    try:
        accounts = extract_mail_accounts()
    except RuntimeError as e:
        logging.critical("%s", e)
        return 1

    if not accounts:
        print(f"{COLOR_YELLOW}No hay cuentas de correo que auditar.{COLOR_RESET}\n")
        return 0

    stats["total"] = len(accounts)
    print(f"Auditando {len(accounts)} cuenta(s)...\n")

    for i, acct in enumerate(accounts, 1):
        email = acct["email"]
        password = acct["password"]
        pass_hash = _sha1_hex(password)

        print(f"  [{i}/{len(accounts)}] {email:<40} ", end="", flush=True)

        if pass_hash in cache:
            stats["duplicadas"] += 1
            result = cache[pass_hash]
            print(f"{COLOR_YELLOW}[DUPLICADA]{COLOR_RESET} ", end="")
            if result["compromised"]:
                stats["comprometidas"] += 1
                print(f"{COLOR_RED}(filtrada {result['occurrences']}x){COLOR_RESET}")
            else:
                print()
            reporte.append({
                "email": email, "hash": result["hash"],
                "comprometida": result["compromised"],
                "ocurrencias": result.get("occurrences", 0),
                "error": result.get("error"),
            })
            continue

        stats["unicas"] += 1

        try:
            result = check_password_hibp(password, cfg["hibp_rate_limit"])
        except Exception as e:
            stats["errores"] += 1
            print(f"{COLOR_YELLOW}[ERROR]{COLOR_RESET}")
            logging.error("Error inesperado con %s: %s", email, e)
            reporte.append({
                "email": email, "hash": "", "comprometida": False,
                "ocurrencias": 0, "error": str(e),
            })
            cache[pass_hash] = {"compromised": False, "occurrences": 0, "hash": "", "error": str(e)}
            continue

        cache[pass_hash] = result

        if result.get("error"):
            stats["errores"] += 1
            print(f"{COLOR_YELLOW}[API ERROR]{COLOR_RESET}")
        elif result["compromised"]:
            stats["comprometidas"] += 1
            print(f"{COLOR_RED}[COMPROMETIDA] (filtrada {result['occurrences']}x){COLOR_RESET}")
        else:
            print(f"{COLOR_GREEN}[SEGURA]{COLOR_RESET}")

        reporte.append({
            "email": email,
            "hash": result["hash"],
            "comprometida": result["compromised"],
            "ocurrencias": result.get("occurrences", 0),
            "error": result.get("error"),
        })

    seguras = stats["total"] - stats["comprometidas"] - stats["errores"]
    ahorradas = stats["duplicadas"]
    print(f"\n{'=' * 50}")
    print(f"  Total          : {stats['total']}")
    print(f"  Únicas         : {stats['unicas']}")
    print(f"  Duplicadas     : {ahorradas} (omitidas de API)")
    print(f"  Seguras        : {COLOR_GREEN}{seguras}{COLOR_RESET}")
    print(f"  Comprometidas  : {COLOR_RED}{stats['comprometidas']}{COLOR_RESET}")
    print(f"  Errores        : {COLOR_YELLOW}{stats['errores']}{COLOR_RESET}")
    print(f"{'=' * 50}\n")

    if txt_output:
        guardar_reporte_txt(reporte, txt_output)

    return 0 if stats["comprometidas"] == 0 else 2


def main():
    parser = argparse.ArgumentParser(
        description="Heimdall — Plesk Email Password Auditor (vía HIBP k-Anonymity)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  heimdall.py                                              # auditoría en vivo\n"
            "  heimdall.py --txt reporte.txt                            # guardar reporte\n"
            "  heimdall.py --txt /var/log/heimdall/mensual.txt -v       # debug + reporte\n"
            "  heimdall.py --dry-run                                    # solo consola\n"
        ),
    )
    parser.add_argument("--txt", type=str, metavar="FILE", default="",
                        help="Ruta del archivo .txt donde guardar el reporte")
    parser.add_argument("--dry-run", action="store_true",
                        help="No escribir archivo, solo salida por consola")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Log detallado (debug)")

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    if args.dry_run:
        args.txt = ""

    try:
        cfg = load_config()
    except Exception as e:
        logging.critical("Error cargando configuración: %s", e)
        return 1

    try:
        return run_audit(cfg, txt_output=args.txt)
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
        return 130
    except Exception as e:
        logging.exception("Error inesperado: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
