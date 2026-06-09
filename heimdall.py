#!/usr/bin/env python3
"""
Heimdall - Plesk Email Password Auditor
Audita contraseñas de correo Plesk vs HaveIBeenPwned (k-Anonymity).
Optimizado: agrupa por prefijo SHA-1 para minimizar llamadas API.
"""

import os, sys, re, time, hashlib, logging, argparse, subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import requests
from dotenv import load_dotenv


HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
MAIL_AUTH_VIEW = "/usr/psa/admin/sbin/mail_auth_view"
DEFAULT_RATE_LIMIT = 1.5
HIBP_TIMEOUT = 10
SCRIPT_DIR = Path(__file__).parent.resolve()
ENV_PATH = SCRIPT_DIR / ".env"

LINE_RE = re.compile(r"^([^@]+@[^:]+):(.+)$")

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_config() -> dict:
    load_dotenv(dotenv_path=ENV_PATH if ENV_PATH.exists() else None)
    return {
        "hibp_rate_limit": float(os.environ.get("HIBP_RATE_LIMIT", str(DEFAULT_RATE_LIMIT))),
    }


def extract_mail_accounts() -> list[dict]:
    if not Path(MAIL_AUTH_VIEW).exists():
        raise RuntimeError(f"No se encuentra {MAIL_AUTH_VIEW}. ¿Esto es Plesk?")

    try:
        result = subprocess.run([MAIL_AUTH_VIEW], capture_output=True, text=True, timeout=30)
    except FileNotFoundError as e:
        raise RuntimeError(f"No se pudo ejecutar {MAIL_AUTH_VIEW}: {e}") from e
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{MAIL_AUTH_VIEW} no respondió en 30s")

    if result.returncode != 0:
        raise RuntimeError(f"{MAIL_AUTH_VIEW} exit {result.returncode}: {result.stderr.strip()}")

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
            logging.warning("Línea no parseable: %s", line[:80])

    return accounts


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest().upper()


def build_prefix_index(accounts: list[dict]) -> tuple[dict, dict]:
    """Agrupa por hash exacto (dedup) y por prefijo SHA-1 (ahorro API)."""
    hash_to_accounts: dict[str, list[dict]] = defaultdict(list)
    for acct in accounts:
        h = sha1_hex(acct["password"])
        hash_to_accounts[h].append(acct)

    prefix_to_hashes: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for full_hash in hash_to_accounts:
        prefix, suffix = full_hash[:5], full_hash[5:]
        prefix_to_hashes[prefix].append((suffix, full_hash))

    return hash_to_accounts, prefix_to_hashes


def fetch_hibp_suffixes(prefix: str) -> dict[str, int]:
    """Retorna {suffix: count} para un prefijo dado."""
    try:
        resp = requests.get(
            HIBP_API_URL + prefix,
            timeout=HIBP_TIMEOUT,
            headers={"User-Agent": "Heimdall-Plesk-Auditor/2.0"},
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Error HIBP ({prefix}): {e}") from e

    result = {}
    for line in resp.text.splitlines():
        if ":" in line:
            s, c = line.split(":", 1)
            result[s.strip().upper()] = int(c)
    return result


def run_audit(cfg: dict, txt_output: str = "") -> int:
    print(f"\n{COLOR_CYAN}╔════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}║      Heimdall - Plesk Auditor      ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}╚════════════════════════════════════╝{COLOR_RESET}\n")

    try:
        accounts = extract_mail_accounts()
    except RuntimeError as e:
        logging.critical("%s", e)
        return 1

    if not accounts:
        print(f"{COLOR_YELLOW}No hay cuentas para auditar.{COLOR_RESET}\n")
        return 0

    total_cuentas = len(accounts)
    hash_to_accounts, prefix_to_hashes = build_prefix_index(accounts)
    total_unicas = len(hash_to_accounts)
    total_prefijos = len(prefix_to_hashes)
    duplicados = total_cuentas - total_unicas

    print(f"  Cuentas: {COLOR_BOLD}{total_cuentas}{COLOR_RESET} | "
          f"Únicas: {COLOR_BOLD}{total_unicas}{COLOR_RESET} | "
          f"Prefijos: {COLOR_BOLD}{total_prefijos}{COLOR_RESET} | "
          f"Ahorro: {COLOR_GREEN}{duplicados + (total_unicas - total_prefijos)} llamadas{COLOR_RESET}\n")

    stats = {"comprometidas": 0, "errores": 0}
    reporte = []
    hibp_cache: dict[str, dict[str, int]] = {}
    result_cache: dict[str, dict] = {}

    for idx, (prefix, suffix_list) in enumerate(prefix_to_hashes.items(), 1):
        bar = f"[{idx}/{total_prefijos}]"
        print(f"  {bar} Prefijo {prefix} ({len(suffix_list)} pwd) ... ", end="", flush=True)

        time.sleep(cfg["hibp_rate_limit"])

        try:
            suffixes = fetch_hibp_suffixes(prefix)
            hibp_cache[prefix] = suffixes
            print(f"{COLOR_GREEN}OK{COLOR_RESET} ({len(suffixes)} hashes en respuesta)")
        except RuntimeError as e:
            print(f"{COLOR_RED}ERROR{COLOR_RESET}")
            logging.error("Fallo prefijo %s: %s", prefix, e)
            for suffix, full_hash in suffix_list:
                result_cache[full_hash] = {"comprometida": False, "ocurrencias": 0, "error": str(e)}
                for acct in hash_to_accounts[full_hash]:
                    stats["errores"] += len(hash_to_accounts[full_hash])
                    reporte.append({"email": acct["email"], "hash": full_hash,
                                    "comprometida": False, "ocurrencias": 0, "error": str(e)})
            continue

        for suffix, full_hash in suffix_list:
            if suffix in suffixes:
                result_cache[full_hash] = {
                    "comprometida": True,
                    "ocurrencias": suffixes[suffix],
                    "error": None,
                }
                for acct in hash_to_accounts[full_hash]:
                    stats["comprometidas"] += 1
                    reporte.append({"email": acct["email"], "hash": full_hash,
                                    "comprometida": True, "ocurrencias": suffixes[suffix], "error": None})
            else:
                result_cache[full_hash] = {"comprometida": False, "ocurrencias": 0, "error": None}
                for acct in hash_to_accounts[full_hash]:
                    reporte.append({"email": acct["email"], "hash": full_hash,
                                    "comprometida": False, "ocurrencias": 0, "error": None})

    seguras = total_cuentas - stats["comprometidas"] - stats["errores"]
    ahorro_total = duplicados + (total_unicas - total_prefijos)
    print(f"\n{'=' * 50}")
    print(f"  Cuentas        : {total_cuentas}")
    print(f"  Únicas         : {total_unicas}")
    print(f"  Prefijos API   : {total_prefijos}")
    print(f"  Llamadas API   : {total_prefijos} (ahorro: {COLOR_GREEN}{ahorro_total}{COLOR_RESET})")
    print(f"  Seguras        : {COLOR_GREEN}{seguras}{COLOR_RESET}")
    print(f"  Comprometidas  : {COLOR_RED}{stats['comprometidas']}{COLOR_RESET}")
    print(f"  Errores        : {COLOR_YELLOW}{stats['errores']}{COLOR_RESET}")
    print(f"{'=' * 50}\n")

    if txt_output:
        _guardar_reporte(reporte, txt_output)

    return 0 if stats["comprometidas"] == 0 else 2


def _guardar_reporte(reporte: list[dict], ruta: str):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    comp = [r for r in reporte if r["comprometida"]]
    errs = [r for r in reporte if r["error"]]

    lines = []
    lines.append("=" * 60)
    lines.append(f"Heimdall - Reporte ({fecha})")
    lines.append("=" * 60)
    lines.append("")
    if not comp:
        lines.append("[OK] 0 comprometidas.")
    else:
        lines.append(f"[!] {len(comp)} comprometida(s):\n")
        for r in comp:
            lines.append(f"  - {r['email']}")
            lines.append(f"    SHA-1: {r['hash']}")
            lines.append(f"    Filtrada {r['ocurrencias']}x\n")
        lines.append("")
    if errs:
        lines.append(f"[?] {len(errs)} error(es):")
        for r in errs:
            lines.append(f"  - {r['email']}: {r['error']}")
        lines.append("")
    lines.append(f"Total: {len(reporte)} | Comp: {len(comp)} | Err: {len(errs)}")

    Path(ruta).parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{COLOR_CYAN}Reporte: {ruta}{COLOR_RESET}")


def main():
    parser = argparse.ArgumentParser(description="Heimdall — Plesk Password Auditor")
    parser.add_argument("--txt", type=str, default="", metavar="FILE",
                        help="Guardar reporte en .txt")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo consola, sin guardar")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.dry_run:
        args.txt = ""

    try:
        cfg = load_config()
    except Exception as e:
        logging.critical("Config: %s", e)
        return 1

    try:
        return run_audit(cfg, txt_output=args.txt)
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        return 130
    except Exception as e:
        logging.exception("Error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
