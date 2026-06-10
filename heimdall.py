#!/usr/bin/env python3
"""
Heimdall - Plesk Email Password Auditor
Audita contraseñas de correo Plesk vs HaveIBeenPwned (k-Anonymity).
Extracción en cascada: binario → SQL → desencriptación AES-256 → archivo manual.
"""

import os, sys, re, time, hashlib, logging, argparse, subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import requests
from dotenv import load_dotenv


HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
MAIL_AUTH_VIEW_PATHS = [
    "/usr/local/psa/admin/sbin/mail_auth_view",
    "/usr/psa/admin/sbin/mail_auth_view",
]
PSA_SHADOW = "/etc/psa/.psa.shadow"
PSA_SECRET = "/etc/psa/private/secret"
PSA_SQLITE_PATHS = [
    "/usr/local/psa/admin/conf/psa.db",
    "/usr/local/psa/var/psa.db",
    "/opt/psa/admin/conf/psa.db",
]
DEFAULT_RATE_LIMIT = 1.5
HIBP_TIMEOUT = 10
SCRIPT_DIR = Path(__file__).parent.resolve()
ENV_PATH = SCRIPT_DIR / ".env"

# Múltiples formatos de mail_auth_view según versión de Plesk
LINE_RE_COLON = re.compile(r"^([^@]+@[^:]+):(.+)$")       # email:password
LINE_RE_WS   = re.compile(r"^(\S+@\S+)\s+(\S+)$")          # email[whitespace]password

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
        "db_host": os.environ.get("DB_HOST", "localhost"),
        "db_port": int(os.environ.get("DB_PORT", "3306")),
        "db_user": os.environ.get("DB_USER", "admin"),
        "db_password": os.environ.get("DB_PASSWORD", ""),
    }


def _db_password() -> str:
    pwd = os.environ.get("DB_PASSWORD", "")
    if not pwd and Path(PSA_SHADOW).exists():
        pwd = Path(PSA_SHADOW).read_text().strip()
    return pwd


def _parse_mail_line(line: str) -> tuple[str, str] | None:
    """Intenta extraer email y password de una línea en varios formatos."""
    m = LINE_RE_COLON.match(line)
    if m:
        return m.group(1), m.group(2)
    m = LINE_RE_WS.match(line)
    if m:
        return m.group(1), m.group(2)
    # Fallback: split por cualquier whitespace, buscar campo con @
    parts = line.split()
    for i, p in enumerate(parts):
        if "@" in p and i + 1 < len(parts):
            return p, parts[i + 1]
    return None


# ── Backend A: mail_auth_view binario ─────────────────────────────

def _extract_via_binary() -> list[dict] | None:
    path = None
    for p in MAIL_AUTH_VIEW_PATHS:
        if Path(p).exists():
            path = Path(p)
            break
    if not path:
        logging.warning("Backend binary: ningún %s existe", ", ".join(MAIL_AUTH_VIEW_PATHS))
        return None
    try:
        result = subprocess.run(
            [str(path)], capture_output=True, text=True, timeout=30
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logging.warning("Backend binary: error ejecutando %s: %s", path, e)
        return None
    if result.returncode != 0:
        logging.warning("Backend binary: exit code %d: %s",
                        result.returncode, result.stderr.strip())
        return None

    accounts = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = _parse_mail_line(line)
        if parsed:
            email, password = parsed
            if password:
                accounts.append({"email": email, "password": password})
        else:
            logging.warning("Línea no parseable: %s", line[:80])
    logging.info("Backend binary: %d cuentas extraídas desde %s", len(accounts), path)
    return accounts


# ── Backend B: SQL directo a mail_auth_view ───────────────────────

def _extract_via_sql(cfg: dict) -> list[dict] | None:
    password = _db_password()
    if not password:
        logging.warning("Backend SQL: no hay password DB")
        return None
    try:
        import mysql.connector
    except ImportError:
        logging.warning("Backend SQL: mysql-connector-python no instalado")
        return None

    try:
        conn = mysql.connector.connect(
            host=cfg["db_host"], port=cfg["db_port"],
            database="psa", user=cfg["db_user"],
            password=password, connection_timeout=5,
        )
    except Exception as e:
        logging.warning("Backend SQL: conexión falló: %s", e)
        return None

    try:
        with conn.cursor(dictionary=True) as cur:
            cur.execute(
                "SELECT CONCAT(mail_name, '@', domain_id) AS email, password "
                "FROM mail_auth_view "
                "WHERE password IS NOT NULL AND password != ''"
            )
            rows = cur.fetchall()
        accounts = [{"email": r["email"], "password": r["password"]} for r in rows]
        logging.info("Backend SQL: %d cuentas extraídas", len(accounts))
        return accounts
    except Exception as e:
        logging.warning("Backend SQL: query falló: %s", e)
        return None
    finally:
        conn.close()


# ── Backend C: desencriptación AES-256-CBC ────────────────────────

def _plesk_decrypt(encrypted_hex: str, secret: bytes) -> str | None:
    """Descifra password Plesk (AES-256-CBC, key=SHA-256(secret), IV+ct en hex)."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        logging.error("Backend decrypt: pycryptodome no instalado")
        return None

    try:
        raw = bytes.fromhex(encrypted_hex)
    except (ValueError, TypeError):
        return None

    if len(raw) < 17:  # IV(16) + al menos 1 byte de ciphertext
        return None

    key = hashlib.sha256(secret).digest()
    iv, ct = raw[:16], raw[16:]

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8", errors="replace")
    except Exception as e:
        logging.debug("Fallo decrypt (puede ser padding/encoding): %s", e)
        return None


def _extract_via_decrypt(cfg: dict) -> list[dict] | None:
    secret_path = Path(PSA_SECRET)
    if not secret_path.exists():
        logging.warning("Backend decrypt: %s no existe", PSA_SECRET)
        return None

    password = _db_password()
    if not password:
        logging.warning("Backend decrypt: no hay password DB")
        return None

    try:
        import mysql.connector
    except ImportError:
        logging.warning("Backend decrypt: mysql-connector-python no instalado")
        return None

    try:
        conn = mysql.connector.connect(
            host=cfg["db_host"], port=cfg["db_port"],
            database="psa", user=cfg["db_user"],
            password=password, connection_timeout=5,
        )
    except Exception as e:
        logging.warning("Backend decrypt: conexión falló: %s", e)
        return None

    try:
        secret = secret_path.read_bytes()
        with conn.cursor(dictionary=True) as cur:
            cur.execute(
                "SELECT m.id, m.mail_name, d.name AS domain, m.password "
                "FROM mail m JOIN domains d ON m.domain_id = d.id "
                "WHERE m.password IS NOT NULL AND m.password != ''"
            )
            rows = cur.fetchall()

        accounts = []
        for r in rows:
            plain = _plesk_decrypt(r["password"], secret)
            if plain:
                email = f"{r['mail_name']}@{r['domain']}"
                accounts.append({"email": email, "password": plain})

        logging.info("Backend decrypt: %d cuentas descifradas de %d intentos",
                     len(accounts), len(rows))
        return accounts
    except Exception as e:
        logging.warning("Backend decrypt: error: %s", e)
        return None
    finally:
        conn.close()


# ── Backend E: SQLite directo (Plesk sin MySQL) ─────────────────


def _extract_via_sqlite(cfg: dict) -> list[dict] | None:
    import sqlite3

    db_path = None
    for p in PSA_SQLITE_PATHS:
        if Path(p).exists():
            db_path = p
            break
    if not db_path:
        logging.warning("Backend SQLite: ningún %s existe", ", ".join(PSA_SQLITE_PATHS))
        return None

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
    except Exception as e:
        logging.warning("Backend SQLite: conexión falló a %s: %s", db_path, e)
        return None

    try:
        cur = conn.cursor()
        # Intentar vista mail_auth_view (si existe en SQLite)
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='view' AND name='mail_auth_view'")
            if cur.fetchone():
                cur.execute(
                    "SELECT mail_name || '@' || domain_id AS email, password "
                    "FROM mail_auth_view WHERE password IS NOT NULL AND password != ''"
                )
                rows = cur.fetchall()
                accounts = [{"email": r["email"], "password": r["password"]} for r in rows]
                if accounts:
                    logging.info("Backend SQLite: %d cuentas desde mail_auth_view", len(accounts))
                    return accounts
        except Exception:
            pass

        # Fallback: tabla mail + domains + posiblemente secret
        secret = None
        secret_path = Path(PSA_SECRET)
        if secret_path.exists():
            secret = secret_path.read_bytes()

        cur.execute(
            "SELECT m.id, m.mail_name, d.name AS domain, m.password "
            "FROM mail m JOIN domains d ON m.domain_id = d.id "
            "WHERE m.password IS NOT NULL AND m.password != ''"
        )
        rows = cur.fetchall()
        accounts = []
        for r in rows:
            pwd = r["password"]
            if secret and pwd and all(c in "0123456789abcdefABCDEF" for c in pwd):
                plain = _plesk_decrypt(pwd, secret)
                if plain:
                    pwd = plain
            if pwd:
                email = f"{r['mail_name']}@{r['domain']}"
                accounts.append({"email": email, "password": pwd})

        logging.info("Backend SQLite: %d cuentas desde %s", len(accounts), db_path)
        return accounts
    except Exception as e:
        logging.warning("Backend SQLite: query falló: %s", e)
        return None
    finally:
        conn.close()


# ── Backend D: archivo manual ────────────────────────────────────

def _extract_from_file(ruta: str) -> list[dict]:
    path = Path(ruta)
    if not path.exists():
        raise RuntimeError(f"Archivo no encontrado: {ruta}")
    accounts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parsed = _parse_mail_line(line)
        if parsed:
            email, password = parsed
            if password:
                accounts.append({"email": email, "password": password})
        else:
            logging.warning("Línea ignorada: %s", line[:80])
    logging.info("Backend file: %d cuentas desde %s", len(accounts), ruta)
    return accounts


# ── Extract maestro (cascada) ─────────────────────────────────────

BACKENDS = {
    "binary": _extract_via_binary,
    "sql": _extract_via_sql,
    "decrypt": _extract_via_decrypt,
    "sqlite": _extract_via_sqlite,
}


def extract_mail_accounts(cfg: dict, method: str = "", from_file: str = "") -> list[dict]:
    if from_file:
        return _extract_from_file(from_file)

    if method:
        if method not in BACKENDS:
            raise RuntimeError(f"Método inválido: {method}. Opciones: {', '.join(BACKENDS)}")
        fn = BACKENDS[method]
        result = fn(cfg) if method in ("sql", "decrypt") else fn()
        if result is None:
            raise RuntimeError(f"Método '{method}' no disponible")
        return result

    # Cascada automática
    orden = [
        ("binary", lambda: _extract_via_binary()),
        ("sql", lambda: _extract_via_sql(cfg)),
        ("sqlite", lambda: _extract_via_sqlite(cfg)),
        ("decrypt", lambda: _extract_via_decrypt(cfg)),
    ]
    for nombre, fn in orden:
        result = fn()
        if result is not None and len(result) > 0:
            logging.info("Método usado: %s (%d cuentas)", nombre, len(result))
            return result

    raise RuntimeError(
        "Ningún método de extracción funcionó.\n"
        "  Opciones:\n"
        "    - Ejecutar en un servidor Plesk (usa mail_auth_view automáticamente)\n"
        "    - Especificar --from-file cuentas.txt\n"
        "    - Especificar --method sql (MySQL + .psa.shadow)\n"
        "    - Especificar --method sqlite (SQLite: psa.db)\n"
        "    - Especificar --method decrypt (MySQL / SQLite + secret)"
    )


# ── SHA-1 + HIBP ─────────────────────────────────────────────────

def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest().upper()


def build_prefix_index(accounts: list[dict]) -> tuple[dict, dict]:
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
    try:
        resp = requests.get(
            HIBP_API_URL + prefix,
            timeout=HIBP_TIMEOUT,
            headers={"User-Agent": "Heimdall-Plesk-Auditor/2.0"},
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"HIBP ({prefix}): {e}") from e

    result = {}
    for line in resp.text.splitlines():
        if ":" in line:
            s, c = line.split(":", 1)
            result[s.strip().upper()] = int(c)
    return result


# ── Auditoría ─────────────────────────────────────────────────────

def run_audit(cfg: dict, txt_output: str = "",
              method: str = "", from_file: str = "") -> int:
    print(f"\n{COLOR_CYAN}╔════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}║      Heimdall - Plesk Auditor      ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}╚════════════════════════════════════╝{COLOR_RESET}\n")

    try:
        accounts = extract_mail_accounts(cfg, method=method, from_file=from_file)
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

    ahorro = duplicados + (total_unicas - total_prefijos)
    print(f"  {COLOR_BOLD}{total_cuentas}{COLOR_RESET} cuentas · "
          f"{COLOR_BOLD}{total_unicas}{COLOR_RESET} únicas · "
          f"{COLOR_BOLD}{total_prefijos}{COLOR_RESET} prefijos · "
          f"{COLOR_GREEN}{ahorro}{COLOR_RESET} llamadas ahorradas\n")

    stats = {"comprometidas": 0, "errores": 0}
    reporte = []
    comprometidas_list: list[str] = []

    for idx, (prefix, suffix_list) in enumerate(prefix_to_hashes.items(), 1):
        print(f"  [{idx}/{total_prefijos}] {prefix} ", end="", flush=True)

        time.sleep(cfg["hibp_rate_limit"])

        try:
            suffixes = fetch_hibp_suffixes(prefix)
        except RuntimeError as e:
            print(f"{COLOR_RED}ERR{COLOR_RESET}")
            logging.error("Fallo prefijo %s: %s", prefix, e)
            for _, full_hash in suffix_list:
                for acct in hash_to_accounts[full_hash]:
                    stats["errores"] += 1
                    reporte.append({"email": acct["email"], "hash": full_hash,
                                    "comprometida": False, "ocurrencias": 0, "error": str(e)})
            continue

        # Buscar comprometidas en este prefijo
        encontradas = 0
        for suffix, full_hash in suffix_list:
            if suffix in suffixes:
                encontradas += len(hash_to_accounts[full_hash])
                for acct in hash_to_accounts[full_hash]:
                    stats["comprometidas"] += 1
                    comprometidas_list.append(acct["email"])
                    reporte.append({"email": acct["email"], "hash": full_hash,
                                    "comprometida": True,
                                    "ocurrencias": suffixes[suffix], "error": None})
            else:
                for acct in hash_to_accounts[full_hash]:
                    reporte.append({"email": acct["email"], "hash": full_hash,
                                    "comprometida": False, "ocurrencias": 0, "error": None})

        if encontradas:
            print(f"{COLOR_RED}{encontradas} comprometida(s){COLOR_RESET}")
        else:
            print(f"{COLOR_GREEN}OK{COLOR_RESET}")

    seguras = total_cuentas - stats["comprometidas"] - stats["errores"]
    print(f"\n  {'=' * 48}")
    print(f"  Total     : {total_cuentas}")
    print(f"  Seguras   : {COLOR_GREEN}{seguras}{COLOR_RESET}")
    print(f"  {"Comprometidas"}  : {COLOR_RED}{stats['comprometidas']}{COLOR_RESET}")
    print(f"  Errores   : {COLOR_YELLOW}{stats['errores']}{COLOR_RESET}")
    print(f"  Ahorro    : {COLOR_GREEN}{ahorro} llamadas API{COLOR_RESET}")
    print(f"  {'=' * 48}\n")

    if comprometidas_list:
        print(f"  {COLOR_RED}Cuentas comprometidas:{COLOR_RESET}")
        for email in comprometidas_list:
            print(f"    - {email}")
        print("")

    if txt_output:
        _guardar_reporte(reporte, txt_output)

    return 0 if stats["comprometidas"] == 0 else 2


def _guardar_reporte(reporte: list[dict], ruta: str):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    comp = [r for r in reporte if r["comprometida"]]
    errs = [r for r in reporte if r["error"]]

    lines = ["=" * 60, f"Heimdall - Reporte ({fecha})", "=" * 60, ""]
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
    Path(ruta).write_text("\n".join(lines) + "\n")
    print(f"{COLOR_CYAN}Reporte: {ruta}{COLOR_RESET}")


# ── CLI ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Heimdall — Plesk Email Password Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  heimdall.py                                              # cascada auto\n"
            "  heimdall.py --from-file cuentas.txt                      # archivo plano\n"
            "  heimdall.py --method sql                                 # forzar SQL\n"
            "  heimdall.py --method decrypt                             # forzar decrypt\n"
            "  heimdall.py --txt /var/log/heimdall/mensual.txt          # guardar reporte\n"
        ),
    )
    parser.add_argument("--txt", type=str, default="", metavar="FILE",
                        help="Guardar reporte en .txt")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo consola, no guardar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    g = parser.add_argument_group("Extracción (por defecto: cascada automática)")
    g.add_argument("--method", type=str, default="",
                   choices=["binary", "sql", "sqlite", "decrypt"],
                   help="Forzar método de extracción")
    g.add_argument("--from-file", type=str, default="", metavar="FILE",
                   help="Leer cuentas desde archivo (formato email:pass)")

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
        return run_audit(cfg, txt_output=args.txt,
                         method=args.method, from_file=args.from_file)
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        return 130
    except Exception as e:
        logging.exception("Error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
