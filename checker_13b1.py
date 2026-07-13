import requests
import random
import string
import time
import sys
import os
import threading
from datetime import datetime
from urllib.parse import quote
from colorama import Fore, Style, init

init(autoreset=True)

SAVE_FILE = "save.txt"
PROXY_FILE = "proxies.txt"
WEBHOOK_FILE = "webhook.txt"
DEFAULT_THREADS = 5
MAX_THREADS = 50

C_LABEL = Fore.WHITE + Style.BRIGHT
C_DIM = Fore.LIGHTBLACK_EX
C_INFO = Fore.LIGHTCYAN_EX
C_OK = Fore.LIGHTGREEN_EX + Style.BRIGHT
C_BAD = Fore.LIGHTRED_EX + Style.BRIGHT
C_WARN = Fore.LIGHTYELLOW_EX
C_PROXY = Fore.LIGHTBLUE_EX

STAT_LABEL_WIDTH = 9
RECENT_LIMIT = 5

_username_lock = threading.Lock()
_username_index = 0

DEFAULT_PROXY_SCHEME = "http"

_proxy_lock = threading.Lock()
_proxy_index = 0
_proxies = []

_stats_lock = threading.Lock()
_display_lock = threading.Lock()
_file_lock = threading.Lock()


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def stat_line(label, value, value_color=Fore.LIGHTWHITE_EX, raw=False):
    label_part = f"{C_LABEL}{label:<{STAT_LABEL_WIDTH}}{C_DIM}│ "
    if raw:
        print(f"  {label_part}{value}{Style.RESET_ALL}")
    else:
        print(f"  {label_part}{value_color}{value}{Style.RESET_ALL}")


def print_divider():
    print(C_DIM + "  " + "-" * 16 + Style.RESET_ALL)


def recent_line(icon, username, status, color):
    print(f"  {color}{icon} {username:<12} {status}{Style.RESET_ALL}")


def generate_username():
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=4))


def pick_username_file():
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        path = filedialog.askopenfilename(
            title="Choisir le fichier de usernames",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")],
        )
        root.destroy()
        return path if path else None
    except Exception as e:
        print(C_BAD + f"[!] Impossible d'ouvrir l'explorateur: {e}" + Style.RESET_ALL)
        return None


def load_usernames(path):
    usernames = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                usernames.append(line)
    return usernames


def get_next_username(usernames):
    global _username_index
    if not usernames:
        return generate_username()

    with _username_lock:
        username = usernames[_username_index % len(usernames)]
        _username_index += 1
    return username


def format_proxy(line, default_scheme=DEFAULT_PROXY_SCHEME):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    scheme = default_scheme
    if "://" in line:
        scheme, line = line.split("://", 1)

    if "@" in line:
        url = f"{scheme}://{line}"
    else:
        parts = line.rsplit(":", 3)
        if len(parts) == 4:
            if parts[1].isdigit():
                host, port, user, password = parts
            elif parts[3].isdigit():
                user, password, host, port = parts
            else:
                return None
            user = quote(user, safe="")
            password = quote(password, safe="")
            url = f"{scheme}://{user}:{password}@{host}:{port}"
        elif len(parts) == 2 and parts[1].isdigit():
            host, port = parts
            url = f"{scheme}://{host}:{port}"
        else:
            return None

    return {"http": url, "https": url}


def load_proxies(proxy_file=PROXY_FILE, default_scheme=DEFAULT_PROXY_SCHEME):
    if not os.path.exists(proxy_file):
        return []

    proxies = []
    with open(proxy_file, "r", encoding="utf-8") as f:
        for line in f:
            proxy = format_proxy(line, default_scheme=default_scheme)
            if proxy:
                proxies.append(proxy)
    return proxies


def get_next_proxy():
    global _proxy_index
    if not _proxies:
        return None, 0

    with _proxy_lock:
        idx = _proxy_index % len(_proxies)
        proxy = _proxies[idx]
        _proxy_index += 1
    return proxy, idx + 1


def load_threads():
    if not os.path.exists(THREADS_FILE):
        return DEFAULT_THREADS
    try:
        with open(THREADS_FILE, "r", encoding="utf-8") as f:
            value = int(f.read().strip())
        return max(1, min(value, MAX_THREADS))
    except (ValueError, OSError):
        return DEFAULT_THREADS


def log_error(username, e, proxy=None):
    with _file_lock:
        with open("errors-logs.txt", "a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            proxy_info = ""
            if proxy:
                proxy_info = f" | proxy={proxy.get('http', '')}"
            f.write(f"[{ts}] username={username}{proxy_info} | {type(e).__name__}: {e}\n")


def check_username(username, proxy=None):
    try:
        payload = {
            "username": username,
            "password": "Xk9#mP2$vL5@nQ8!",
            "email": f"{username}fake@protonmail.com",
            "consent": True,
            "date_of_birth": "1999-06-15",
            "gift_code_sku_id": None,
            "captcha_key": None,
        }
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIn0=",
        }
        r = requests.post(
            "https://discord.com/api/v9/auth/register",
            json=payload,
            headers=headers,
            proxies=proxy,
            timeout=10,
        )
        if r.status_code == 429:
            return "ratelimit"
        data = r.json()
        if "token" in data:
            return "hit"
        errors = data.get("errors", {})
        username_errors = errors.get("username", {})
        password_errors = errors.get("password", {})
        if password_errors and not username_errors:
            return "hit"
        if username_errors:
            codes = [v.get("code", "") for v in username_errors.get("_errors", [])]
            if any("USERNAME_ALREADY_TAKEN" in c or "taken" in c.lower() for c in codes):
                return "bad"
            return "hit"
        captcha = data.get("captcha_key")
        if captcha:
            return "hit"
        e = Exception(f"HTTP {r.status_code} - {r.text[:300]}")
        log_error(username, e, proxy=proxy)
        return "error"
    except (
        requests.exceptions.ProxyError,
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.ReadTimeout,
    ) as e:
        log_error(username, e, proxy=proxy)
        return "proxy_error"
    except Exception as e:
        log_error(username, e, proxy=proxy)
        return "error"


def save_hit(username):
    with _file_lock:
        with open(SAVE_FILE, "a", encoding="utf-8") as f:
            f.write(username + "\n")


def run_check(usernames, webhook_url):
    username = get_next_username(usernames)

    while True:
        if _proxies:
            proxy, _ = get_next_proxy()
        else:
            proxy = None

        result = check_username(username, proxy=proxy)

        if result == "ratelimit":
            if _proxies:
                time.sleep(0.5)
                continue
            time.sleep(2)
            continue

        if result == "proxy_error" and _proxies:
            with _stats_lock:
                _stats["proxy_errors"] += 1
            continue

        break

    with _stats_lock:
        _stats["generated"] += 1
        if result == "hit":
            _stats["hits"] += 1
            save_hit(username)
            notify_hit(webhook_url, username)
        elif result == "bad":
            _stats["bad"] += 1
        else:
            _stats["errors"] += 1
        _stats["recent_results"].append((username, result))


def worker(usernames, webhook_url):
    while True:
        run_check(usernames, webhook_url)


def refresh_display():
    with _display_lock:
        with _stats_lock:
            elapsed = time.time() - _stats["start_time"]
            generated = _stats["generated"]
            hits = _stats["hits"]
            bad = _stats["bad"]
            errors = _stats["errors"]
            proxy_errors = _stats["proxy_errors"]
            recent_results = list(_stats["recent_results"])
        cpm = (generated / elapsed) * 60 if elapsed > 0 else 0
        print_stats(
            generated, hits, bad, errors, proxy_errors, cpm,
            _proxy_count, recent_results, _thread_count,
        )


_stats = {}
_proxy_count = 0
_thread_count = DEFAULT_THREADS


def load_webhook():
    if not os.path.exists(WEBHOOK_FILE):
        return None
    with open(WEBHOOK_FILE, "r", encoding="utf-8") as f:
        url = f.read().strip()
    if url and url.startswith("https://"):
        return url
    return None


def send_webhook_hit(webhook_url, username):
    try:
        payload = {
            "embeds": [
                {
                    "title": "Username disponible",
                    "description": f"`{username}`",
                    "color": 5763719,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ]
        }
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        log_error(username, e)


def notify_hit(webhook_url, username):
    if not webhook_url:
        return
    threading.Thread(target=send_webhook_hit, args=(webhook_url, username), daemon=True).start()


def init_save_file():
    if not os.path.exists(SAVE_FILE):
        open(SAVE_FILE, "w", encoding="utf-8").close()


def print_stats(generated, hits, bad, errors, proxy_errors, cpm, proxy_count, recent_results, thread_count):
    sys.stdout.write("\033[H")
    clear_screen()

    stat_line("Threads", str(thread_count), C_INFO)
    stat_line("Checked", str(generated), Fore.LIGHTWHITE_EX)
    stat_line("Valid", str(hits), C_OK)
    stat_line("Invalid", str(bad), C_BAD)
    stat_line("Errors", str(errors), C_WARN)
    if proxy_count:
        stat_line("Proxy err", str(proxy_errors), Fore.LIGHTMAGENTA_EX)
    stat_line("CPM", f"{cpm:.1f}", C_INFO + Style.BRIGHT)

    print()
    print_divider()
    print()

    if not recent_results:
        print(C_DIM + "  (en attente...)" + Style.RESET_ALL)
    else:
        for username, result in recent_results[-RECENT_LIMIT:]:
            if result == "hit":
                recent_line("✔", username, "VALID", C_OK)
            elif result == "bad":
                recent_line("✘", username, "INVALID", C_BAD)
            elif result == "proxy_error":
                recent_line("⚠", username, "PROXY", Fore.LIGHTMAGENTA_EX)
            else:
                recent_line("•", username, result.upper(), C_WARN)
    print(Style.RESET_ALL)


def main():
    global _proxies, _stats, _proxy_count, _thread_count

    username_file = pick_username_file()
    if not username_file:
        print(C_BAD + "[!] Aucun fichier selectionne." + Style.RESET_ALL)
        sys.exit(1)

    usernames = load_usernames(username_file)
    if not usernames:
        print(C_BAD + "[!] Le fichier est vide ou invalide." + Style.RESET_ALL)
        sys.exit(1)

    proxy_file = PROXY_FILE
    if len(sys.argv) > 1:
        proxy_file = sys.argv[1]

    _proxies = load_proxies(proxy_file)
    _proxy_count = len(_proxies)
    _thread_count = load_threads()
    webhook_url = load_webhook()

    init_save_file()
    _stats = {
        "generated": 0,
        "hits": 0,
        "bad": 0,
        "errors": 0,
        "proxy_errors": 0,
        "recent_results": [],
        "start_time": time.time(),
    }

    clear_screen()
    print(C_OK + f"  ✔ {len(usernames)} usernames" + C_DIM + f"  ←  {C_INFO}{os.path.basename(username_file)}")
    if _proxy_count:
        print(C_OK + f"  ✔ {_proxy_count} proxies" + C_DIM + f"     ←  {C_PROXY}{proxy_file}")
    else:
        print(C_WARN + f"  ⚠ Aucune proxy" + C_DIM + f"        ←  {proxy_file} introuvable (mode direct)")
    print(C_OK + f"  ✔ {_thread_count} threads" + C_DIM + f"    ←  {C_INFO}{THREADS_FILE}")
    if webhook_url:
        print(C_OK + f"  ✔ Webhook actif" + C_DIM + f"     ←  {C_INFO}{WEBHOOK_FILE}")
    else:
        print(C_WARN + f"  ⚠ Pas de webhook" + C_DIM + f"      ←  {WEBHOOK_FILE} introuvable")
    print()
    print(C_DIM + "  Demarrage dans 1.5s..." + Style.RESET_ALL)
    time.sleep(1.5)

    for _ in range(_thread_count):
        t = threading.Thread(target=worker, args=(usernames, webhook_url), daemon=True)
        t.start()

    while True:
        time.sleep(0.2)
        refresh_display()


if __name__ == "__main__":
    main()
