import requests
import random
import string
import time
import sys
import os
import threading
from datetime import datetime
from urllib.parse import quote
from colorama import Fore, Back, Style, init

init(autoreset=True)

SAVE_FILE = "save.txt"
PROXY_FILE = "proxies.txt"
HEADER = "== By Skid == == > https://cc-checker.eu == == > https://t.me/observerinfo3 == == =="

C_LABEL = Fore.WHITE + Style.BRIGHT
C_DIM = Fore.LIGHTBLACK_EX
C_ACCENT = Fore.LIGHTMAGENTA_EX + Style.BRIGHT
C_INFO = Fore.LIGHTCYAN_EX
C_OK = Fore.LIGHTGREEN_EX + Style.BRIGHT
C_BAD = Fore.LIGHTRED_EX + Style.BRIGHT
C_WARN = Fore.LIGHTYELLOW_EX
C_PROXY = Fore.LIGHTBLUE_EX

_username_lock = threading.Lock()
_username_index = 0

ASCII_ART = [
    r" ____  _    _     _                  ",
    r"/ ___|| | _(_) __| |                 ",
    r"\___ \| |/ / |/ _` |                 ",
    r" ___) |   <| | (_| |                 ",
    r"|____/|_|\_\_|\__,_|                 ",
    r" | || |   ___                        ",
    r" | || |_ / __|                       ",
    r" |__   _| (__                        ",
    r"    |_|  \___|                       ",
    r"  _  _  ____  _               _                ",
    r" | || |/ ___|| |__   ___  ___| | _____ _ __   ",
    r" | || || |   | '_ \ / _ \/ __| |/ / _ \ '__|  ",
    r" |__   _| |___| | | |  __/ (__|   <  __/ |     ",
    r"    |_|  \____|_| |_|\___|\___| |\_\___|_|     ",
    r"",
    r"   4c Checker By Skid - @Observerinfo3         ",
]

# Default proxy scheme when the line has no protocol (http / socks5 / socks4)
DEFAULT_PROXY_SCHEME = "http"

_proxy_lock = threading.Lock()
_proxy_index = 0
_proxies = []


def get_red_gradient(index, total):
    ratio = index / max(total - 1, 1)
    r = int(160 + 95 * ratio)
    g = int(10 + 40 * ratio)
    b = int(90 - 70 * ratio)
    return f"\033[38;2;{r};{g};{b}m"


def print_separator(title=None):
    line = "─" * 46
    if title:
        print(C_ACCENT + f"  ╔{line}╗")
        print(C_ACCENT + f"  ║  {title:<44}║")
        print(C_ACCENT + f"  ╚{line}╝" + Style.RESET_ALL)
    else:
        print(C_DIM + f"  {line}" + Style.RESET_ALL)


def stat_line(label, value, value_color=Fore.LIGHTWHITE_EX, raw=False):
    if raw:
        print(f"  {C_LABEL}{label:<10}{C_DIM}│ {value}{Style.RESET_ALL}")
    else:
        print(f"  {C_LABEL}{label:<10}{C_DIM}│ {value_color}{value}{Style.RESET_ALL}")


def print_ascii():
    os.system("cls" if os.name == "nt" else "clear")
    total = len(ASCII_ART)
    for i, line in enumerate(ASCII_ART):
        color = get_red_gradient(i, total)
        print(color + line + Style.RESET_ALL)
    print()


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
    """
    Convert a proxy line into a requests-compatible proxies dict.

    Primary format (proxy-cheap):
      host:port:username:password
      e.g. proxy-us.proxy-cheap.com:5959:pcBqj4yHMv-res-any-sid-12345:PC_37v3pAq2oZo7BY4Of
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "://" in line:
        url = line
    elif "@" in line:
        url = f"{default_scheme}://{line}"
    else:
        parts = line.rsplit(":", 3)
        if len(parts) == 4:
            host, port, user, password = parts
            user = quote(user, safe="")
            password = quote(password, safe="")
            url = f"{default_scheme}://{user}:{password}@{host}:{port}"
        elif len(parts) == 2:
            host, port = parts
            url = f"{default_scheme}://{host}:{port}"
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


def proxy_label(proxy):
    if not proxy:
        return "direct"
    url = proxy.get("http", "")
    if "@" in url:
        auth = url.split("@", 1)[0]
        auth = auth.replace("http://", "").replace("https://", "")
        if ":" in auth:
            return auth.rsplit(":", 1)[0]
        return auth
    return url.replace("http://", "").replace("https://", "")


def log_error(username, e, proxy=None):
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
    with open(SAVE_FILE, "a", encoding="utf-8") as f:
        f.write(username + "\n")


def init_save_file():
    if not os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, "w", encoding="utf-8") as f:
            f.write(HEADER + "\n\n")


def print_stats(generated, hits, bad, errors, proxy_errors, cpm, hit_list, proxy_count, recent_results, username_source, current_proxy_num, current_proxy_label):
    sys.stdout.write("\033[H")
    print_ascii()

    print_separator("CHECKER")
    stat_line("Usernames", username_source, C_INFO)
    if proxy_count:
        proxy_text = (
            f"{C_PROXY}{current_proxy_num}/{proxy_count} "
            f"{C_DIM}({C_PROXY}{current_proxy_label}{C_DIM})"
        )
        stat_line("Proxy", proxy_text, raw=True)

    print()
    print_separator("STATS")
    stat_line("Checked", str(generated), Fore.LIGHTWHITE_EX)
    stat_line("Valid", str(hits), C_OK)
    stat_line("Invalid", str(bad), C_BAD)
    stat_line("Errors", str(errors), C_WARN)
    if proxy_count:
        stat_line("Proxy err", str(proxy_errors), Fore.LIGHTMAGENTA_EX)
    stat_line("CPM", f"{cpm:.1f}", C_INFO + Style.BRIGHT)

    print()
    print_separator("RECENT")
    if not recent_results:
        print(C_DIM + "  (en attente...)" + Style.RESET_ALL)
    for username, result in recent_results[-10:]:
        if result == "hit":
            badge = Back.GREEN + Fore.BLACK + Style.BRIGHT + " VALID " + Style.RESET_ALL
            print(f"  {C_OK}✔ {username:<14}{badge}")
        elif result == "bad":
            badge = Back.RED + Fore.WHITE + Style.BRIGHT + " INVALID " + Style.RESET_ALL
            print(f"  {C_BAD}✘ {username:<14}{badge}")
        elif result == "proxy_error":
            badge = Back.MAGENTA + Fore.WHITE + Style.BRIGHT + " PROXY " + Style.RESET_ALL
            print(f"  {Fore.LIGHTMAGENTA_EX}⚠ {username:<14}{badge}")
        else:
            badge = Back.YELLOW + Fore.BLACK + Style.BRIGHT + f" {result.upper()} " + Style.RESET_ALL
            print(f"  {C_WARN}• {username:<14}{badge}")
    print(Style.RESET_ALL)


def main():
    global _proxies

    username_file = pick_username_file()
    if not username_file:
        print(C_BAD + "[!] Aucun fichier selectionne." + Style.RESET_ALL)
        sys.exit(1)

    usernames = load_usernames(username_file)
    if not usernames:
        print(C_BAD + "[!] Le fichier est vide ou invalide." + Style.RESET_ALL)
        sys.exit(1)

    username_source = f"{len(usernames)} from {os.path.basename(username_file)}"

    proxy_file = PROXY_FILE
    if len(sys.argv) > 1:
        proxy_file = sys.argv[1]

    _proxies = load_proxies(proxy_file)
    proxy_count = len(_proxies)

    init_save_file()
    generated = 0
    hits = 0
    bad = 0
    errors = 0
    proxy_errors = 0
    hit_list = []
    recent_results = []
    start_time = time.time()

    os.system("cls" if os.name == "nt" else "clear")
    print_ascii()
    print_separator("DEMARRAGE")
    print(C_OK + f"  ✔ {len(usernames)} usernames" + C_DIM + f"  ←  {C_INFO}{os.path.basename(username_file)}")
    if proxy_count:
        print(C_OK + f"  ✔ {proxy_count} proxies" + C_DIM + f"     ←  {C_PROXY}{proxy_file}")
    else:
        print(C_WARN + f"  ⚠ Aucune proxy" + C_DIM + f"        ←  {proxy_file} introuvable (mode direct)")
    print()
    print(C_DIM + "  Demarrage dans 1.5s..." + Style.RESET_ALL)
    time.sleep(1.5)

    while True:
        username = get_next_username(usernames)
        current_proxy_num = 0
        current_proxy_label = "direct"

        while True:
            if _proxies:
                proxy, current_proxy_num = get_next_proxy()
                current_proxy_label = proxy_label(proxy)
            else:
                proxy = None

            result = check_username(username, proxy=proxy)

            if result == "ratelimit":
                if _proxies:
                    continue
                time.sleep(2)
                continue

            if result == "proxy_error" and _proxies:
                proxy_errors += 1
                continue

            break

        generated += 1

        if result == "hit":
            hits += 1
            hit_list.append(username)
            save_hit(username)
        elif result == "bad":
            bad += 1
        else:
            errors += 1

        recent_results.append((username, result))

        elapsed = time.time() - start_time
        cpm = (generated / elapsed) * 60 if elapsed > 0 else 0

        print_stats(
            generated, hits, bad, errors, proxy_errors, cpm,
            hit_list, proxy_count, recent_results, username_source,
            current_proxy_num, current_proxy_label,
        )


if __name__ == "__main__":
    main()
