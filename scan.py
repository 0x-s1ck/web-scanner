import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse
import random, time, threading, hashlib, string, sys, itertools
from datetime import datetime
from queue import Queue

# ===== COLOR =====
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ===== CONFIG =====
MAX_WORKERS = 40
TIMEOUT = 6
DELAY_MIN = 0.05
DELAY_MAX = 0.1
LEN_TOL = 200

START_YEAR = 2015
END_YEAR = datetime.now().year

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile)"
]

ARCHIVE_EXTS = [
    "zip","rar","7z","tar","tar.gz","tgz",
    "sql","sql.gz","dump","gz",
    "sqlite","sqlite3","mdb","accdb","csv"
]

SECOND_EXTS = [
    "bak","old","backup","save","tmp","orig","~"
]

COMMON_PATHS = [
    "backup","db","uploads/backup","storage","files/backup","data","archive"
]

SENSITIVE_FILES = [
    ".env",".env.local",".env.production",".env.backup",
    "wp-config.php","wp-config.php.bak","wp-config.php.old",
    "config.php","config.php.bak","config.php.old","config.php.save","config.php.tmp","config.php.orig",
    ".htaccess",".htpasswd",".htuser",
    "id_rsa","id_dsa","id_ed25519","id_ecdsa",
    "credentials.json","service-account.json","secrets.json",
    "composer.json","package.json","requirements.txt","Gemfile",
    "Dockerfile",".dockerignore","docker-compose.yml",
    ".git/config",".git/credentials",".gitignore",
    "debug.log","error.log","access.log"
]

ADMIN_PATHS = [
    "admin","wp-admin","administrator","cpanel","phpmyadmin",
    "panel","backend","manage","dashboard","control",
    "api","api/v1","api/v2","api/admin","graphql","rest",
    "login","signin","auth","account","user","users",
    "config","configuration","settings","configs",
    "upload","uploads","file","files","media",
    "test","staging","dev","v2","v1"
]

UPLOAD_PATHS = [
    "upload","uploads","files","file","assets","media",
    "images","img","storage","storage/app","tmp","cache",
    "admin","administrator","adminpanel","admin-panel",
    "admin_area","adminarea","backend","backoffice",
    "panel","controlpanel","cp","dashboard",
    "data","userfiles","private","protected",
    "backup","backups","old","archive",
    "test","testing","staging","dev"
]

TEST_FILES = [
    "test.php","info.php","index.php",
    "image.php.jpg","photo.jpg.php","file.pdf.php",
    "cmd.phtml","exec.phar","upload.php"
]

# ================== UTILS ==================

def headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def ensure_https(url):
    url = url.strip().replace("http://","").replace("https://","")
    return f"https://{url.rstrip('/')}"

def random_path(length=14):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def fingerprint(resp):
    try:
        body = next(resp.iter_content(4096), b"")
    except:
        body = b""
    return {
        "status": resp.status_code,
        "ctype": resp.headers.get("Content-Type", "").lower(),
        "length": int(resp.headers.get("Content-Length", len(body))),
        "hash": hashlib.md5(body).hexdigest() if body else None,
        "body": body
    }

# ================== WORDLIST ==================

def domain_wordlist(domain):
    clean = domain.replace("www.", "")
    parts = clean.split(".")

    # SECOND LEVEL TLD (ID)
    sld = {
        "co.id","ac.id","sch.id","go.id",
        "or.id","web.id","my.id"
    }

    last_two = ".".join(parts[-2:])

    if last_two in sld and len(parts) >= 3:
        main = parts[-3]
    elif len(parts) >= 2:
        main = parts[-2]
    else:
        main = parts[0]

    years = [str(y) for y in range(START_YEAR, END_YEAR + 1)]
    out = {main}

    for y in years:
        out.add(f"{main}{y}")
        out.add(f"{main}_{y}")
        out.add(f"{main}-{y}")

    return out

WEB_EXTS = ["php", "html", "htm", "txt", "js", "json", "xml", "inc", "conf", "cfg", "yaml", "yml", "env", "ini", "pl", "cgi", "py", "rb", "asp", "aspx"]

def generate_archive_files(domain):
    base_words = {
        "backup","backups","db","database",
        "dump","site","www","htdocs","public_html",
        "app","apps","api","panel","admin","mobile",
        "wp-backup","wp-content/backup","database-backup","old-site",
        "test","dev","staging","prod","fullbackup","sitebackup","webbackup",
        "config.php","config","configuration","settings","wp-config",
        "settings.php","database.php","db.php"
    }

    years = [str(y) for y in range(START_YEAR, END_YEAR + 1)]
    words = domain_wordlist(domain) | base_words
    out = set()

    for w in words:
        for e in ARCHIVE_EXTS:
            out.add(f"{w}.{e}")
            for se in SECOND_EXTS:
                out.add(f"{w}.{e}.{se}")

    for w in words:
        for e in WEB_EXTS:
            out.add(f"{w}.{e}")
            for se in SECOND_EXTS:
                out.add(f"{w}.{e}.{se}")

    for y in years:
        for e in ARCHIVE_EXTS:
            out.add(f"backup{y}.{e}")
            out.add(f"backup_{y}.{e}")
            out.add(f"backup-{y}.{e}")
            for se in SECOND_EXTS:
                out.add(f"backup{y}.{e}.{se}")

    for cp in COMMON_PATHS:
        for w in words:
            for e in ARCHIVE_EXTS:
                out.add(f"{cp}/{w}.{e}")

    out.update(SENSITIVE_FILES)
    out.update(generate_variations())
    for ap in ADMIN_PATHS:
        out.add(ap)
        for se in SECOND_EXTS:
            out.add(f"{ap}.{se}")

    for up in UPLOAD_PATHS:
        out.add(up)
        for se in SECOND_EXTS:
            out.add(f"{up}.{se}")

    out.update(TEST_FILES)

    return out

def generate_variations():
    seeds = [
        "config.php","wp-config.php","settings.php","database.php","db.php"
    ]
    suffixes = [
        "bak","old","save","backup","orig","tmp","~","swp","swo",
        "1","2","3","final","fix","new"
    ]
    double_exts = ["txt","log","zip","rar","tar","tar.gz","7z","gz"]
    years = [str(y) for y in range(2019, datetime.now().year + 1)]

    def case_variants(name):
        return {name, name.lower(), name.upper(), name.capitalize()}

    out = set()
    for seed in seeds:
        name, ext = seed.rsplit(".", 1)

        for v in case_variants(seed):
            out.add(v)

        for s in suffixes:
            out.add(f"{seed}.{s}")

        for d in double_exts:
            out.add(f"{seed}.{d}")

        for y in years:
            out.add(f"{seed}.{y}")

        for y, s in itertools.product(years, suffixes):
            out.add(f"{name}_{y}.{s}")

        for v, s in itertools.product(case_variants(seed), suffixes):
            out.add(f"{v}.{s.upper()}")

    out.update([
        ".env",".env.local",".env.prod",".env.bak",".env~",
        ".git/config",".git/HEAD",
        ".htaccess",".htpasswd",
        "composer.json","composer.lock",
        "backup.sql","database.sql","dump.sql",
        "config.zip","config.tar.gz"
    ])

    return out

# ================== CORE CHECK ==================

SENSITIVE_KEYWORDS = [
    b"password", b"passwd", b"pwd", b"pass",
    b"db ", b"database", b"db_", b"_db",
    b"config", b"cfg", b"conf",
    b"secret", b"private", b"key",
    b"token", b"jwt", b"bearer",
    b"api_key", b"apikey", b"access_key", b"client_secret",
    b"auth", b"credential", b"username", b"user",
    b"admin", b"root",
    b"hash", b"md5", b"sha",
    b"connection", b"host", b"port",
    b"mysql", b"postgres", b"postgresql", b"redis", b"mongodb", b"sqlite",
    b"table", b"schema", b"insert", b"update", b"delete", b"select",
    b"email", b"smtp", b"ftp", b"ssh", b"vpn",
    b"phpmyadmin", b"cpanel", b"wp-config", b".env",
    b"session", b"cookie", b"encryption"
]

TEXT_EXTS = [
    "text/plain", "text/css", "application/json", 
    "application/xml", "text/xml", "application/x-sh"
]

def check_url(url, tag, session):
    try:
        base = url.rsplit("/", 1)[0]
        fake_url = f"{base}/{random_path()}"

        fake = session.get(
            fake_url,
            timeout=TIMEOUT, stream=True,
            allow_redirects=True, verify=False
        )
        fake_fp = fingerprint(fake)

        real = session.get(
            url,
            timeout=TIMEOUT, stream=True,
            allow_redirects=True, verify=False
        )
        real_fp = fingerprint(real)

        if real_fp["status"] != 200:
            return ("MISS", url)

        # Check if it's a known sensitive file - auto-FOUND if 200
        url_clean = url.rstrip('/')
        for sf in SENSITIVE_FILES:
            if url_clean.endswith(sf.lstrip('/')):
                return ("FOUND", f"[{tag}] {url}")

        body = real_fp.get("body", b"").lower()
        if any(x in body for x in [b"login", b"signin", b"password", b"access denied", b"forbidden", b"403", b"404", b"not found"]):
            return ("MISS", url)

        if real_fp["length"] < 100:
            return ("MISS", url)

        if "text/html" in real_fp["ctype"]:
            if (real_fp["hash"] == fake_fp["hash"] and
                abs(real_fp["length"] - fake_fp["length"]) < LEN_TOL):
                return ("MISS", url)

            body = real_fp["body"].lower()
            if any(x in body for x in [b"404", b"not found", b"forbidden"]):
                return ("MISS", url)

            return ("FOUND", f"[{tag}] {url}")

        ctype = real_fp["ctype"]
        if any(t in ctype for t in TEXT_EXTS):
            if any(k in body for k in SENSITIVE_KEYWORDS):
                return ("FOUND", f"[{tag}] {url}")
            return ("MISS", url)

        return ("FOUND", f"[{tag}] {url}")

    except:
        return ("ERROR", url)
    finally:
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

# ================== WORKER ==================

def worker(q, results, total, lock, processed):
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=2, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    
    while True:
        item = q.get()
        if item is None:
            break

        url, tag = item
        status, data = check_url(url, tag, session)

        if status == "FOUND":
            print(f"{GREEN}[FOUND]{RESET} {data}", flush=True)
        elif status == "MISS":
            print(f"{RED}[MISS]{RESET} {data}", flush=True)
        else:
            print(f"{YELLOW}[ERROR]{RESET} {data}", flush=True)

        with lock:
            processed[0] += 1

        results.append((status, data))
        q.task_done()

def progress_thread(processed, total, lock):
    spinner = ["0", "x", "+", "-", "/", "\\", "*", "o", "O", "@", "#", "%", "=", ":", ".", "~"]
    idx = 0
    while True:
        with lock:
            done = processed[0]
        
        if done >= total:
            print(file=sys.stderr)
            break
        
        spin = spinner[idx % len(spinner)]
        idx += 1
        print(f"{spin}", end="\r", flush=True, file=sys.stderr)
        time.sleep(0.2)

requests.packages.urllib3.disable_warnings()

# ================== INPUT ==================

print("\n[1] Mass Scan (file)")
print("[2] Single Target\n")
mode = input("Pilih Mode : ").strip()

targets = []
if mode == "1":
    fname = input("Nama file : ").strip()
    with open(fname) as f:
        targets = [ensure_https(x.strip()) for x in f if x.strip()]
elif mode == "2":
    targets.append(ensure_https(input("Target domain: ").strip()))
else:
    exit()

# ================== MAIN ==================

for target in targets:
    domain = urlparse(target).netloc
    print(f"\nTARGET → {domain}\n")

    urls = [(f"{target}/{f}", "ARCHIVE") for f in generate_archive_files(domain)]

    q = Queue()
    results = []

    for u in urls:
        q.put(u)

    lock = threading.Lock()
    processed = [0]
    total = len(urls)

    threads = []
    for _ in range(MAX_WORKERS):
        t = threading.Thread(target=worker, args=(q, results, total, lock, processed))
        t.start()
        threads.append(t)

    p = threading.Thread(target=progress_thread, args=(processed, total, lock))
    p.start()

    q.join()
    p.join()
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()

    found = [d for s, d in results if s == "FOUND"]

    if found:
        import os
        clean = domain.replace("www.", "")
        parts = clean.split(".")
        sld = {"co.id","ac.id","sch.id","go.id","or.id","web.id","my.id"}
        last_two = ".".join(parts[-2:])
        if last_two in sld and len(parts) >= 3:
            folder_name = parts[-3]
        elif len(parts) >= 2:
            folder_name = parts[-2]
        else:
            folder_name = parts[0]
        
        base_folder = folder_name
        suffix = ".result"
        counter = 0
        
        while os.path.isfile(folder_name):
            counter += 1
            folder_name = f"{base_folder}{suffix}{counter}"
        
        os.makedirs(folder_name, exist_ok=True)
        with open(f"{folder_name}/{domain}.txt", "w") as f:
            for x in found:
                f.write(x + "\n")

    print("\nSTATUS SUMMARY")
    print(f"Total Checked : {len(results)}")
    print(f"Found         : {len(found)}\n")
