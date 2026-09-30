"""Horizontal authorization (IDOR) differencing check (改造⑦-④).

Walks object IDs on an API/URL template with {id} and compares responses as seen
by a privileged session, a low-privilege session, and anonymous access. Objects
that reply to the low-priv/anonymous request with data similar to the privileged
one are flagged as potential IDOR / broken object-level authorization.
"""
from typing import Any, Dict, List


def idor_check(base_url: str, start: int = 1, end: int = 10, ids: str = "",
               method: str = "GET", cookie_a: str = "", cookie_b: str = "",
               bearer_a: str = "", bearer_b: str = "", threshold: int = 0,
               timeout: int = 20) -> Dict[str, Any]:
    import requests
    import warnings
    from urllib3.exceptions import InsecureRequestWarning
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    if "{id}" not in base_url:
        return {"success": False, "error": "base_url must contain {id} (e.g. /api/user/{id}/details)"}
    id_list = [int(x) for x in ids.split(",") if x.strip().isdigit()] or list(range(start, end + 1))
    s = requests.Session()
    s.verify = False

    def call(cookie: str = "", bearer: str = "") -> tuple:
        h = {}
        if cookie:
            h["Cookie"] = cookie
        if bearer:
            h["Authorization"] = f"Bearer {bearer}"
        r = s.request(method, base_url.format(id=id_), headers=h, timeout=timeout, allow_redirects=False)
        return r.status_code, len(r.content), r.text[:1500]

    rows: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    prev_a = None
    for id_ in id_list:
        code_a, len_a, body_a = call(cookie_a, bearer_a)
        code_b, len_b, body_b = call(cookie_b, bearer_b)
        anon_code, anon_len, _ = call()
        note = []
        if code_b == 200 and len_b > 0:
            ratio = (len_b / max(len_a, 1)) if len_a else 0
            similar = 0.5 <= ratio <= 1.5
            if similar:
                note.append(f"low-priv {code_b} sees ~same data as priv ({ratio:.0%})")
        else:
            note.append(f"low-priv blocked ({code_b})")
        if anon_code in (200,) and anon_len > 0:
            note.append(f"anonymous {anon_code} len={anon_len}")
            if len_a and 0.5 <= (anon_len / len_a) <= 1.5:
                note.append("anon data ~identical to privileged -> IDOR")
        rows.append({"id": id_, "priv": code_a, "priv_len": len_a,
                     "low": code_b, "low_len": len_b, "anon": anon_code, "anon_len": anon_len})
        if any("identical" in n or "similar" in n for n in note):
            findings.append({"id": id_, "note": "; ".join(note)})
    return {
        "success": True,
        "base_url": base_url,
        "checked": len(id_list),
        "findings": findings,
        "rows": rows[:100],
        "tip": "objects flagged here respond to low-priv/anonymous access like the privileged path; verify manually",
    }