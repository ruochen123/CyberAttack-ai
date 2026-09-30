"""Attack chain correlation (改造⑦-②).

Fingerprint a web target (whatweb + httpx headers), map components/versions onto
known exploit knowledge (searchsploit CVE/exploit ids, nuclei tags, msf modules),
and produce an actionable "component -> candidate exploit" list.
"""
import json
import re
import subprocess
from typing import Any, Dict, List

WHATWEB = "whatweb"
HTTPX = "httpx"
SEARCHSPLOIT = "searchsploit"

# keyword(ci) -> (name, nuclei tag, msf module hint, searchsploit term)
RULES: List[tuple] = [
    ("shiro", "Apache Shiro", "shiro", "", "shiro"),
    ("thinkphp", "ThinkPHP", "thinkphp", "", "thinkphp"),
    ("wordpress", "WordPress", "wordpress", "exploit/unix/webapp/wp_admin_shell_upload", "wordpress"),
    ("tomcat", "Apache Tomcat", "tomcat", "exploit/multi/http/tomcat_mgr_upload", "tomcat"),
    ("struts", "Apache Struts2", "struts", "", "struts2"),
    ("weblogic", "Oracle WebLogic", "weblogic", "", "weblogic"),
    ("drupal", "Drupal", "drupal", "exploit/unix/webapp/drupal_drupalgeddon2", "drupal"),
    ("joomla", "Joomla", "joomla", "", "joomla"),
    ("phpmyadmin", "phpMyAdmin", "phpmyadmin", "", "phpmyadmin"),
    ("laravel", "Laravel", "laravel", "", "laravel"),
    ("gitlab", "GitLab", "gitlab", "", "gitlab"),
    ("jenkins", "Jenkins", "jenkins", "exploit/multi/http/jenkins_script_console", "jenkins"),
    ("apache", "Apache HTTPD", "apache", "", "apache"),
    ("nginx", "nginx", "nginx", "", "nginx"),
    ("iis", "Microsoft IIS", "iis", "", "iis"),
    ("php", "PHP", "php", "", "php"),
    ("grails", "Grails", "grails", "", "grails"),
    ("spring", "Spring Framework", "spring", "", "spring"),
    ("symfony", "Symfony", "symfony", "", "symfony"),
    ("django", "Django", "django", "", "django"),
    ("rails", "Ruby on Rails", "rails", "", "rails"),
    ("solr", "Apache Solr", "solr", "", "solr"),
    ("elasticsearch", "Elasticsearch", "elasticsearch", "", "elasticsearch"),
]

_VRE = re.compile(r"\[([0-9][0-9A-Za-z._-]*)\]")


def _version(line: str, kw: str = "") -> str:
    if kw:
        m = re.search(re.escape(kw) + r"\[([0-9][0-9A-Za-z._-]*)\]", line, re.I)
        if m:
            return m.group(1)
    m = _VRE.search(line)
    return m.group(1) if m else ""


def _searchsploit(term: str, limit: int = 4) -> List[str]:
    try:
        r = subprocess.run([SEARCHSPLOIT, term, "--json"], capture_output=True, text=True, timeout=45)
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout)
        hits = data.get("results", {}).get("exploitdb", []) or data.get("EXPLOITDB", [])
        return [f"{h.get('Title','')} [{h.get('Exploit-DB ID','')}]"
                for h in hits[:limit] if isinstance(h, dict)]
    except Exception:
        return []


def _components(url: str) -> List[Dict[str, Any]]:
    comps: Dict[str, Dict[str, Any]] = {}
    try:
        out = subprocess.run([WHATWEB, "--color=never", "-a", "3", url],
                             capture_output=True, text=True, timeout=90).stdout
    except Exception:
        out = ""
    # each whatweb output line is like "  X-... [a[1.2], b]"
    lines = out.splitlines()
    for line in lines:
        for kw, name, ntag, msf, sterm in RULES:
            if kw in line.lower():
                c = comps.setdefault(name, {"name": name, "version": "", "nuclei_tags": [], "msf": "", "searchsploit": []})
                if ntag and ntag not in c["nuclei_tags"]:
                    c["nuclei_tags"].append(ntag)
                if msf and not c["msf"]:
                    c["msf"] = msf
                if mode := re.search(re.escape(kw) + r"\[([0-9][0-9A-Za-z._-]*)\]", line, re.I):
                    c["version"] = c["version"] or mode.group(1)
    # shiro detection via rememberMe cookie header (GET, dump headers)
    try:
        h = subprocess.run(["curl", "-s", "-D", "-", "-o", "/dev/null", "-m", "15", url],
                           capture_output=True, text=True, timeout=20).stdout
        if "rememberme=" in h.lower():
            comps.setdefault("Apache Shiro", {"name": "Apache Shiro", "version": "", "nuclei_tags": ["shiro"], "msf": "", "searchsploit": []})
    except Exception:
        pass
    return list(comps.values())


def attack_chain(url: str, searchsploit_limit: int = 4) -> Dict[str, Any]:
    comps = _components(url)
    for c in comps:
        terms = []
        if c["version"]:
            terms.append(f"{c['name'].lower()} {c['version']}")
        terms.append(c["name"].lower())
        if c["name"] == "Apache Shiro":
            terms.append("shiro")
        seen = []
        for t in terms:
            seen += _searchsploit(t, searchsploit_limit)
        c["searchsploit"] = seen[:searchsploit_limit]
    return {
        "success": True,
        "target": url,
        "component_count": len(comps),
        "components": comps,
        "tip": "run nuclei with tags above (e.g. -tags shiro,then check shiro key; "
               "use the msf module or searchsploit exploit id to move from recon to exploitation",
    }