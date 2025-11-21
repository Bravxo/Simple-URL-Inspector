#!/usr/bin/env python3
from art import *
import argparse
import requests
import tldextract
from bs4 import BeautifulSoup
import hashlib

# Lista de tipos de contenido peligrosos
DANGEROUS_CT = [
    "application/x-msdownload",
    "application/javascript",
    "application/zip",
    "application/x-7z-compressed",
    "application/vnd.ms-cab-compressed",
    "application/vnd.microsoft.portable-executable"
]

def fetch_url(url):
    return requests.get(url, timeout=10, allow_redirects=True)

def analyze_domain(url):
    ext = tldextract.extract(url)
    return {
        "domain": f"{ext.domain}.{ext.suffix}",
        "subdomain": ext.subdomain,
        "tld": ext.suffix
    }

def analyze_redirects(resp):
    return {
        "redirects": len(resp.history),
        "chain": [h.url for h in resp.history] + [resp.url]
    }

def analyze_html(resp):
    soup = BeautifulSoup(resp.text, "html.parser")
    inputs = [i.get("type","").lower() for i in soup.find_all("input")]
    has_password = "password" in inputs
    has_otp = any("otp" in (i.get("name","")+i.get("id","")).lower() for i in soup.find_all("input"))
    keywords = ["login","verify","account","update","security","password","otp","token"]
    text = soup.get_text(" ").lower()
    hits = [k for k in keywords if k in text]
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    #Favicon hashh
    favicon_hash = None
    icon = soup.find("link", rel=lambda v: v and "icon" in v.lower())
    if icon and icon.get("href"):
        try:
            ico_url = requests.compat.urljoin(resp.url, icon["href"])
            ico = requests.get(ico_url, timeout=5)
            favicon_hash = hashlib.sha256(ico.content).hexdigest()
        except Exception:
            pass
    return {
        "title": title,
        "has_password": has_password,
        "has_otp": has_otp,
        "keyword_hits": hits,
        "favicon_hash": favicon_hash
    }

def analyze_js(resp):
    soup = BeautifulSoup(resp.text, "html.parser")
    scripts = soup.find_all("script")
    indicators = []
    for s in scripts:
        code = s.string or ""
        if any(k in code for k in ["eval(", "new Function", "atob(", "unescape("]):
            indicators.append("JS ofuscado")
        if "addEventListener" in code and "keypress" in code:
            indicators.append("Keylogger-like")
    return {"script_count": len(scripts), "indicators": indicators} 

def analyze_downloads(resp):
    ct = resp.headers.get("Content-Type","").lower()
    cd = resp.headers.get("Content-Disposition","").lower()
    auto_download = "attachment" in cd or any(d in ct for d in DANGEROUS_CT)
    return {"content_type": ct, "auto_download": auto_download}

def score(domain, redirects, html, js, dl):
    s = 0
    if redirects["redirects"] > 2: s += 10
    if html["has_password"]: s += 30
    if html["has_otp"]: s += 20
    if html["keyword_hits"]: s += 20
    if js["indicators"]: s += 15
    if dl["auto_download"]: s += 25
    return min(s, 100)

def main():
    parser = argparse.ArgumentParser(description="Phishing/Malware Link Inspector")
    parser.add_argument("url", help="URL sospechosa a analizar")
    args = parser.parse_args()
    tprint("Simple Inspector")
    print("\n=== SIMPLE Phishing/Malware Inspector ===")

    try:
        resp = fetch_url(args.url)
        domain = analyze_domain(resp.url)
        redirects = analyze_redirects(resp)
        html = analyze_html(resp)
        js = analyze_js(resp)
        dl = analyze_downloads(resp)
        risk = score(domain, redirects, html, js, dl)

        print(f"\nURL final: {resp.url}")
        print(f"Dominio: {domain['domain']} (Subdominio: {domain['subdomain']}, TLD: {domain['tld']})")
        print(f"Redirecciones: {redirects['redirects']} → {redirects['chain']}")
        print(f"Título de la página: {html['title']}")
        print(f"Formulario de login: {html['has_password']}")
        print(f"Campo OTP: {html['has_otp']}")
        print(f"Palabras clave sospechosas: {', '.join(html['keyword_hits']) if html['keyword_hits'] else '—'}")
        print(f"Favicon hash: {html['favicon_hash'] or '—'}")
        print(f"Scripts detectados: {js['script_count']} → {', '.join(js['indicators']) if js['indicators'] else '—'}")
        print(f"Tipo de contenido: {dl['content_type']}")
        print(f"Descarga automática sospechosa: {dl['auto_download']}")
        print(f"\n>>> Riesgo estimado: {risk}/100 <<<\n")

    except requests.exceptions.ConnectionError:
        print("El dominio no existe o no responde. Esto puede ser un intento de phishing con un dominio falso... (o no)")
    except Exception as e:
        print(f"Error al analizar: {e}")

if __name__ == "__main__":
    main()

