# 🛡️ Cheat Sheet — SOC Analyst / Blue Team

Analyse de logs, requêtes SIEM, threat hunting et réponse à incident pour les épreuves de type investigation.

---

## 1. Analyse de logs en ligne de commande

```bash
# Filtrage / recherche
grep -i "failed password" /var/log/auth.log
grep -rniE "error|denied|unauthorized" /var/log/
zgrep "pattern" /var/log/*.gz              # Dans les logs compressés

# Compter et classer (top IP, top users…)
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
cut -d' ' -f1 access.log | sort | uniq -c | sort -rn   # Top IP sources

# Brute force SSH : IP avec le plus d'échecs
grep "Failed password" auth.log | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" \
  | sort | uniq -c | sort -rn

# Fenêtre temporelle
awk '$0 >= "10:00:00" && $0 <= "11:00:00"' app.log
sed -n '/08:00/,/09:00/p' app.log

# Logs systemd
journalctl -u ssh --since "2024-01-01" --until "today"
journalctl -p err -b                        # Erreurs du boot courant
```

### Logs web (Apache/Nginx) — motifs d'attaque

```bash
# Codes de réponse
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# Scans / fuzzing (beaucoup de 404)
awk '$9==404 {print $7}' access.log | sort | uniq -c | sort -rn | head

# Tentatives SQLi / LFI / XSS dans les URL
grep -iE "union.*select|\.\./|<script>|/etc/passwd|base64_" access.log

# User-Agents suspects (outils)
grep -iE "sqlmap|nikto|nmap|gobuster|ffuf|curl|wget" access.log
```

---

## 2. Journaux d'événements Windows

```powershell
# Récupérer des événements
Get-WinEvent -LogName Security -MaxEvents 100
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}   # Échecs de login
wevtutil qe Security /c:50 /f:text

# Depuis un .evtx exporté
Get-WinEvent -Path capture.evtx | Where-Object {$_.Id -eq 4688}
```

### Event IDs à connaître

| ID | Signification |
|----|---------------|
| 4624 | Connexion réussie |
| 4625 | Échec de connexion |
| 4634 / 4647 | Déconnexion |
| 4672 | Connexion avec privilèges élevés |
| 4688 | Création de processus (ligne de commande) |
| 4720 | Création de compte utilisateur |
| 4728/4732 | Ajout à un groupe privilégié |
| 7045 | Installation d'un service (persistance) |
| 1102 | Journal de sécurité effacé (⚠️) |
| Sysmon 1 | Création de processus (détaillé) |
| Sysmon 3 | Connexion réseau |
| Sysmon 11 | Création de fichier |

---

## 3. Requêtes SIEM

### Splunk (SPL)

```spl
index=main sourcetype=access_combined status=404
| stats count by clientip | sort -count

index=win EventCode=4625
| stats count by Account_Name, src_ip | where count > 10

index=* | search "powershell" "EncodedCommand"
| table _time, host, CommandLine
```

### ELK / Kibana (KQL)

```kql
event.code: "4625" and source.ip: "10.0.0.5"
user.name: "admin" and event.action: "logon-failed"
process.command_line: *Invoke-Expression* or process.command_line: *DownloadString*
```

---

## 4. Threat hunting & IOC

```bash
# Extraire des IOC d'un fichier (IP, domaines, hashes)
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" fichier | sort -u          # IP
grep -oE "[a-f0-9]{32}" fichier | sort -u                          # MD5
grep -oE "[a-f0-9]{64}" fichier | sort -u                          # SHA256
grep -oE "https?://[^ \"']+" fichier | sort -u                     # URL

# Hash d'un fichier suspect
sha256sum suspect.exe
# → à comparer sur VirusTotal / base d'IOC

# YARA : détecter un malware par signature
yara regles.yar ./echantillon
yara -r regles.yar /chemin/           # Récursif
```

Exemple de règle YARA minimale :

```yara
rule Webshell_PHP {
    strings:
        $a = "eval($_POST"
        $b = "system($_GET"
    condition:
        any of them
}
```

---

## 5. Analyse réseau (détection)

```bash
# Suricata (IDS)
suricata -r capture.pcap -l ./out/
cat out/fast.log                      # Alertes

# Zeek (ex-Bro) — logs structurés
zeek -r capture.pcap
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service
cat http.log | zeek-cut host uri
cat dns.log | zeek-cut query          # Exfil DNS / DGA ?
```

---

## 6. Réponse à incident — réflexes

1. **Identifier** : quel hôte, quel compte, quelle heure (construire une timeline).
2. **Corréler** : croiser logs auth + réseau + process (4688/Sysmon 1).
3. **IOC** : extraire IP, domaines, hashes ; vérifier la réputation.
4. **Persistance** : services (7045), tâches planifiées, comptes créés (4720).
5. **Exfiltration** : gros volumes sortants, DNS anormal, requêtes régulières (beaconing).
6. **Confinement** : isoler l'hôte, révoquer le compte.

> Le flag est souvent : une IP d'attaquant, un nom d'utilisateur compromis, un hash,
> une heure précise ou une commande décodée (ex. PowerShell `-EncodedCommand` en base64).

```bash
# Décoder un PowerShell -EncodedCommand (UTF-16LE base64)
echo "BASE64_ICI" | base64 -d | iconv -f UTF-16LE -t UTF-8
```