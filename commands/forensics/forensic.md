# 🔍 Cheat Sheet — Forensic CTF

Commandes de référence pour les épreuves forensic (fichiers, stégano, réseau, mémoire, disque).

---

## 1. Identification & inspection de fichiers

```bash
file suspect.bin                 # Type réel du fichier (magic bytes)
exiftool image.jpg               # Métadonnées (GPS, auteur, dates, commentaires)
strings -n 6 fichier             # Chaînes imprimables >= 6 caractères
strings -e l fichier             # Chaînes UTF-16LE (fréquent sous Windows)
xxd fichier | less               # Dump hexadécimal
hexdump -C fichier | head        # Dump hex + ASCII
binwalk fichier                  # Détecter fichiers embarqués / signatures
binwalk -e fichier               # Extraire les fichiers embarqués
binwalk -Me fichier              # Extraction récursive
foremost -i disk.img -o out/     # Carving par signatures
photorec disk.img                # Récupération interactive de fichiers
```

Réparer / vérifier une image corrompue (ex. PNG dont les magic bytes ont été modifiés) :

```bash
xxd image.png | head             # Vérifier l'en-tête (PNG = 89 50 4E 47)
pngcheck -v image.png            # Diagnostiquer un PNG
```

---

## 2. Stéganographie

```bash
steghide extract -sf image.jpg               # Extraire (demande le mot de passe)
steghide info image.jpg                       # Infos sur données cachées
stegseek image.jpg wordlist.txt               # Bruteforce passphrase steghide (rapide)
zsteg image.png                               # LSB / stégano PNG & BMP
zsteg -a image.png                            # Tous les tests zsteg
outguess -r image.jpg out.txt                 # Extraction outguess
exiftool -b -ThumbnailImage img.jpg > t.jpg   # Extraire une miniature cachée
```

Analyse visuelle (plans de bits, canaux de couleur) :

```bash
# Ouvrir dans Stegsolve (GUI) : java -jar stegsolve.jar
convert image.png -separate canal_%d.png      # Séparer les canaux RVB
```

Audio :

```bash
sox audio.wav -n spectrogram -o spec.png      # Spectrogramme (flag parfois dedans)
# Sinon : Audacity / Sonic Visualiser en mode spectrogramme
```

---

## 3. Analyse réseau (PCAP)

```bash
tshark -r capture.pcap                                  # Lister les paquets
tshark -r capture.pcap -q -z io,phs                     # Hiérarchie des protocoles
tshark -r capture.pcap -q -z conv,tcp                   # Conversations TCP
tshark -r capture.pcap -Y "http.request" \
       -T fields -e http.host -e http.request.uri       # URLs HTTP demandées
tshark -r capture.pcap --export-objects http,./objets/  # Extraire les fichiers HTTP
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name  # Requêtes DNS (exfil ?)

# Suivre un flux TCP précis
tshark -r capture.pcap -z follow,tcp,ascii,0 -q

# Extraire des credentials transitant en clair
tcpdump -r capture.pcap -A | grep -i -E "pass|user|login"
```

### ⭐ Récupérer les beacons et faire la moyenne des secondes (6 décimales)

Un *beacon* = paquet périodique émis vers un C2 (ex. toutes les X secondes vers une IP/port fixe).
On extrait les timestamps des paquets vers la cible, puis on calcule une moyenne arrondie à **6 décimales**.

**A. Moyenne de l'intervalle entre deux beacons (le plus courant)** — « toutes les combien de secondes » :

```bash
tshark -r capture.pcap -Y "ip.dst == 10.10.10.10 && tcp.port == 4444" \
       -T fields -e frame.time_epoch \
  | awk 'NR>1 {sum += $1 - prev; n++} {prev = $1} END {printf "%.6f\n", sum/n}'
```

**B. Moyenne de la partie « secondes » (fraction sous-seconde) des timestamps :**

```bash
tshark -r capture.pcap -Y "ip.dst == 10.10.10.10" \
       -T fields -e frame.time_epoch \
  | awk -F. '{ s += ("0." $2) } END { printf "%.6f\n", s/NR }'
```

**C. Variante générique si tu n'as qu'une liste de timestamps dans un fichier :**

```bash
# timestamps.txt = une valeur epoch par ligne
awk '{ s += $1; n++ } END { printf "%.6f\n", s/n }' timestamps.txt
```

> Adapte le filtre `-Y` : `ip.dst`, `tcp.dstport`, `http.host`… selon la destination du beacon.
> Pour repérer la cible, commence par `tshark -r capture.pcap -q -z conv,ip` et regarde l'IP qui revient à intervalle régulier.

---

## 4. Forensic mémoire (Volatility)

```bash
# Volatility 3
vol -f memory.dmp windows.info                 # OS / profil
vol -f memory.dmp windows.pslist               # Processus
vol -f memory.dmp windows.pstree               # Arbre des processus
vol -f memory.dmp windows.cmdline              # Lignes de commande
vol -f memory.dmp windows.netscan              # Connexions réseau
vol -f memory.dmp windows.filescan             # Fichiers en mémoire
vol -f memory.dmp windows.dumpfiles --virtaddr 0xADDR   # Extraire un fichier
vol -f memory.dmp windows.hashdump             # Hashes NTLM

# Volatility 2 (profil requis)
volatility -f memory.dmp imageinfo
volatility -f memory.dmp --profile=Win7SP1x64 pslist
```

---

## 5. Disque & systèmes de fichiers

```bash
mmls disk.img                    # Table des partitions
fls -r -o 2048 disk.img          # Lister fichiers (offset = début partition)
icat -o 2048 disk.img INODE      # Extraire un fichier par inode
tsk_recover -o 2048 disk.img out/   # Récupérer les fichiers supprimés
mount -o ro,loop disk.img /mnt   # Monter en lecture seule
```

---

## 6. Divers utile

```bash
# Décodage rapide
echo "ZmxhZw==" | base64 -d
echo "666c6167" | xxd -r -p
tr 'A-Za-z' 'N-ZA-Mn-za-m' <<< "synt"       # ROT13

# Archives protégées
zip2john archive.zip > h.txt && john h.txt --wordlist=rockyou.txt
john --show h.txt

# Git « oublié » sur un dump
git log --all --oneline
git show <commit>
```

---

## 7. Réflexe méthodologique

1. `file` + `exiftool` + `binwalk` sur **tout** fichier reçu.
2. `strings` systématique (ASCII puis UTF-16).
3. Chercher le pattern du flag : `strings fichier | grep -iE "flag\{|CTF\{"`.
4. Si image/audio → stégano. Si `.pcap` → tshark. Si `.dmp`/`.raw` → Volatility. Si `.img`/`.dd` → Sleuth Kit.