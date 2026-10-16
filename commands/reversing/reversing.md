# 🧩 Cheat Sheet — Reverse Engineering

Analyse statique et dynamique de binaires pour les épreuves de reversing.

---

## 1. Premier contact avec le binaire

```bash
file prog                        # Type, architecture, statique/dynamique, stripped ?
strings -n 6 prog                # Chaînes (flag en clair ? messages ?)
strings -e l prog                # Chaînes UTF-16 (binaires Windows)
nm prog                          # Symboles (si non stripped)
rabin2 -I prog                   # Infos (arch, protections, langage) — radare2
checksec --file=prog             # Protections : NX, PIE, Canary, RELRO
```

Détecter / enlever un packer :

```bash
upx -d prog                      # Désempaqueter UPX
# Entropie élevée + peu de strings = souvent packé
```

---

## 2. Analyse statique

### objdump / readelf

```bash
objdump -d prog                  # Désassemblage
objdump -d -M intel prog         # Syntaxe Intel (plus lisible)
objdump -s -j .rodata prog       # Dump d'une section (données)
readelf -h prog                  # En-tête ELF
readelf -S prog                  # Sections
readelf -r prog                  # Relocations (fonctions importées)
```

### radare2 / rizin

```bash
r2 -A prog                       # Ouvrir + analyser
# Dans r2 :
aaa            # Analyse complète
afl            # Lister les fonctions
pdf @ main     # Désassembler main
s main ; VV    # Vue graphe
iz             # Chaînes dans data
axt @ sym.str  # Qui référence cette chaîne
```

### Décompilateurs (GUI)

- **Ghidra** — gratuit, décompile en pseudo-C. `Window > Decompiler`.
- **IDA Free / Cutter** — décompilation + graphe.
- Workflow : chercher `main` → suivre la logique de vérification du flag.

---

## 3. Analyse dynamique

```bash
ltrace ./prog                    # Appels de bibliothèque (strcmp du flag !)
strace ./prog                    # Appels système (open, read, ptrace…)
```

> `ltrace` révèle souvent directement le `strcmp(input, "le_vrai_flag")`.

### GDB (avec pwndbg / GEF)

```bash
gdb ./prog
```
```gdb
break main              # Point d'arrêt
run                     # Lancer
run < input.txt         # Lancer avec une entrée
continue / c            # Continuer
nexti / ni              # Pas à pas (sans entrer)
stepi / si              # Pas à pas (en entrant)
info functions          # Lister les fonctions
disassemble main        # Désassembler
break *0x401234         # BP à une adresse
x/20xw $rsp             # Examiner la pile (20 mots hex)
x/s 0x4005f0            # Lire une chaîne
info registers          # Registres
set $rax = 1            # Modifier un registre (forcer un chemin)
```

Patcher une comparaison pour contourner une vérif (ex. forcer un saut) :
- Repérer le `jne`/`jz` qui garde la « mauvaise » branche, le remplacer par `nop`/`jmp` dans r2 (`wa`) ou Ghidra.

---

## 4. Langages managés

### .NET / C#

```bash
# dnSpy (Windows) ou ilspycmd — décompilation quasi parfaite du code source
ilspycmd prog.exe
monodis prog.exe                 # Désassembler IL
```

### Java / JAR

```bash
# jd-gui (GUI) ou procyon/CFR
cfr prog.jar --outputdir out/
unzip prog.jar -d extrait/
javap -c -p Classe.class         # Désassembler le bytecode
```

### Python « compilé »

```bash
# PyInstaller / py2exe
python pyinstxtractor.py prog.exe        # Extraire les .pyc
uncompyle6 module.pyc                      # Décompiler (Py <=3.8)
decompyle3 module.pyc                       # Py 3.7-3.9
```

---

## 5. Android (APK)

```bash
apktool d app.apk -o out/        # Décoder ressources + smali
jadx -d out/ app.apk             # Décompiler en Java (le plus simple)
jadx-gui app.apk                 # Version graphique
# Chercher le flag / endpoints / clés
grep -rniE "flag|http|secret|key" out/
```

---

## 6. Astuces CTF reversing

- Chercher le flag en clair d'abord (`strings`) — parfois trop simple.
- `ltrace` pour voir le `strcmp` de validation.
- Si le flag est « calculé » (XOR, addition par caractère) : retrouver l'algo dans le décompilateur et l'inverser en Python.
- Anti-debug (`ptrace`) : patcher l'appel ou mettre un BP avant pour le neutraliser.
- Flag souvent sous forme `flag{...}` / `CTF{...}` → `strings prog | grep -iE "flag\{|ctf\{"`.

Exemple d'inversion d'un XOR trouvé dans le binaire :

```python
enc = [0x3b, 0x2f, 0x2a, 0x7c]   # octets lus dans .rodata
key = 0x5a
print("".join(chr(b ^ key) for b in enc))
```