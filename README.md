Ardes: Alat za skeniranje i pretragu sigurnosnih ranjivosti
Ardes je alat razvijen za skeniranje IP adresa, detekciju portova, brute-force napade na direktorijume, kao i pretragu exploit-a u bazi podataka Exploit-DB. Kombinuje različite tehnike za analizu sigurnosti i pruža korisnicima efikasne alate za istraživanje potencijalnih ranjivosti.

# Struktura projekta
Projekat je organizovan u sledećoj strukturi direktorijuma:

Ardes/
README.md: Detaljan opis alata i uputstvo za korišćenje
requirements.txt: Lista Python zavisnosti (nmap, requests, beautifulsoup4...)
ardes.py: Glavni ulazni fajl (CLI interfejs)

core/
scanner.py: Modul za skeniranje IP adresa i detekciju portova (80/8080)
dirbuster.py: Modul za brute-force napade na direktorijume (koristi wordlist + requests)
fetcher.py: Modul za curl/GET zahteve i parsiranje HTML stranica
fingerprint.py: Modul za prepoznavanje alata i verzija korišćenjem regex-a i heuristika
exploit_search.py: Modul za slanje upita na Exploit-DB (web scraping ili API)
utils.py: Pomoćne funkcije (logovanje, validacija IP adresa, itd.)

data/
common_dirs.txt: Wordlist za brute-force napade na direktorijume
fingerprints.json: JSON šabloni (regex) za detekciju alata i verzija
results/: Direktorijum za snimanje rezultata skeniranja

reports/
scan_2025-09-05.txt: Primer izlaznog fajla sa rezultatima skeniranja
exploits.json: JSON fajl sa pronađenim exploit-ima


# Uputstvo za korišćenje
Instalacija
Da biste pokrenuli Ardes na svom računaru, prvo morate instalirati sve potrebne Python zavisnosti. To možete uraditi pomoću sledeće komande:
pip install -r requirements.txt

....
