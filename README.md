# Ardes

## Struktura projekta
Ardes/
├── README.md                # Opis alata, uputstvo za korišćenje
├── requirements.txt         # Python zavisnosti (nmap, requests, beautifulsoup4...)
├── ardes.py                 # Glavni ulazni fajl (CLI interfejs)
│
├── core/                    # Glavna logika alata
│   ├── scanner.py           # Modul za skeniranje IP adrese i otkrivanje portova 80/8080
│   ├── dirbuster.py         # Modul za brute-force direktorijuma (wordlist + requests)
│   ├── fetcher.py           # Modul za curl/GET stranica i parsiranje HTML-a
│   ├── fingerprint.py       # Modul za detekciju alata i verzija (regex + heuristike)
│   ├── exploit_search.py    # Modul koji šalje query na Exploit-DB (web scraping ili API)
│   └── utils.py             # Pomoćne funkcije (logger, validacija IP-a, itd.)
│
├── data/                    # Wordlist-i i pomoćni fajlovi
│   ├── common_dirs.txt      # Lista za dir busting
│   ├── fingerprints.json    # Šabloni (regex) za prepoznavanje alata i verzija
│   └── results/             # Snimljeni rezultati skeniranja
│
├── reports/                 # Izlazni fajlovi (rezultati)
│   ├── scan_2025-09-05.txt  # Primer izlaza skeniranja
│   └── exploits.json        # Nađeni exploit-i
│
└── tests/                   # Jednostavni testovi za module
    ├── test_scanner.py
    ├── test_dirbuster.py
    └── ...
