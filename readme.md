# Tunelování datových přenosů přes DNS dotazy
ISA - Sieťové aplikácie a správa sietí
VUT FIT
Matej koreň, xkoren10

## make:
Preloženie celého projektu:\
`make` alebo `make all`\
Preloženie serverovej aplikácie:\
`make receiver`\
Preloženie klientskej aplikácie:\
`make sender`\
Vyčistenie binárnych súborov:\
`make clean`

## Serverová aplikácia/ receiver:
Server počúva na implicitnom porte pre DNS komunikáciu (port 53) a prichádzajúce dátové prenosy ukladá na disk vo forme súboru. Spustenie programu je podľa nasledujúceho predpisu:

`dns_receiver {BASE_HOST} {DST_DIRPATH}`

* BASE_HOST je parameter určujúci bázovú doménu prenosov
* DST_DIRPATH je cesta, pod ktorou sa dáta ukladajú na serveri

Príklad spustenia:\
`./dns_receiver www.example.com ./data`

## Klientska aplikácia / sender:
Klientska aplikácia odosiela dáta zo súboru / štandardného vstupu.  Spustenie programu je podľa nasledujúceho predpisu:

`dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]`

* Prepínač –u slúži na vynútenie vzdialeného DNS serveru ( ak nie je zadaný, použije sa prvý implicitný DNS server zo súboru etc/resolv.conf
* BASE_HOST je parameter určujúci bázovú doménu prenosov
* DST_FILEPATH je cesta, pod ktorou sa dáta uložia na serveri
* SRC_FILEPATH je cesta k súboru na odoslanie (ak nie je zdaná, číta sa z STDIN)

Príklady použitia:\
`echo "abc" | ./dns_sender -u 127.0.0.1 example.com data.txt`
`./dns_sender -u 127.0.0.1 www.example.com data.txt ./data.txt`\
`./dns_sender www.example.com data.txt <data.txt`\
`./dns_sender www.example.com data.txt ./data.txt`