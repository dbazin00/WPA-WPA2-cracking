### SVEUČILIŠTE U SPLITU

### FAKULTET ELEKTROTEHNIKE, STROJARSTVA I

### BRODOGRADNJE

### Split, siječanj 2021.

PROBIJANJE WPA/WPA2 LOZINKI

```
Luka Rosić
Davor Bazina
```

## Sadržaj

- 1. Uvod
- 2. Algoritmi zaštite bežičnih mreža
   - 2. 1. WEP
   - 2. 2. WPA/WPA2
- 3. Potrebni alati
- 4. Dohvaćanje handshakea
   - 4. 1. Prebacivanje u način za praćenje
   - 4. 2. Određivanje žrtve
   - 4. 3. Deautentikacija
- 5. Probijanje lozinke na lokalnom računalu
- 6. Hashtopolis
- 7. Probijanje lozinke u oblaku
   - 7. 1. Instalacija Cloudtopolisa
   - 7. 2. Kreiranje vaučera
   - 7. 3. Kreiranje hash liste
   - 7. 4. Kreiranje novog taska
- 8. Usporedba vremena probijanja
- 9. Sažetak
- Korištene naredbe
- Literatura


## 1. Uvod

Nastankom bežičnih mreža, pojavilo se i slanje podataka preko bežičnih mreža. Paralelno sa
slanjem prvih podataka preko bežičnih mreža, javlja se i problem zaštite tih podataka. Budući
da su bežične mreže ranjivije u odnosu na žične mreže, algoritmi za zaštitu bežičnih podataka,
koji su se s godinama pojavljivali, razvijali su se kako bi približili razinu sigurnosti bežičnih
onoj koja je prisutna u žičnim mrežama.

Povijest Wi-Fi počinje 1991. godine razvojem WaveLAN koji se smatra prethodnikom Wi-Fi
tehnologije. Naziv Wi-Fi tehnologija nose sve stavke unutar IEEE 802.11 skupine standarda.
Unutar te skupine standarda postoje 3 algoritma kojima se najčešće osiguravaju podaci koji se
prenose u bežičnim mrežama. Tri algoritma koja su najčešće u praktično primjeni su WEP,
WPA i WPA2 te će u daljnjim poglavljima ukratko bit pojašnjeni

Cilj ovog dokumenta je testirati način probijanja lozinki mreža unutar IEEE 802.
korištenjem koji koriste algoritme WPA ili WPA2. Opisat će se alati potrebni za obavljanje
tog procesa, usporedit će se rezultati dobivanih vremena u donosu na probijanje korištenjem
lokalne tehnologije i probijanje u oblaku (eng. cloud) koristeći Googleove resurse.

Uz načine probijanja lozinki, bit će opisane i vrste napada te njihove prednosti i mane.
Ključni pojmovi u cjelokupnom procesu će biti Hashcat, Hashtopolis te Cloudtopolis. Njihova
primjena i definicija bit će opisani kasnije, ali su to alati koji će imati ključnu korist u
probijanju lozinki.

Osim ovih alata, bit će potreban i operativni sustav Kali Linux zbog svojih ugrađenih naredbi
te skupine alata Aircrack-ng ima prednost nad ostalim operativnim sustavima. Posljednji alat
koji će biti potreban je Wi-Fi adapter koji će imati karakteristike za dohvaćanje rukovanja
(eng. handshake).


## 2. Algoritmi zaštite bežičnih mreža

IEEE 802.11 standard za bežične mreže predviđa mehanizme kojima je cilj povećanje
sigurnosti bežičnih mreža, odnosno ostvarivanja povjerljivosti i integriteta podataka te
mogućnost sigurne autentifikacije. Podaci koji putuju bežičnom mrežom moraju biti zaštićeni
od presretanja ili prisluškivanje i moraju nepromijenjeni stići na svoju destinaciju. Cilj ovih
algoritama je zaštitu bežičnih mreža približiti onima iz žičnih mreža.

### 2. 1. WEP

Wireless Encryption Protocol (WEP) je protokol, dio IEEE 802.11 standarda, namijenjen
osiguranju bežičnih mreža. WEP protokol kriptira podatke koji putuju između korisnika i
pristupne točke zajedničkim ključem. Korisnik mora imati odgovarajući WEP ključ kako bi
mogao komunicirati s pristupnom točkom. WEP protokol za enkripciju koristi RC4 algoritam
sa 64 ili 128 bitnim ključem, a za osiguranje integriteta podataka koristi se CRC-32 algoritam.

Pokazalo se da je takav sigurnosni mehanizam moguće probiti javno dostupnim alatima, stoga
se ne preporuča kao odgovarajuća mjera zaštite. Danas je moguće lozinke enkriptirane ovim
algoritmom probiti u roku od par minuta korištenjem minimalnih resursa. WEP je uveden

1997. godine, a već 2001. uočeni su ranjivosti samog algoritma.

### 2. 2. WPA/WPA

Wi-Fi Protected Access (WPA) je sigurnosni mehanizam osmišljen da ispravi nedostatke u
WEP protokolu. WPA koristi dinamičke ključeve koji se mijenjaju za vrijeme korištenja
sustava (TKIP) te „Michael“ algoritam za provjeru integriteta podataka. WPA“ kao dodatno
poboljšanje, umjesto RC4, koristi varijantu AES algoritma za enkripciju, ali nije podržan na
starijim mrežnim sučeljima.

Za autentifikaciju, WPA podržava 802.1x, ali može se koristiti i manje sigurni sustav sa
zajedničkim ključem – korisnici moraju poznavati zajednički ključ da bi se mogli spojiti na
mrežu. WEP zamijenjen je WPA algoritmom 2004. godine, tri godine nakon što su uočene
ranjivosti u WEP algoritmu.


## 3. Potrebni alati

Prva stvar koju je potrebno nabaviti je Wi-Fi adapter. Pri odabiru modela treba pripaziti da
uređaj ima ugrađenu opciju prebacivanja u način za praćenje (eng. monitoring mode) te
svojstvo package injection koje će kasnije biti potrebno za deautentikaciju. Konkretno u
ovom postupku korišten je Wi-Fi adapter modela Alfa AWUS036ACH čiji izgled se može
vidjeti na Slika 1.

![slika1](https://user-images.githubusercontent.com/37696656/109645241-d7089580-7b56-11eb-87c9-84eba5a513db.png "Slika 1. Alfa AWUS036ACH")

*Slika 1. Alfa AWUS036ACH*

Nakon nabave hardwarea potrebno je instalirati operativni sustav. U ovom procesu korišten je
operativni sustav instaliran je na virtualnom stroju (Virtual Box) te je korišten Kali Linux.
Razlog odabira Kali Linux sustava je mrežni softverski paket Aircrack-ng koji se sastoji od
detektora, snajpera za pakete, WEP i WPA/WPA2 crackera i alata za analizu 802.11 bežičnih
LAN mreža.


## 4. Dohvaćanje handshakea

Pošto je nabavljena hardverska oprema te instaliran odgovarajući operativni sustav, kreće se s
postupkom probijanja WPA/WPA2 lozinke, odnosno, kao početni korak, dohvaćanje
handshakea. Pri samom dohvaćanju handshakea, korišten je mrežni softverski paket Aircrack-
ng, a za detekciju lozinke su korišteni neki brži i efikasniji alati.

Prvi korak je prebaciti Wi-Fi adapter iz zadanog upravljačkog načina (eng. managed mode) u
način za praćenje (eng. monitoring mode) koji služi za praćenje prometa na određenom
bežičnom kanalu. Ovaj način također omogućava dohvaćanje paketa bez povezivanja na
pristupnu točku žrtve.

### 4. 1. Prebacivanje u način za praćenje

Bitno je prvo provjeriti naredbom [1] u kojem načinu rada se nalazi Wi-Fi adapter. Na Slika 2
vidljivo je da se adapter wlan0 trenutno nalazi u upravljačkom načinu, stoga je potrebno
prebaciti u način za praćenje. Prije toga potrebno mogu se potencijalno pojaviti procesi koji bi
izazvali određene grješke koji se provjere naredbom [2]. Naredbom [3] pobiju se ti procesi te
se dobije rezultat kao na Slika 3.

![slika2](https://user-images.githubusercontent.com/37696656/109645645-6dd55200-7b57-11eb-8a5d-14134924dc1c.png "Slika 2. Provjera je li adapter u načinu za praćenje")
*Slika 2. Provjera je li adapter u načinu za praćenje*

![slika3](https://user-images.githubusercontent.com/37696656/109645655-72016f80-7b57-11eb-91d0-41a63e2380f1.png "Slika 3. Priprema za prebacivanje u način za praćenje")
*Slika 3. Priprema za prebacivanje u način za praćenje*

Pošto su provjereni i, za svaki slučaj, pobijeni svi kritični procesi, pristupa se samom
prebacivanju Wi-Fi adaptera u način za praćenje. Taj proces se izvršava pomoću naredbe [4]
nakon čega se opet pokreće naredba [1] čime se provjerava je li adapter u ispravnom načinu.
Rezultat ovih dviju naredbi bit će vidljiv na ekranu kao na Slika 4.

![slika4](https://user-images.githubusercontent.com/37696656/109645668-7463c980-7b57-11eb-89d4-c4e98c8344be.png "Slika 4. Prebacivanje adaptera u način za praćenje")
*Slika 4. Prebacivanje adaptera u način za praćenje*

### 4. 2. Određivanje žrtve

Nakon što su sve postavke Wi-Fi adaptera postavljene, moraju se odrediti sve potencijalne
žrtve, odnosno sve pristupne točke relativno blizu Wi-Fi adapteru. Slika 5 je primjer svih
pristupnih točaka na koje se adapter može spojiti. Lista svih tih pristupnih točaka dobije
pokretanjem naredbe [5].

![slika5](https://user-images.githubusercontent.com/37696656/109645673-762d8d00-7b57-11eb-8feb-9777b3d3ba3f.png "Slika 5. Sve dostupne pristupne točke")
*Slika 5. Sve dostupne pristupne točke*

Nakon odluke koja će mreža biti napadnuta, bira se uređaj koji će poslužiti kao posrednik za
dohvaćanje handshakea te se prekida izvršavanje naredbe pritiskom kombinacije tipki Ctrl +
C. Naredbom [6] se opet pokreće isti proces kao i u prethodnom koraku s razlikom da je fokus
usmjeren na odabrani uređaj.

### 4. 3. Deautentikacija

Zatim se na odabranom uređaju naredbom [7] započinje proces deautentifikacije odabranog
uređaja ponavljajućim (eng. replay) napadom. Deautentifikacijom se uređaj odspoji s
pristupne točke. Ponovnim spajanjem uređaja na pristupnu točku, žrtva dolazi u opasnost da
se presretne handshake koji se dohvaća u trenutku kada žrtva pristupi internetu.

![slika6](https://user-images.githubusercontent.com/37696656/109645676-77f75080-7b57-11eb-8c59-a96fb142b53f.png "Slika 6. Dohvat handshakea")
*Slika 6. Dohvat handshakea*

Slika 6 prikazuje povratnu informaciju uspješnog dohvaćenog handshakea. Kad je dohvaćen
handshake on izvorno ima ekstenziju .cap, ali ga je potrebno prebaciti u format .hccapx.
Najjednostavniji način za napraviti konverziju iz jednog formata u drugi je koristeći
internetski pretvarač dostupan na poveznici [[2]](https://hashcat.net/cap2hccapx/).

## 5. Probijanje lozinke na lokalnom računalu

Datoteka koja je dobivena nakon konverzije je zapravo datoteka u kojoj je sadržana sama
WPA/WPA2 lozinka te je treba dekriptirati. Najčešće korišteni alat za dekriptiranje
WPA/WPA2 lozinki je Haschcat, alat kojem je primarni cilj oporavak lozinki. Budući da je
Hashcat alat otvorenog koda, cijela dokumentacija, kao i poveznica na programski kôd je
dostupna na poveznici [[3]](https://hashcat.net/wiki/doku.php?id=hashcat).

Alat Hashcat dostupan je na više operativnih sustava, ali u ovom procesu korišten je na
operativnom sustavu Windows. Ovaj alat podržava i više tipova napada od kojih su najbrži i
najprecizniji napad rječnikom (eng. dictionary attack) te napad sirovom snagom (eng. brute-
force attack).

Budući da WPA/WPA2 lozinke moraju biti dugačke minimalno 8 znakova, za potrebe ovog
primjera uzeto je prvih osam brojeva te je za ovaj primjer korišten napad rječnikom
rockyou.txt koji je dostupan na Githubu. Lozinka se na ovakav način probije u roku jedne
minute. Ovakav način probijanja nije najprecizniji jer se bazira na limitiranom fondu već
postojećih lozinki.

Budući da je napad rječnikom nepouzdan, najtočnija, ali i najsporija metoda za probijanje
lozinki je napad sirovom snagom. Na Slika 7 i Slika 8 prikazan je proces probijanja lozinke
od osam znakova. Cijeli proces se obrađuje na grafičkoj kartici NVIDIA GeForce MX150 te
je potrebno puno više vremena u odnosu na napad rječnikom. Za ovaj proces je potrebno 46
dana te je brzina probijanja 51 865 H/s.

![slika7](https://user-images.githubusercontent.com/37696656/109645685-7a59aa80-7b57-11eb-977c-bc0bba18776c.png "Slika 7. Hashcat na Windowsu")
*Slika 7. Hashcat na Windowsu*

![slika8](https://user-images.githubusercontent.com/37696656/109645694-7d549b00-7b57-11eb-8d6a-a36acc9910f4.png "Slika 8. Hashcat na Windowsu")
*Slika 8. Hashcat na Windowsu*


## 6. Hashtopolis

Prije prelaska na probijanje lozinki na oblaku potrebno je definirati Hashtopolis i neke
pojmove vezane uz njega. Hashtopolis je višeplatformni klijent-serverski alat za distribuirane
Hashcat zadatke na više računala. Glavni cilj razvoja Hashtopolisa je portabilnost, robusnost,
višekorisnička podrška i upravljanje više grupa. Sam Hashtopolis se sastoji od agenta koji
predstavlja klijent te od servera.

Najbitniji pojmovi koji će se u daljnjem procesu probijanja lozinki u oblaku su:
- Agent: Hashtopolis klijent koji se automatski izvršava probijanje pomoću Hashcata.
- Hashlist: Lista hasheva spremljenih u bazu podataka. U ovom slučaju to će biti
.hccapx koja je kreirana u jednom od prethodnih koraka.
- Task: Svaki task, odnosno zadatak ima naredbeni redak koji definira kako će se
Hashcat izvršavati.
- Supertask: Grupa subtaskova. Ovo zapravo i nije task, nego objedinjeni subtaskovi
kako bi bili prikazani kao jedinstveni task.
- Subtask: Dio supertaska. Zapravo se definira kao i običan task s tim da je prioritet
jedina relevantna stvar u supertasku.
- Keyspace: Svaki task ima predefiniran keyspace koji govori koliko će biti velik set
ključeva.
- Chunk: Dio keyspacea dodijeljen određenom agentu. Ako se chunk zaustavi, on ili
dio njega bit će dodijeljen idućem slobodnom agentu.
- Access Management: Upravlja pristupom funkcijama i akcijama.
- Groups: Koristi se za odvajanje hashlista, taskova i agenata jednih od drugih ukoliko
je to potrebno.

Više o Hashtopolisu, njegovoj definiciji, procesu instalacije i ostalim potrebnim
informacijama može se pronaći na Github repozitoriju na poveznici [[4]](https://github.com/s3inlc/hashtopolis).

![slika9](https://user-images.githubusercontent.com/37696656/109645705-7fb6f500-7b57-11eb-8239-9a47c72d660f.png "Slika 9. Početna stranica Hashtopolisa")
*Slika 9. Početna stranica Hashtopolisa*

## 7. Probijanje lozinke u oblaku

Efikasniji i brži način od probijanja WPA/WPA2 lozinki na lokalnom računalu je izvršavanje
procesa u oblaku. Za ovaj proces odbran Cloudtopolis čija cjelokupna dokumentacija te upute
dostupne na poveznici [[5]](https://github.com/JoelGMSec/Cloudtopolis). Cloudtopolis je Googleov oblak stoga je potrebno imati Google
račun da bi se moglo pristupiti samom oblaku. Također je potrebno i korištenje Hashtopolisa
koji je ukratko opisan u prethodnom poglavlju.

### 7. 1. Instalacija Cloudtopolisa

Cloudtopolis podrazumijeva izvršavanje Hashtopolis zadataka u oblaku koristeći Googleove
resurse s ciljem ubrzanja procesa probijanja WPA/WPA2 lozinki. Prvi korak pri korištenju
jest instalacija samog Cloudtopolisa korištenjem naredbi [8], [9] i [10] u ljusci dostupnoj na
poveznici [[6]](https://ssh.cloud.google.com/cloudshell/editor?hl=en&fromcloudshell=true&shellonly=true). Rezultat bi trebao biti vidljiv kao na Slika 10 i Slika 11. Samom Hashtopolisu
pristupa se na adresi localhost: 8000 koja će biti vidljiva nakon procesa instalacije te
korisničko ime i lozinka Hashtopolisa.

![slika10](https://user-images.githubusercontent.com/37696656/109645713-82194f00-7b57-11eb-9dbc-772325fe035f.png "Slika 10. Instalacija u ljusci")
*Slika 10. Instalacija u ljusci*

![slika11](https://user-images.githubusercontent.com/37696656/109645721-83e31280-7b57-11eb-8c70-21dab755aae0.png "Slika 11. Završena insta lacija u ljusci")
*Slika 11. Završena insta lacija u ljusci*

### 7. 2. Kreiranje vaučera

Nakon toga pristupa se kreiranju vaučera za agenta u Hashtopolisu kao na Slika 12. Vaučer
može bit proizvoljno generiran ili se može definirati neki određeni kojeg je lakše za zapamtiti.
Taj vaučer ubacuje se u Cloudtopolis notebook u već pripremljeni programski kôd kojemu
nedostaje jedino taj vaučer. To bi trebalo izgledati kao na Slika 13.

![slika12](https://user-images.githubusercontent.com/37696656/109645727-85acd600-7b57-11eb-9e3d-24bf178436d2.png "Slika 12. Generiranje vaučera za agenta")
*Slika 12. Generiranje vaučera za agenta*

![slika13](https://user-images.githubusercontent.com/37696656/109645732-87769980-7b57-11eb-92dc-6a5debea72f3.png "Slika 13. Notebook")
*Slika 13. Notebook*

Kad se pokrene blok naredbi u notebooku, javljat će se jedna greška konstantno s porukom
_„No task available“_ što znači da trenutno ne postoji niti jedan aktivan task koji taj agent
izvršava, stoga je potrebno vratiti se u Hashtopolis te kreirati task, ali prije toga potrebno je
definirati hashlist.

### 7. 3. Kreiranje hash liste

Hashlist kreira se kao na Slika 14. Na toj slici vidi se da je potrebno navesti ime same hash
liste i algoritam enkripcije koji je u ovom slučaju WPA/WPA2 s rednim brojem 2500 što
govori da ima više algoritama koji se mogu probiti na ovaj način. I posljednja stvar koju je
potrebno uraditi je navesti hashcat format (.hcapx) te prenijeti s lokalnog računala datoteku
prethodno generiranu iz handshakea što je opisano u jednom od prethodnih poglavlja.

![slika14](https://user-images.githubusercontent.com/37696656/109645735-89405d00-7b57-11eb-945c-549583a09642.png "Slika 14. Nova hash lista")
*Slika 14. Nova hash lista*

### 7. 4. Kreiranje novog taska

Pošto je definirana nova hash lista, kreira se i novi task kao na Slika 15 gdje se jasno vidi da
je potrebno definirati naziv samog taska, hashlist koja će se probijati, prioritet te broj komada
na koje će se podijeliti probijanje (eng. chunk size). Najbitnija stvar pri kreiranju taska je
naredbeni redak koji u ovom slučaju govori da se radi o probijanju lozinke od 8 znakova (ne
brojeva kao na lokalnom računalu) te da je napad sirovom snagom.


![slika15](https://user-images.githubusercontent.com/37696656/109645740-8a718a00-7b57-11eb-8e5e-491fe4844491.png "Slika 15. Novi task")
*Slika 15. Novi task*

Zatim se upravo kreiranom tasku pridružuje agent koji će izvršavati taj isti task. Pri povratku
na Cloudtopolis notebook, ukoliko se izvršavanje nije zaustavilo, trebao bi se naći, ali i
započeti izvršavati task koji je ima najveći prioritet na tom vaučeru, odnosno agentu kao na
Slika 16. Ako je prioritet jednak nuli, task se ne će početi izvršavati. Google proizvoljno
dodijeli resurse grafičke kartice, i to jednu od 4 moguća modela proizvođača NVIDIA: K80,
T4, P4 ili P100.

![slika16](https://user-images.githubusercontent.com/37696656/109645743-8c3b4d80-7b57-11eb-9a2d-44ae0a6cfda0.png "Slika 16. Početak izvršavanja taska na agentu")
*Slika 16. Početak izvršavanja taska na agentu*

## 8. Usporedba vremena probijanja

Kao što je prethodnom spomenuto, najviše vremena potrebnog za probijanje WPA/WPA
lozinke je na lokalnom računalu zbog toga što su slabiji resursi. Brzina probijanja lozinke od
8 znakova iznosi oko 51 865 H/s te vremenski interval u kojem će biti obavljen taj proces
iznosi čak 46 dana što znači da nije toliko jednostavno prosječnom korisniku probiti
WPA/WPA2 lozinku.

Pri prebacivanju procesa probijanja na oblak, brzina za lozinku od 8 znakova povećala se na
304,69 kH/s te vrijeme potrebno je malo skoro 9 dana za samo jednog agenta. Čime su
performanse poboljšane za otprilike 6 puta, ali treba imati u obziru da su na lokalnom
računalu dostupni puno slabiji resursi u odnosu na oblak..

![slika17](https://user-images.githubusercontent.com/37696656/109645752-8e9da780-7b57-11eb-9455-773b22a4f097.png "Slika 17. Brzina s jednim agentom")
*Slika 17. Brzina s jednim agentom*

Uključivanjem 5 dodatnih agenata, brzina samog procesa skače na čak 1928,84 kH/s, a
vrijeme potrebno za probiti WPA/WPA2 iznosi malo manje od 5 dana za lozinku od 8
znakova. Iz ovih podataka može se primijetiti da brzina raste linearno u dodavanjem svakog
novog agenta

![slika18](https://user-images.githubusercontent.com/37696656/109645756-90676b00-7b57-11eb-9b37-e6a375d0f391.png "Slika 18. Brzina sa 6 agenata")
*Slika 18. Brzina sa 6 agenata*


|                | Vrijeme [dani]   | Brzina [kH/s]     |
| :------------- | :----------: | -----------: |
|  Lokalno računalo| 46   | 51,865    |
| Oblak – 1 agent  | 9 | 304,69 \| |
| Oblak – 6 agenta   | 5 | 1928,84 \| |
*Tablica 1. Usporedba vremena izvršavanje i brzina*

## 9. Sažetak

U idućim koracima je sažetak cijelog procesa opisanog u ovom dokumentu:

1. Nabaviti pripadni Wi-Fi adapter
2. Instalirati Kali Linux operativni sustav (može i na virtualnom stroju)
3. Dohvaćanje handshakea (Kali Linux)
    1. Pokrenuti naredbu airmon-ng check kill
    2. Prebacivanje u način za praćenje naredbom airmon-ng start wlan0
    3. Odluka o mreži koja će biti žrtva; Naredbom airodump-ng wlan0 provjere se
       sve dostupne mreže
    4. Pokretanje naredbe airodump-ng --bssid <BSSID> -c <broj kanala> -w <ime
       datoteke> wlan0 gdje su BSSID i broj kanala uzeti iz prethodnog koraka, a
       ime datoteke proizvoljno
    5. Paralelno otvaranje novog terminala i pokretanje naredbe aireplay-ng --deauth
       _<broj deautentikacijskih paketa koji se šalju> –_ a <MAC adresa pristupne
       _točke> –c <MAC uređaja žrtve> wlan0_ te je potrebno unijeti parametre u <>
       iz prethodnog koraka
    6. Ukoliko dođe potvrda o uspješno dohvaćenom handshakeu, pristupa se
       sljedećem koraku
4. Konvertiranje datoteke uhvaćenog handshake na poveznici
    https://hashcat.net/cap2hccapx/
5. Pokretanje Google Shella preko poveznice
    https://ssh.cloud.google.com/cloudshell/editor?hl=en&fromcloudshell=true&shellonly=true
6. Instaliranje Cloudtopolisa u Google Shellu pokretanje sljedećih naredbi:
    1. wget https://raw.githubusercontent.com/JoelGMSec/Cloudtopolis/master/Cloudtopolis.sh
    2. chmod +x Cloudtopolis.sh
    3. ./Cloudtopolis.sh
7. Pristup Hashtopolisu na sljedećoj poveznici i sa sljedećim podacima:

![slika19](https://user-images.githubusercontent.com/37696656/109645760-91989800-7b57-11eb-8829-200cf8da1764.png)

8. Generiranje vaučera za agenta (Agents > New agent)
9. Kopirati vaučer i zalijepiti ga u poveznicu
    https://colab.research.google.com/github/JoelGMSec/Cloudtopolis/blob/master/Cloudtopolis.ipynb
    na za to predviđeno mjesto
10. Pokretanje notebooka iz prethodnog koraka
11. Kreiranje hash liste (Lists > New Hashlist) – konvertirani dohvaćeni handshake
12. Kreiranje novog taska (Tasks > New Task) – upisati naredbeni redak s vrstom napada
13. Čekati odrađivanje taska


## Korištene naredbe

```
[1] iwconfig
[2] airmon-ng check
[3] airmon-ng check kill
[4] airmon-ng start wlan0
[5] airodump-ng wlan0
[6] airodump-ng --bssid <BSSID> - c <broj kanala> - w <ime datoteke> wlan0
[7] aireplay-ng --deauth <broj deautentikacijskih paketa koji se šalju> –a 
    <MAC adresa pristupne točke> – c <MAC uređaja žrtve> wlan0
[8] wget https://raw.githubusercontent.com/JoelGMSec/Cloudtopolis/master/Cloudtopolis.sh
[9] chmod +x Cloudtopolis.sh
[10] ./Cloudtopolis.sh
```

## Literatura

```
[1] https://www.aircrack-ng.org/doku.php?id=cracking_wpa
[2] https://hashcat.net/cap2hccapx/
[3] https://hashcat.net/wiki/doku.php?id=hashcat
[4] https://github.com/s3inlc/hashtopolis
[5] https://github.com/JoelGMSec/Cloudtopolis
[6] https://ssh.cloud.google.com/cloudshell/editor?hl=en&fromcloudshell=true&shellonly=true
[7] https://colab.research.google.com/github/JoelGMSec/Cloudtopolis/blob/master/Cloudtopolis.ipynb
[8] https://ssh.cloud.google.com/devshell/proxy?authuser=0&port=8000&environment_id=default
[9] https://hashcat.net/wiki/
```

