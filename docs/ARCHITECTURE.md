# Architektur und Verträge

## Anrufverarbeitung

1. SIP trifft auf dem öffentlichen Interface des jeweiligen Switches ein.
2. Firewall und FreeSWITCH-ACL müssen die Quelle erlauben. Aktuelle Tests kamen
   von `198.96.222.228`; auf dem 50er ist die Quelle durch `198.96.222.0/24` abgedeckt.
3. Das Sofia-Profil `voip01` übergibt an den Dialplan, unter anderem `telekomfl`
   und `pdid`. `PDIDRoutingReseller.lua` gehört zum eingehenden Reseller-Rufweg.
4. Lua lädt `dbconnect.lua`, liest Routing-/Tarifdaten aus `ccsystem`, setzt Kanal-
   variablen und erzeugt gegebenenfalls eine B-Seite über `voip01`.
5. Answer-/Hangup-Hooks schreiben die zentrale Abrechnung. `mod_cdr_csv` schreibt
   zusätzlich lokale Gesprächsseiten zur unabhängigen Nachvollziehbarkeit.

Die vorhandenen sieben 50er-Kontexte sind `ccdialout`, `didrouting`, `ivrs`,
`pdid`, `publicTrunks`, `routing`, `telekomfl`. Nicht auf einen generischen
FreeSWITCH-Beispieldialplan zurücksetzen.

## Panel und XML

| Switch | Quelle im LIVE-Modus | Panel-ID |
| --- | --- | --- |
| 38 | `https://www.telemediacloud.com/configHandler/` (altes Panel, 92.61.60.60) | 6 |
| 50 | `http://192.168.1.225:9000/configHandler/` (überarbeitetes Panel) | 4 |

Abrufaktionen: `getHostsConfig`, `getGateways`, `getGatewayUsers`,
`getCardsConfig`, `ivrXML`. Abrufschlüssel und Original-URLs aus alten Skripten
stehen ausschließlich in der verschlüsselten `production-reference`.

Der 38er benutzt `/usr/local/libexec/voip38-integrate` beim Dienststart und
`voip38-render-xml` für die native XML-Vorverarbeitung. Die geschützte Referenz
liegt unter `/root/voip38-build/production-reference`, Generationsstände unter
`/root/voip38-build/integration`. Ein Firewall-Fetch-Timer läuft minütlich.

Der 50er benutzt `/usr/local/libexec/voip50-build-config` als Modus-Dispatcher,
in LIVE `/usr/local/libexec/voip50-live-runtime start`. Der native Renderer
aktualisiert XML bei Start/`reloadxml`. Der private Cache liegt unter
`/var/lib/freeswitch/voip50-live-xml-cache`; bei einem Abrufproblem wird der
geprüfte letzte Stand bzw. der vorbereitete Kandidat verwendet.

Der 50er lädt die Firewall nicht automatisch aus dem Panel: dessen Quellenliste
wich vom alten aktiven 50er ab. Die produktive Firewall bleibt auf der geprüften
alten Liste. XML-Aktualisierung und Firewall-Aktivierung sind getrennte Vorgänge.

Nicht ungeprüft alte `/fetchConfig.py`-Anweisungen übernehmen. Auf dem neuen
50er existiert ein Kompatibilitätsaufruf unter `/etc/freeswitch/scripts/fetchConfig.py`;
maßgeblich sind die oben genannten Renderer und die systemd-Startkette.

## Event Socket / FreeSWITCH-Konsole

`fs_cli` benutzt das Event Socket Interface (ESL), normalerweise TCP 8021.
Das Panel sendet über ESL unter anderem Verwaltungsbefehle. Ein erfolgreicher
HTTP/XML-Abruf beweist deshalb noch keine funktionierende Panel-Steuerung.

Die ursprünglichen ESL-Zugangsdaten und restriktiven ACLs wurden erhalten.
Die lokale Root-Konfiguration ist `/root/.fs_cli_conf` (0600); ein Wrapper
`/usr/local/bin/fs_cli` erlaubt dem Betreiber `mark` den geschützten Zugriff.
ESL niemals öffentlich ohne Firewall, ACL und Passwort freigeben.

## ODBC und Lua-Kompatibilität

Beide am 50er konfigurierten DSNs (`freeswitch146`, `freeswitch155`) zeigen laut
übernommener Konfiguration auf **192.168.1.155 / ccsystem**. Die zwei Namen
stellen damit keine unabhängige Datenbankredundanz dar. Auswahl `1` entspricht
`freeswitch146`, Auswahl `2` entspricht `freeswitch155`.

Die Verbindung wird nativ mit `freeswitch.Dbh(dsn, user, password)` erstellt.
Zugangsdaten kommen aus den vorhandenen XML-Globals; nicht hart im Code hinterlegen.
`INTERACTIVE=1` wurde für die Idle-Verbindungskompatibilität übernommen.
Der MariaDB-ODBC-Treiber ist `libmaodbc.so`, installiert im unixODBC-Treiberpfad
`/usr/lib/x86_64-linux-gnu/odbc/`. Ein bloßes `ctypes.CDLL('libmaodbc.so')` außerhalb
dieses Pfades ist kein verlässlicher unixODBC-Test.

**Wichtiger Legacy-Vertrag:** `connectDB()` muss neben dem Rückgabewert die
Lua-Globale `useDB` auf `'1'` oder `'2'` setzen und auf die Session übertragen.
`PDIDRoutingReseller.lua` und weitere Hooks lesen diese Globale beim Aufbau der
B-Seite. Ein anfangs fehlender Export verursachte am 31.10. einen echten Fehler.
Der genehmigte Hotfix ist in aktiver Datei, Kandidat und Quellvorlage gesichert.
Es reicht nicht, nur die Rückgabe einer DB-Verbindung zu testen.

## Abrechnung

- `billedsec` und `multiplier` bleiben entsprechend der vorhandenen Lua-/Panel-
  Verwendung erhalten; keine neue Tarif- oder Guthabenregel einführen.
- Der Betreiber hat ausdrücklich das bisherige Prepaid-Verhalten mit möglicher
  Nachbelastung/negativem Restguthaben bestätigt. Ein positives Restguthaben muss
  nicht den gesamten ersten Tarifblock decken.
- Die zentrale Tabelle `cc_cdrs` kann für A- und B-LEG dieselbe eingehende
  Call-UUID verwenden. Die lokalen CSV-Seiten haben dagegen eigene Kanal-UUIDs.
  Nach UUID allein nicht fälschlich einen fehlenden zentralen B-CDR behaupten.
- Zeit, Leg-Richtung, Dauer, Ursache und Switch-Zuordnung gemeinsam abgleichen.
- Die Testsicherung enthält lokale CDRs. Die zentrale MariaDB wird hier nicht
  gedumpt oder zurückgespielt.

## Ansagen

Beide Switches lesen ausschließlich per NFS-RO von:
`192.168.1.214:/volume1/freeswitchSounds/en/us/callie/mark`.
Mountpunkte sind `/mnt/voip38-prompts` bzw. `/mnt/voip50-prompts`.
Die NAS-IP-Freigabe muss für die jeweils verwendete Quell-IP bestehen.

Alle zehn Minuten übernimmt der Sync neue/geänderte `promptFile_*.wav` in eine
geprüfte lokale Generation; vorhandene lokale Dateien bleiben bei NAS-Problemen
verfügbar. Der lokale Zielpfad lautet
`/var/lib/freeswitch/sounds/en/us/callie/mark`. Die Dateien sind nur root und
FreeSWITCH zugänglich. Die notwendigen Ansagen 30, 32, 34, 36, 74, 84 und 86
sind in der Sicherung enthalten. Keine lizenzerforderliche VoIPmonitor-
Installation ergänzen; der Betreiber verwendet HOMER bzw. dessen FS-Integration.
