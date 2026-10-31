# Nachweise und offene Punkte

## Sicherung vom 31.10.2026

| Prüfung | VoIP38 | VoIP50 |
| --- | --- | --- |
| Gastidentität über gepinntes SSH und Hypervisor-UUID | korrekt | korrekt |
| FreeSWITCH vor Sicherung | active, 1.11.3 | active, 1.11.3 |
| Root-Dateiexport Exitcode | 0 | 0 |
| AES-256-Verschlüsselung Exitcode | 0 | 0 |
| OpenPGP-Integrität und vollständiges Lesen aller Tar-Inhalte | bestanden | bestanden |
| reguläre gelesene Dateien | 42.024 | 42.383 |
| stabile Programm-/Konfigurationshashes gegen getrennte Metadaten | 198 passend | 191 passend |
| konsistente SQLite-Kopien, jeweils integrity_check=ok | 3 | 2 |
| Reassemblierung aller veröffentlichten Teile gegen Original-SHA-256 | bestanden | bestanden |

Maschinenlesbare Berichte stehen in `validation/`. Sie enthalten keine
Passwörter, SIP-Inhalte oder echte Gesprächsdatensätze. Der archivierte
Metadatensatz enthält zusätzlich Paketlisten und detaillierte Dateiprüfsummen.

Der Schlüssel befindet sich ausschließlich außerhalb des Repositories.
Öffentliche Textdateien wurden auf offensichtliche Secret-Muster geprüft und
gegen die aus den Archiven gelesenen individuellen Secret-Werte verglichen.
Allgemeine Feld-/Bibliotheksbezeichner wurden bei der Prüfung einzeln betrachtet;
eine Stichwortübereinstimmung in Programmcode ist kein credentialhaltiger Literalwert.

## Betriebsabnahme vor dieser Sicherung

- Neuer 38er: produktiver Test mit Verbindung und Gespräch, Panel-/CDR-Abgleich;
  `default_profile=voip01` zur Behebung des IVR-/Bridge-Pfads dauerhaft gesetzt.
  Lokale CDRs und Rotation ohne Dienstneustart eingerichtet.
- Neuer 50er: zwei NICs und produktive LAN-/WAN-Adressen umgeschaltet; alter
  50er vorher sauber heruntergefahren. Provider-SIP von 198.96.222.228 nachgewiesen.
- 50er-`useDB`: ursprünglichen Nil-Fehler im realen Caller reproduziert,
  genehmigte Korrektur in aktiver Datei und beiden Vorlagen vorgenommen,
  elf native Lua-Fälle und tatsächlichen Caller-Präfix geprüft. Kein FS-Neustart.
- Nachfolgender echter 50er-Anruf beantwortet; Ansage vom Betreiber als hörbar
  bestätigt. Lokale A-/B-Seiten mit je fünf Sekunden und zentrale A-/B-CDRs
  derselben Dauer abgeglichen. Keine realen UUIDs/Rufnummern in diesem öffentlichen Bericht.
- Zuletzt gemeldete längere Zustellzeit ist nicht kausal geklärt. 50:50-Lastverteilung
  und Anbieter-Failover wurden dadurch nicht quantitativ nachgewiesen.
- Anmeldung als mark und sudo in Xen-Konsole wurde auf beiden Ersatzgästen bestätigt.
- Ansagen liegen lokal vor; NFS-RO-Synchronisierung ist eingerichtet.

Das sind historische Funktionsnachweise der laufenden Ersatz-Switches. Sie sind
kein Nachweis einer bereits erfolgreich gebooteten Wiederherstellung aus den
hier veröffentlichten Archiven.

## Beim Backup entdeckter und anschließend behobener Fehler

Der installierte `voip50-check-interface` fordert in `pre-up` weiterhin einen
15 Minuten frischen Umschaltnachweis. Dies kann die Netzanbindung nach einem
späteren Reboot blockieren. Die passende permanente Commissioning-Datei existiert
bereits für die FS-Laufzeit, wird aber vom ursprünglichen Netzwerk-Guard noch
nicht verwendet.

Die Korrektur unter `source/recovery/` wurde nach ausdrücklicher Betreiberfreigabe
am 31.10.2026 um 12:18 Uhr Europe/Vienna auf dem LIVE-50er atomar installiert.
Die Regression ist gegen den archivierten Original-Guard reproduziert. Die
aktuelle Testsuite besteht zehn Testmethoden einschließlich abgelaufenem oder in
der Zukunft liegendem Erstnachweis, späterem regulärem Boot, falscher UUID, MAC/Rolle, geändertem Plan,
fehlender Freigabe sowie beschädigten Archivteilen und Pfadtraversal.

Beide tatsächlichen `pre-up`-Prüfungen des installierten Guards bestehen jetzt;
vertauschte Interface-Rollen werden weiterhin abgewiesen. FreeSWITCH-PID 9574
blieb unverändert, ebenso Netzwerkadressen, Routen, Firewall und relevante
Steuer-/FreeSWITCH-Konfigurationsdateien. Es gab keinen Dienst-/Netzwerkneustart.
Beide gespeicherten Installationsquellen auf dem Gast wurden ebenfalls korrigiert.
Ein tatsächlicher Reboot wurde gemäß Auftrag nicht ausgelöst.

[Installationsnachweis](../validation/voip50-reboot-guard-fix.json) und
[technische Änderung](VOIP50-REBOOT-GUARD-FIX.md). Die verschlüsselten Basisarchive
enthalten den Stand vor diesem Hotfix; beim Restore den dokumentierten Overlay anwenden.

## Noch durchzuführen, bevor ein Restore als abgenommen gilt

1. Archiv auf isoliertes Ziel mit getrennten VIFs zurückspielen und UEFI-Boot prüfen.
2. UUID/MAC-Bindungen, Netzwerkrollen, Passwort-Konsole und SSH prüfen.
3. 50er-Netzwerk-Guard auf dem Restore-Ziel korrigieren und Boot erneut prüfen.
4. Firewall vor Anbindung prüfen, dann externe XML-/DB-/NAS-/ESL-Abhängigkeiten testen.
5. Nach kontrollierter Übernahme echter Testanruf, Medien, Ansage, Auflegen,
   lokale und zentrale Abrechnung; anschließend neuer Sicherungssatz.

Die Telefoniedienste, Panels und Datenbanken wurden weder durch die Sicherung
noch durch diesen Guard-Hotfix neu konfiguriert oder neu gestartet.
