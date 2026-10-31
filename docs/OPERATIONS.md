# Betrieb und Diagnose

Alle Zeitangaben mit `timedatectl`/`date --iso-8601=seconds` abgleichen. Die
Betriebszeit ist Europe/Vienna; am Sicherungstag gilt UTC+1. Zentrale und lokale
CDRs können unterschiedliche Darstellungen derselben Zeit verwenden.

## Zugang und tägliche Prüfung

```sh
ssh mark@192.168.1.50
sudo -i
systemctl is-active freeswitch
systemctl --failed
fs_cli -x 'status'
fs_cli -x 'show calls count'
fs_cli -x 'sofia status profile voip01'
fs_cli -x 'global_getvar default_profile'
fs_cli -x 'global_getvar switchid'
ip -4 -br address
ip -4 route
df -h /
```

Für den 38er entsprechend `192.168.1.38`. `fs_cli` ohne `-x` öffnet die interaktive
Konsole; `/exit` beendet nur den Client. ESL-Passwörter nicht als Argumente eingeben.
`fs_cli -x 'shutdown'`, Profil-Restarts und Dienstneustarts sind keine Diagnosebefehle.

## Nicht klingelnder Anruf

1. Genaue Testzeit, Zielnummer und erwarteten Switch klären. Ein Lieferanten-
   Loadshare von 50:50 beweist keinen Failover bei ausgeschalteter Gegenseite.
2. Die lokal eingegangenen Anrufe und CDRs **vor** und nach dem Test vergleichen.
   Ein erst später gestarteter tcpdump beweist nichts über einen früheren Anruf.
3. In `journalctl -u freeswitch --since ...` und den geschützten FS-Logdateien nach
   Anruf-UUID, `New Channel`, Lua-Fehler, Transfer, Bridge und Hangup-Ursache suchen.
4. Falls der Eingang unklar bleibt, einen zeitlich begrenzten SIP-Metadaten-
   Mitschnitt der konkreten Quelle erstellen. Keine Audio-/RTP-Aufzeichnung als
   Standarddiagnose, Rohdaten nicht ins öffentliche Repository kopieren.
5. Für echte SIP-Zustellung Firewall **und** ACL prüfen:

```sh
fs_cli -x 'acl 198.96.222.228 domains'
ss -lunp
ip route get 198.96.222.228
nft list ruleset
```

`NO_ROUTE_DESTINATION` ist eine Rufweg-/Dialplan-Ursache. Erst den konkreten
Lua-/Bridge-Pfad und die übergebene Nummer prüfen; daraus nicht automatisch auf
ein Netzwerkproblem oder einen fehlenden Tarif schließen.

Der Test nach dem 50er-Hotfix war hörbar. Die beobachtete Verzögerung könnte
mit einem ersten Versuch zum ausgeschalteten 38er zusammenhängen; dies ist
ohne korrelierte SIP-Zeitpunkte **nicht bewiesen**.

## Gateways und Aktualisierung

`NOREG` ist bei IP-zu-IP-Gateways ohne SIP-Registrierung normal. Ein fehlgeschlagener
OPTIONS-Ping mit 408/503 bedeutet nicht automatisch, dass eine Registrierung fehlt.
Ein im Panel deaktivierter Datensatz kann noch als bereits geladenes Gateway
existieren. Unterscheiden zwischen Panel-Daten, abgerufenem XML und Sofia-Laufzeit.

```sh
fs_cli -x 'sofia status gateway'
fs_cli -x 'sofia status profile voip01'
```

Ein `reloadxml` aktualisiert XML, entfernt aber nicht zwangsläufig jedes bereits
geladene Gateway. Gateway-Abbau/Rescan nur gezielt nach Prüfung aktiver Anrufe und
Rufwege durchführen, nicht mit einem pauschalen Profilneustart. Die historischen
Deaktivierungen werden nicht durch Wiederherstellen einer alten Panel-Datenbank
zurückgesetzt; diese Datenbank ist ausdrücklich nicht Teil dieses Restore.

## Lokale und zentrale CDRs

Lokaler Pfad: `/var/log/freeswitch/cdr-csv/Master.csv`, beide Gesprächsseiten,
22 CSV-Spalten. Dateien mit einem CSV-Parser lesen, nicht anhand von Kommas im
Rohtext auftrennen. Die Originalvorlagen/Spaltenreihenfolge sind im verschlüsselten
FreeSWITCH-XML enthalten. Zentral liegen die Abrechnungseinträge in `ccsystem.cc_cdrs`.

- Zeitzone, Switch-ID, Call-UUID, Leg-Richtung, `billedsec`, `multiplier`, Answer-
  und Hangup-Status prüfen.
- Eine beantwortete lokale Seite allein beweist nicht den zentralen Abrechnungserfolg.
- Zentral können beide Legs die A-UUID teilen; lokal besitzt die B-Seite ihre eigene UUID.
- Keine echten Rufnummern, CDR-Dateien oder Zugangsdaten in öffentliche Issues stellen.

Rotation: täglich bzw. ab 20 MiB; Prüfung alle fünf Minuten; 14 Archive und
`maxage 14`, verzögerte Kompression, Reopen statt `copytruncate`.
Die 20-MiB-Grenze ist eine Prüfschwelle, keine harte Dateigrößenobergrenze: Bei
hohem CDR-Aufkommen kann eine Datei zwischen zwei Prüfungen weiter wachsen.

```sh
systemctl status voip50-cdr-rotate.timer --no-pager
systemctl status voip50-cdr-rotate.service --no-pager
du -sh /var/log/freeswitch/cdr-csv
```

## Ansagen und Ausfälle externer Systeme

```sh
systemctl status voip50-prompt-sync.timer --no-pager
systemctl status voip50-prompt-sync.service --no-pager
findmnt /mnt/voip50-prompts
readlink -f /var/lib/freeswitch/sounds/en/us/callie/mark
```

Auf dem 38er die Unit-/Pfadnamen entsprechend ersetzen. NAS-Freigaben sind
IP-gebunden. Nach Adresswechsel .217 → .50 bzw. .213 → .38 die tatsächliche
Quell-IP berücksichtigen. Ein lokaler Ansagenbestand erlaubt Wiedergabe auch
bei vorübergehend nicht erreichbarem NAS.

Bei ODBC-Fehlern 08S01/2013 zuerst Verlauf, Verbindungsalter, tatsächliche
SQL-Ergebnisse und CDRs prüfen. Ein einzelner verlorener Handle kann neben
einer erfolgreichen anderen Verbindung auftreten. Beide 50er-DSNs zeigen
auf dieselbe Datenbank; Namen mit 146/155 nicht als Nachweis zweier Server lesen.

## Wartung und Rückfall

Nur nach Absprache neue Eingänge pausieren und aktive Gespräche auslaufen lassen.
Vor jedem Neustart/Shutdown die Zahl aktiver Calls prüfen. Nie alten und neuen
Switch mit identischen IP-Adressen gleichzeitig starten.

Der frühere `voip38-testcall-observer` war ein Hilfsdienst zur Testbeobachtung,
kein Bestandteil der eigentlichen Telefonie. Einen eventuellen Fehler dieses
Observers getrennt von `freeswitch.service` bewerten. Der aktuelle Unitsatz wird
im Metadatenarchiv vollständig aufgeführt.
