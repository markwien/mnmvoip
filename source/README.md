# Quellen und Herkunft

## `installed/`

Direkt aus den entschlüsselten, geprüften Dateisicherungen entnommene
Wartungsprogramme, systemd-Units/Drop-ins und Netzwerkdateien. Originalpfade und
SHA-256-Prüfsummen stehen in `installed-manifest.json`. Diese Kopien dokumentieren
den **tatsächlich installierten Ausgangsstand der Dateisicherung**, einschließlich
historischer Kommentare und des damaligen 50er-Neustart-Guard-Problems.
Der spätere LIVE-Hotfix ist separat unter `recovery/` samt Installationsnachweis
dokumentiert; die Basiskopie bleibt für Archivabgleich und Regressionstest unverändert.

Die Lua-Geschäftslogik, originalen credentialhaltigen XML-/ODBC-/ESL-Dateien und
rootgeschützten Kandidaten sind vollständig in den **verschlüsselten** Archiven
enthalten. Nicht versehentlich entschlüsselte Produktionsdateien hier ergänzen.

## `maintenance/`

Bei der Migration verwendete Wartungs-/Generatorquellen und Labortests aus dem
Arbeitsverzeichnis. Sie sind zur Erklärung und Weiterentwicklung beigefügt.
Sie sind kein idempotenter Installer und kein Befehlssatz zum erneuten Ausführen
auf einem bereits produktiven Switch. Einige Tests setzen ausschließlich BUILD,
damalige temporäre Pfade, alte Hashes oder simulierte Netzwerke voraus.

Insbesondere:

- Kein generisches erneutes Ausführen von BUILD-Installern auf LIVE.
- Netzwerk-Aktivierungsskripte des ursprünglichen Cutovers werden hier bewusst
  nicht als ausführbarer Wiederherstellungsweg angeboten.
- Die Vorlage `voip50_live_dbconnect.lua` enthält den genehmigten `useDB`-Fix.
  Sie ist an die ursprüngliche 50er-UUID gebunden. Eine neue Gast-UUID muss
  auch in allen aktiven und gespeicherten Kandidaten angepasst werden.
- Lua-Regressionstests verwenden synthetische Zugangsdaten, keine produktiven.
- `maintenance/voip50_check_interface.py` ist der historische Guard vor dem
  Hotfix. Für Installationen den aktuellen Guard unter `recovery/` verwenden.
- Für die Wiederherstellung ist der installierte Stand im zugehörigen
  verschlüsselten Archiv maßgeblich, nicht die Reihenfolge der Generatoren.

## `recovery/`

Die Korrektur des 50er-Netzwerk-Guards wurde während der Sicherungsprüfung
erstellt und nach ausdrücklicher Freigabe am 31.10.2026 um 12:18 Uhr Europe/Vienna
auf dem LIVE-50er atomar installiert. FreeSWITCH wurde nicht neu gestartet und
Netzwerk/Firewall blieben unverändert. Beide gespeicherten Installationsvorlagen
auf dem Gast sind ebenfalls aktualisiert.

Der Original-Dateisicherung fehlt dieser spätere Hotfix. Installationshinweise
für ein offline wiederhergestelltes Ziel stehen in `docs/RESTORE.md`, der
Installationsnachweis in `validation/voip50-reboot-guard-fix.json`.

Lokale, ungefährliche Prüfungen:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_public_tree.py
```

Die Datei-/Archivprüfungen ersetzen keinen Boot- und echten Telefonietest nach
einer Wiederherstellung. Zugangsdaten gehören in die geschützten Originaldateien,
nicht in Quellcode oder Issues.
