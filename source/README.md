# Quellen und Herkunft

## `installed/`

Direkt aus den entschlüsselten, geprüften Dateisicherungen entnommene
Wartungsprogramme, systemd-Units/Drop-ins und Netzwerkdateien. Originalpfade und
SHA-256-Prüfsummen stehen in `installed-manifest.json`. Diese Kopien dokumentieren
den **tatsächlich installierten Stand**, einschließlich historischer Kommentare
und des bekannten 50er-Neustart-Guard-Problems.

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
- Für die Wiederherstellung ist der installierte Stand im zugehörigen
  verschlüsselten Archiv maßgeblich, nicht die Reihenfolge der Generatoren.

## `recovery/`

Die vorgeschlagene Korrektur des 50er-Netzwerk-Guards wurde während der
Sicherungsprüfung erstellt und offline getestet. Sie ist **nicht** auf dem
laufenden Switch installiert. Installationshinweise nur für ein offline
wiederhergestelltes Ziel stehen in `docs/RESTORE.md`.

Lokale, ungefährliche Prüfungen:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_public_tree.py
```

Die Datei-/Archivprüfungen ersetzen keinen Boot- und echten Telefonietest nach
einer Wiederherstellung. Zugangsdaten gehören in die geschützten Originaldateien,
nicht in Quellcode oder Issues.
