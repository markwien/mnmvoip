# VoIP50: Netzwerk-Guard für spätere Neustarts korrigiert

Installiert am **31.10.2026 um 12:18:17 Uhr Europe/Vienna** auf `192.168.1.50`,
nach ausdrücklicher Betreiberfreigabe. Kein Reboot, kein Dienstneustart und
kein `ifup`/`ifdown` wurden ausgeführt.

## Ursache und Verhalten

Beide Interface-Stanzas rufen in `pre-up` den Helfer
`/usr/local/libexec/voip50-check-interface` auf. Der ursprüngliche Helfer verlangte
bei jedem Aufruf den einmaligen, nur 15 Minuten gültigen Umschaltnachweis.
Nach dessen Ablauf wurden deshalb auch bereits dauerhaft freigegebene Interfaces
abgewiesen. Vor dem Fix scheiterten die direkten Prüfaufrufe für enX0 und enX1.

Der neue Helfer trennt die erste Aktivierung von einem späteren Start:

- Bei **erster Aktivierung** ohne dauerhaften Nachweis bleiben die frische
  Freigabe und die bestätigte Abschaltung des vorherigen IP-Besitzers erforderlich.
- Bei vorhandenem **dauerhaften Nachweis** muss MODE exakt LIVE sein. Der
  rootgeschützte Nachweis muss autorisiert sein und vollständig zur Gast-UUID
  sowie zum gesamten aktuellen Netzwerkplan passen. Der alte Timestamp wird
  in diesem Fall nicht mehr verlangt.
- Interface-Name, Rolle, MAC und tatsächliche Gast-Hypervisor-UUID bleiben geprüft.
  Ungültige vorhandene Nachweise fallen nicht auf eine schwächere Prüfung zurück.

Es wurden keine Freigaben neu erzeugt, keine Zeitstempel verlängert und keine
Netzwerk-/Firewall-Prüfungen entfernt.

## Installierte Dateien

| Pfad | Berechtigung |
| --- | --- |
| `/usr/local/libexec/voip50-check-interface` | root:root 0700 |
| `/root/voip50-build/network-preparation/voip50_check_interface.py` | root:root 0600 |
| `/home/mark/voip50-build-input/voip50_check_interface.py` | root:root 0600 |

Alle drei Dateien haben den SHA-256-Wert:
`afd801290a7806d31aa5dbd97ba90534058f5f480ad317fa02ed241e2bf61911`.

Die vorherigen Dateien liegen geschützt und mit Originalrechten unter
`/root/voip50-build/reboot-guard-fix-20261031T111817Z/` in ihren ursprünglichen
Unterpfaden. Diese Sicherung nicht in die öffentliche Git-Struktur kopieren.
Der zugehörige Quelltext liegt unter
[`source/recovery/voip50_check_interface.py`](../source/recovery/voip50_check_interface.py).

## Prüfung ohne Neustart

Der Kandidat wurde zunächst separat auf dem Gast geprüft und erst danach atomar
an die aktiven Pfade gesetzt. Anschließend wurden nur diese lesenden Aufrufe ausgeführt:

```sh
sudo /usr/local/libexec/voip50-check-interface enX0 internal
sudo /usr/local/libexec/voip50-check-interface enX1 public
```

Beide geben Exitcode 0 zurück. Vertauschte Rollen geben weiterhin Exitcode 1
zurück. Keiner dieser Aufrufe aktiviert oder deaktiviert ein Interface.

Zusätzliche Prüfung:

- FreeSWITCH blieb aktiv, PID vorher und nachher **9574**.
- Unveränderte IPs/MACs und Routen, unveränderte Firewalldefinition.
- Unveränderte Hashes von Netzwerkplan, dauerhafter Freigabe, MODE,
  `/etc/nftables.conf`, Interface-Datei, FS-Master-XML und aktivem `dbconnect.lua`.
- Zum unmittelbaren Prüfzeitpunkt waren vor und nach der Änderung null aktive Calls.
  Es wurden keine Rufwege geändert, Sessions beendet oder FS-Reloads ausgeführt.
- Zehn lokale Regression-/Sicherungs-Tests bestanden; darunter der nachgestellte
  Fehler des alten Guards bei abgelaufenem Nachweis.

Maschinenlesbarer [Installationsnachweis](../validation/voip50-reboot-guard-fix.json).
Ein echter Reboot ist weiterhin **nicht getestet**; der Auftrag untersagte einen Neustart.

## Wiederherstellung und Rücknahme

Die großen verschlüsselten Basisarchive bleiben unverändert und enthalten den
alten Guard. Deshalb bei jeder Wiederherstellung den neuen Guard und seine
beiden Quellkopien gemäß [RESTORE.md, Abschnitt 5](RESTORE.md#5-bekannte-50er-neustartfalle-vor-dem-ersten-restore-boot-behandeln)
übernehmen. Die alte Datei unter `source/installed/` bleibt als Snapshot und
Regressionstest erhalten, nicht als aktueller Installationskandidat.

Falls eine Rücknahme nötig wird, ausschließlich die drei Guard-Dateien aus dem
genannten Backup atomar zurücksetzen. Auch das braucht keinen Netzwerk-/FS-Neustart,
stellt aber die alte Neustartfalle wieder her. Originalnachweise nicht bearbeiten.
