# Sicherung und Schlüssel

## Inhalt und Speicherorte

`backups/2026-10-31/manifest.json` beschreibt vier verschlüsselte Dateien:
je ein Root-Dateisystemarchiv und ein Metadatenarchiv für 38 und 50. Die Dateien
sind in höchstens 40 MiB große Git-Dateien zerlegt. Jeder Teil und jedes wieder
zusammengesetzte Archiv besitzt eine SHA-256-Prüfsumme.

Verschlüsselung: GnuPG OpenPGP, AES-256, zufällige Passphrase mit 384 Bit
Zufallsentropie, SHA-512 S2K mit hohem Iterationswert und Integritätsschutz.
Unverschlüsselte Root-Dateisystemarchive wurden nicht auf der Arbeitsstation
abgelegt; SSH-Ausgabe wird direkt in GnuPG geleitet. Die Passphrase wird über
einen Dateideskriptor statt über die Prozessargumente übergeben.

Der separate Schlüssel wurde auf Marks Arbeitsstation unter folgendem Pfad
erstellt (Datei 0600, Elternverzeichnis 0700):

```text
/Users/mark/Documents/ChatGPT/AWX/private-backups/voip-20261031/recovery-passphrase.txt
```

**Diese Datei jetzt zusätzlich im eigenen Passwortmanager oder einem getrennten
Offline-Tresor aufbewahren.** Sie wird nicht zu GitHub übertragen. Ohne sie sind
die Archive nicht wiederherstellbar. Beide Server verwenden für diesen einmaligen
Sicherungssatz dieselbe zufällige Passphrase. SSH-Login-Schlüssel können die
Archive nicht entschlüsseln. Die lokale Passphrase-Datei nicht löschen, bevor
eine unabhängige sichere Kopie geprüft wurde.

Die vier vollständigen verschlüsselten Dateien liegen zusätzlich lokal in
demselben privaten Verzeichnis. Diese lokalen Kopien ersetzen keine separate
Schlüsselsicherung; ein reiner Verlust der Arbeitsstation muss durch GitHub-Kopie
plus unabhängig aufbewahrten Schlüssel abgedeckt werden.

## Root-Dateisystem

Enthalten sind unter anderem Betriebssystemdateien, Kernel/initramfs, EFI-Dateien,
Benutzer und Passwort-Hashes, SSH-Identitäten und autorisierte Schlüssel, alle
Konfigurationen, `/opt/freeswitch` mit Modulen/Bibliotheken, `/usr/local`, Lua-
Skripte, lokale Ansagen und Generationen, lokale Logs/CDRs, rootgeschützte
Produktionsreferenzen, Kandidaten und Umschaltunterlagen.

ACLs, xattrs, numerische Besitzer, Modi, Hardlinks und Symlinks werden durch
GNU tar erhalten. Die separat gemountete EFI-Partition wird ausdrücklich
mitgelesen. Keine NFS-Inhalte werden rekursiv vom NAS gezogen; die lokalen
Ansagenkopien sind enthalten.

Ausgenommen: `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/mnt`,
`/media`, `lost+found`, Swap-Dateien, heruntergeladener APT-Paketcache sowie
die aktiven FreeSWITCH-SQLite-Dateien. Deren konsistente Online-Sicherungen
stehen stattdessen im Metadatenarchiv.

## Metadaten

- Paketnamen, genaue Versionen/Architektur und manuell installierte Pakete.
- Tatsächliche IPs/MACs, Routing, Firewall als Text/JSON, Mounts und Blockgeräte.
- GPT-Partitionstabelle, Dateisystem-UUIDs, aktive Units/Timer und vollständige
  zusammengesetzte FreeSWITCH-systemd-Unit.
- FreeSWITCH-Version, Status, Modulübersicht, Linker-Abhängigkeiten, Kernel.
- SHA-256-Dateimanifest von `/etc`, `/usr/local`, `/opt/freeswitch` und Lua.
- SQLite-Online-Sicherungen: 38 drei Datenbanken, 50 zwei. Alle vor und nach
  Übertragung mit `PRAGMA integrity_check` geprüft.

Die Metadaten sind ebenfalls verschlüsselt: Auch Firewall-Listen und bestimmte
Statusausgaben können vertrauliche betriebliche Informationen enthalten.

## Grenzen

Dies ist eine geprüfte **Live-Dateisicherung**, kein atomarer XVA-/Block-Snapshot.
Logs, CDRs und generierte Caches können sich während des Lesens verändern;
die separat gesicherten SQLite-Dateien sind jeweils konsistent, aber keine
gemeinsame Transaktion über alle Dateien und die externe MariaDB hinweg.
Das RPO ist der Sicherungszeitraum am 31.10.2026; spätere Änderungen fehlen.

Nicht enthalten sind zentrale MariaDB-/Panel-Server, vollständige NAS-Freigabe,
Xen-Orchestra-Datenbank, XCP-ng-Hostinstallation oder Providerkonfiguration.
Ein Restore des Switches setzt funktionierende externe Abhängigkeiten voraus.
Für einen Totalausfall der Gesamtplattform sind zusätzliche unabhängige DB-,
NAS- und Hypervisor-Sicherungen nötig; diese wurden hier nicht verändert.

## Neue Sicherung erzeugen

`scripts/backup.py --help` beschreibt den gepinnten SSH-Aufruf. Metadaten werden
mit `scripts/export_metadata.py` über root SSH direkt in denselben verschlüsselten
Empfänger geleitet (`--remote-command-file`). Eine neue Passphrase außerhalb
des Repositories erzeugen; keine alten Sicherungsdateien überschreiben.

Vor einer Veröffentlichung immer `verify_backup.py` auf beide zusammengehörigen
Archive anwenden. GnuPG-Exitstatus, vollständiges Lesen aller Tar-Inhalte,
übereinstimmende stabile Datei-Hashes und SQLite-Integrität müssen erfolgreich sein.
Öffentliche JSON-Prüfberichte enthalten nur sichere Zusammenfassungen. Rohdaten,
Passphrasen, privaten Schlüssel und entschlüsselte Archive niemals committen.

Es wurde kein automatischer Backup-Zeitplan angelegt. Nach Konfigurationsänderungen
den Stand bewusst neu sichern; die Sicherung vom 31.10. ist unveränderliche Referenz.
