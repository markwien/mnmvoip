# MNM VoIP – Betrieb und Wiederherstellung von VoIP38 und VoIP50

Gesicherter Stand vom **31. Oktober 2026, etwa 11:48–11:50 Uhr Europe/Vienna**.
Beide Ersatz-Switches sind produktiv: Debian 13, FreeSWITCH 1.11.3, Lua 5.1.
Die Sicherung erfolgte lesend, ohne Dienstneustart oder Netzwerkumschaltung.

Dieses öffentliche Repository enthält die Betriebsdokumentation, geprüften
Wiederherstellungswerkzeuge, Wartungsquellen und **verschlüsselte vollständige
Dateisicherungen beider Switches**. Die Originalkonfigurationen einschließlich
Zugangsdaten, lokaler CDRs, Ansagen und Referenzen liegen ausschließlich in diesen
verschlüsselten Archiven. Der Entschlüsselungsschlüssel gehört nicht ins Repository.

| System | LAN | Öffentlich | Panel-Konfiguration | Switch-ID |
| --- | --- | --- | --- | --- |
| VoIP38 | 192.168.1.38/24 | 92.61.60.38/26 | altes Panel / telemediacloud.com | 6 |
| VoIP50 | 192.168.1.50/24 | 92.61.60.50/26 | 192.168.1.225:9000 | 4 |

Für die Wiederherstellung zuerst [RESTORE.md](docs/RESTORE.md) lesen. Die
Schrittfolge unterscheidet zwischen einer Ersatzplatte in derselben VM und einer
vollständig neu angelegten VM mit neuen UUIDs/MAC-Adressen.

- [Inventar und Netzwerkkarten](docs/INVENTORY.md)
- [Architektur, XML, Lua und Abrechnung](docs/ARCHITECTURE.md)
- [Betrieb, Diagnose und CDRs](docs/OPERATIONS.md)
- [Firewall und Netzwerkschutz](docs/FIREWALL.md)
- [Sicherungsumfang und Schlüssel](docs/BACKUP.md)
- [Wiederherstellung und Rückfallplan](docs/RESTORE.md)
- [Nachweise, Änderungen und offene Punkte](docs/VALIDATION.md)
- [Wartungsquellen und ihre Verwendung](source/README.md)

Die zentrale MariaDB `ccsystem`, die Panels, das NAS und die Xen-Orchestra-
Infrastruktur sind externe Abhängigkeiten. Ihre Server werden hier **nicht**
gesichert. Lokal vorhandene Konfigurations- und Ansagenkopien sind enthalten.

Die Archive wurden entschlüsselt, vollständig gelesen und auf Prüfsummen geprüft;
alle fünf SQLite-Sicherungen bestanden `integrity_check`. Ein Boot-/Telefonietest
einer aus diesen Archiven neu wiederhergestellten VM wurde noch nicht durchgeführt.

**Aktualisierung 31.10.2026, 12:18 Uhr:** Die Neustartfalle im Netzwerk-Guard des
50ers ist ohne Neustart behoben. Der Hotfix und beide Schnittstellen wurden am
LIVE-Gast lesend geprüft. Die unveränderten verschlüsselten Archive enthalten
den früheren Stand; beim Restore deshalb den [Guard-Overlay aus Abschnitt 5](docs/RESTORE.md#5-bekannte-50er-neustartfalle-vor-dem-ersten-restore-boot-behandeln)
einspielen. [Änderung und Nachweise](docs/VOIP50-REBOOT-GUARD-FIX.md).

## Sicherung laden und prüfen

Ein vollständiger Clone umfasst ungefähr 1,6 GB verschlüsselte Sicherungsdaten.
Die Archive sind wegen des GitHub-Dateilimits in Teile zu je höchstens 40 MiB zerlegt.

```sh
git clone https://github.com/markwien/mnmvoip.git
cd mnmvoip
python3 scripts/reassemble.py backups/2026-10-31/manifest.json --output restore-work/encrypted
python3 scripts/verify_backup.py \
  --rootfs restore-work/encrypted/voip50-rootfs.tar.gz.gpg \
  --metadata restore-work/encrypted/voip50-metadata.tar.gz.gpg \
  --passphrase-file /sicherer/ort/recovery-passphrase.txt
```

Voraussetzungen: Python ab 3.9, GnuPG und genügend freier Speicher. Für die eigentliche
Wiederherstellung Linux-Rescue mit GNU tar, ACL-/xattr-Unterstützung und Root-Rechten
verwenden. Niemals ein Root-Dateisystemarchiv auf einem laufenden Switch entpacken.
