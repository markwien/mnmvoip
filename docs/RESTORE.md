# Wiederherstellung

Dieses Verfahren stellt die **gesicherten Switch-Dateien** wieder her. Es setzt
die externe MariaDB, Panels, NAS, VLANs und Provider-Zustellung voraus. Ein
kompletter Restore-Boot wurde bisher nicht durchgeführt; erfolgreiche Prüfungen
stehen in [VALIDATION.md](VALIDATION.md).

## 1. Ziel und Umschaltung festlegen

Für einen gefahrlosen Restore-Test eine separate VM mit **beiden VIFs getrennt**
anlegen. Nicht parallel dieselben produktiven IPs im LAN/WAN aktivieren.

Für einen echten Ersatz zuerst den noch existierenden Switch sauber außer
Betrieb nehmen: Eingänge nach Absprache pausieren, Gespräche auslaufen lassen,
`show calls count` auf null prüfen, Gast herunterfahren, in XO `halted` und beide
VIFs inaktiv prüfen. Die alten CentOS-VMs ebenfalls ausgeschaltet lassen.
Den jeweils anderen funktionierenden Switch nicht beiläufig stoppen.

Zwei Fälle unterscheiden:

- **Ersatzplatte in derselben VM:** Gast-UUID und beide MACs bleiben identisch.
  Die gespeicherten Netzwerk-/Laufzeitpläne können nach Prüfung erhalten bleiben.
- **Vollständig neue VM:** Neue UUIDs/MACs passen nicht zu den gespeicherten
  Guards. Erst Identitäten, Pläne und beim 50er die gebundenen Vorlagen anpassen;
  siehe Abschnitt 6. Ein blindes Hochfahren der kopierten Konfiguration reicht nicht.

VM für Debian 13 amd64, UEFI und genügend Root-Speicher bereitstellen. Die
Sicherung enthält etwa 1,5 GB reguläre Nutzdateien je Switch; mindestens die
bisherige Plattengröße verwenden und ausreichend Platz für CDRs/Logs vorsehen.
Die genauen ursprünglichen Partitionen stehen im Metadatenarchiv. Als einfache
Grundlage Debian 13 mit EFI-Partition und ext4-Root installieren, dann mit einer
Linux-Rescue-ISO starten. Den Netzwerkzugriff auf das Restore-Arbeitsverzeichnis
nur über eine sichere Managementverbindung herstellen.

## 2. Verschlüsselte Dateien zusammensetzen und verifizieren

```sh
git clone https://github.com/markwien/mnmvoip.git
cd mnmvoip
python3 scripts/reassemble.py backups/2026-10-31/manifest.json --output restore-work/encrypted
python3 scripts/verify_backup.py \
  --rootfs restore-work/encrypted/voip50-rootfs.tar.gz.gpg \
  --metadata restore-work/encrypted/voip50-metadata.tar.gz.gpg \
  --passphrase-file /sicherer/ort/recovery-passphrase.txt
```

Für 38 die Dateinamen ändern. Bei fehlendem Teil, falscher Prüfsumme, GPG-Fehler
oder SQLite-Fehler abbrechen. Den Schlüssel aus dem getrennten Tresor beziehen;
er ist weder im GitHub-Repository noch aus den SSH-Schlüsseln rekonstruierbar.

## 3. Ausschließlich auf das offline gemountete Ziel entpacken

Ab hier Root in einer Linux-Rescue-Umgebung, GNU tar und GnuPG benutzen.
Zielgeräte anhand `lsblk -f` prüfen; die folgenden `/dev/xvda*` sind Beispiele
für den dokumentierten Aufbau und dürfen nicht ungeprüft übernommen werden.
Diese Schritte überschreiben Dateien auf dem gewählten Ziel. Niemals `/` eines
laufenden Systems als Entpackziel verwenden.

```sh
mkdir -p /mnt/recovered
mount /dev/xvda2 /mnt/recovered
mkdir -p /mnt/recovered/boot/efi
mount /dev/xvda1 /mnt/recovered/boot/efi
findmnt /mnt/recovered
findmnt /mnt/recovered/boot/efi
umask 077
mkdir -p /sicheres/restore-work
gpg --output /sicheres/restore-work/rootfs.tar.gz --decrypt restore-work/encrypted/voip50-rootfs.tar.gz.gpg
gpg --output /sicheres/restore-work/metadata.tar.gz --decrypt restore-work/encrypted/voip50-metadata.tar.gz.gpg
```

GnuPG fragt nach der separat aufbewahrten Passphrase. Erst nach erfolgreicher
Authentifizierung/Exitcode 0 entpacken; die entschlüsselten Dateien bleiben im
geschützten Arbeitsbereich. Sie enthalten auch Passwort-Hashes und private
Schlüssel. Root-Archiv und Metadaten müssen vom selben Switch/Sicherungssatz sein.

```sh
tar --acls --xattrs --numeric-owner --same-owner --same-permissions \
  -xzpf /sicheres/restore-work/rootfs.tar.gz -C /mnt/recovered
mkdir -p /sicheres/restore-work/metadata
tar -xzpf /sicheres/restore-work/metadata.tar.gz -C /sicheres/restore-work/metadata
mkdir -p /mnt/recovered/proc /mnt/recovered/sys /mnt/recovered/dev /mnt/recovered/run
mkdir -p /mnt/recovered/tmp /mnt/recovered/var/tmp /mnt/recovered/mnt /mnt/recovered/media
chmod 1777 /mnt/recovered/tmp /mnt/recovered/var/tmp
mkdir -p /mnt/recovered/var/lib/freeswitch/db
cp /sicheres/restore-work/metadata/sqlite/*.db /mnt/recovered/var/lib/freeswitch/db/
chroot /mnt/recovered chown -R freeswitch:freeswitch /var/lib/freeswitch/db
chroot /mnt/recovered chmod 750 /var/lib/freeswitch/db
find /mnt/recovered/var/lib/freeswitch/db -type f -name '*.db' -exec chmod 600 '{}' +
touch /mnt/recovered/etc/cloud/cloud-init.disabled
```

Keine alten SQLite-WAL/SHM-Dateien von einem anderen Stand ergänzen. Das Archiv
enthält keine Live-Kanäle; aktive Gespräche lassen sich nicht wiederherstellen.
Die SQLite-Kopien sind pro Datei konsistent, externe Abrechnungsdaten werden
nicht zurückgedreht.

Cloud-init wird **nur auf dem Restore-Ziel** deaktiviert, damit eine neue
XO-Instanzidentität keine ursprünglichen First-Boot-Befehle, Paketupgrades,
Passwort-/Netzwerkänderungen oder Reboots erneut auslöst. Erst nach Abnahme
bewusst über eine spätere Wiederverwendung von Cloud-init entscheiden.

## 4. Bootfähigkeit und Gerätedaten korrigieren

- `/mnt/recovered/etc/fstab` an die tatsächlichen neuen Dateisystem-UUIDs aus
  `blkid` anpassen. Root und EFI nicht mit alten, unpassenden UUIDs belassen.
- Der Sicherungssatz enthält `/boot` und die EFI-Dateien, aber keinen Block-
  Bootsektor/XVA-Container. Falls nötig den Debian-UEFI-Bootloader aus Rescue
  neu installieren. Dafür `/dev`, `/proc`, `/sys` ins Chroot verfügbar machen.
- Beispiel für eine UEFI-Wiederinstallation, erst nach Prüfung der Mounts:

```sh
mount --rbind /dev /mnt/recovered/dev
mount --make-rslave /mnt/recovered/dev
mount -t proc proc /mnt/recovered/proc
mount --rbind /sys /mnt/recovered/sys
mount --make-rslave /mnt/recovered/sys
chroot /mnt/recovered update-initramfs -u -k all
chroot /mnt/recovered grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --no-nvram
chroot /mnt/recovered update-grub
```

Den UEFI-Booteintrag im Xen-Firmwaremenü prüfen; wenn dieses einen Fallback-
Bootpfad verlangt, GRUB entsprechend für den Wechseldatenträger-/Fallbackpfad
installieren. BIOS- und UEFI-Installationen nicht mischen. Nach Arbeiten im
Chroot Bind-Mounts sauber lösen; Rescue-Datenträger nicht versehentlich als
Dauerbootmedium belassen.

## 5. Bekannte 50er-Neustartfalle vor dem ersten Restore-Boot behandeln

**Im ursprünglichen Sicherungsarchiv vorhanden; am LIVE-50er am 31.10.2026
um 12:18 Uhr Europe/Vienna ohne Neustart behoben:**
`/usr/local/libexec/voip50-check-interface` wird durch `pre-up` beider Interfaces
ausgeführt. Der alte Helfer verlangt auch nach erfolgreicher Inbetriebnahme
noch einen weniger als 15 Minuten alten Umschaltnachweis. Dieser ist später
zwangsläufig abgelaufen; deshalb kann ein regulärer Reboot das Netz blockieren.
Die FreeSWITCH-Laufzeit selbst besitzt bereits eine dauerhafte Commissioning-
Prüfung, der Netzwerk-Helfer noch nicht.

Die getestete und inzwischen produktiv installierte Korrektur liegt in
`source/recovery/voip50_check_interface.py`. Die verschlüsselten Basisarchive
bleiben unverändert; dieser Quelltext ist der notwendige Restore-Overlay.
Er akzeptiert nach Inbetriebnahme
nur den rootgeschützten, vollständig zum aktuellen Plan passenden dauerhaften
Nachweis. MAC, Rolle und tatsächliche Gast-UUID bleiben geprüft. Ohne diesen
Nachweis ist für die erste Aktivierung weiterhin frische Abschalt-/Freigabeevidenz nötig.

Nur auf dem **offline wiederhergestellten Ziel** installieren und diese Abweichung
vom archivierten Original protokollieren:

```sh
cp /mnt/recovered/usr/local/libexec/voip50-check-interface \
   /mnt/recovered/root/voip50-check-interface.before-recovery
install -o root -g root -m 700 source/recovery/voip50_check_interface.py \
   /mnt/recovered/usr/local/libexec/voip50-check-interface
install -o root -g root -m 600 source/recovery/voip50_check_interface.py \
   /mnt/recovered/root/voip50-build/network-preparation/voip50_check_interface.py
install -o root -g root -m 600 source/recovery/voip50_check_interface.py \
   /mnt/recovered/home/mark/voip50-build-input/voip50_check_interface.py
```

Bei derselben VM und unverändertem Plan wird der vorhandene dauerhafte Nachweis
verwendet. Bei einer neuen VM erst Abschnitt 6 durchführen. Nicht einfach den
Timestamp eines alten Umschaltnachweises erneuern oder den Guard auskommentieren.
Die zwei Quellkopien werden mit aktualisiert, damit eine spätere Installation
nicht versehentlich den alten Guard zurückbringt. Details und Prüfsummen stehen
in [VOIP50-REBOOT-GUARD-FIX.md](VOIP50-REBOOT-GUARD-FIX.md).

## 6. Vollständig neue VM: Identität bewusst neu binden

Beide Netzwerkkarten vorerst getrennt lassen. In der Xen-Konsole booten, als
`mark` anmelden, `sudo -i`, dann `systemctl stop freeswitch`. Vor jeglicher
LAN-Anbindung die tatsächlichen neuen MACs und die Gast-UUID notieren:

```sh
cat /sys/hypervisor/uuid
ip -br link
```

Die Zuordnung lautet LAN/VLAN4061 → enX0 und WAN/VLAN4001 → enX1. In XO die
richtigen Netzwerke anhand des aktuellen Pools prüfen. NIC-MACs dürfen nur dann
wiederverwendet werden, wenn die bisherige VM vollständig außer Betrieb ist.

### Beide Systeme

`/etc/voipNN/network-plan.json` muss die tatsächlichen Interface-Namen, MACs,
`new_vm_uuid`, VIF-/Netzwerk-Referenzen und unveränderten vorgesehenen IPs enthalten.
Datei root:root 0600. Dazu `/etc/network/interfaces.d/50-cloud-init` und jede
zugehörige `pre-up`-Rollenprüfung kontrollieren. Die Kommentare „INACTIVE/BUILD“
in manchen historischen Dateien bezeichnen deren Entstehung und sagen nichts
über den aktuellen LIVE-Modus aus.

Wenn für einen Restore-Test eine eigene DHCP-IP verwendet wird, müssen MODE,
statische Netzwerkdateien und Schutz-Firewall gemeinsam auf einen isolierten
BUILD-Stand gesetzt werden. Ein bloßer DHCP-Wechsel bei LIVE-Konfiguration
verhindert weder DB-Zugriff noch falsche öffentliche SIP-Adressen. Die alten
Umschaltskripte nicht blind erneut ausführen.

### Zusätzliche Bindungen am 50er

Die alte UUID ist `3558e997-ebeb-1667-beab-52cda40ec3cf`. Sie ist in diesen
aktiven bzw. wieder installierbaren Quellen fest gebunden und muss für eine
neue VM einheitlich ersetzt werden:

- Konstante `VM` in `/usr/local/libexec/voip50-live-runtime` und dessen
  rootgeschützter Quellkopie unter `/root/voip50-build/live-preparation/source/`.
- Guard in `/var/lib/freeswitch/scripts/dbconnect.lua`.
- Dieselbe DB-Vorlage in
  `/root/voip50-build/live-preparation/candidate/dbconnect.lua` (Symlinkziel!)
  und `.../source/voip50_live_dbconnect.lua`.
- Netzwerkplan und relevante noch verwendete Identitätsdateien.

Zur Suche ausschließlich geschützte Dateien lokal prüfen, nichts davon öffentlich
ausgeben. Historische Auditbeweise nicht als neue Freigabe umschreiben.
Vor neuer Inbetriebnahme veraltete Laufzeitnachweise
`/etc/voip50/live-commissioned.json`, `/etc/freeswitch/voip50-live-meta.json`,
`/etc/freeswitch/voip50-live-ready` geschützt archivieren und entfernen.

Eine neue Aktivierung benötigt echten, aktuellen Nachweis, dass **alle bisherigen
Besitzer der .50-Adressen** aus sind. Die vorhandene Proof-Struktur verlangt
`user_authorized_live`, `old_vm_halted`, `old_vifs_inactive`, `checked_epoch`,
`new_vm_uuid`, `old_vm_uuid`; UUIDs müssen zum neuen Netzwerkplan passen und der
Nachweis muss jünger als 15 Minuten sein. `old_vm_uuid` auf den tatsächlich zu
ersetzenden bisherigen LIVE-Gast beziehen; nicht fälschlich nur den schon lange
ausgeschalteten CentOS-50er prüfen. Erst nach realer Prüfung diese rootgeschützte
Datei unter `/root/voip50-build/cutover/authorization.json` erstellen.

Der korrigierte Interface-Guard erlaubt damit die erste Netzanbindung.
`voip50-live-runtime start` erzeugt anschließend neue dauerhafte Nachweise aus
dem übereinstimmenden Plan. Keine alten `activate_network.py`-Skripte verwenden:
Diese sind auf die ursprünglichen VM-UUIDs, BUILD-Firewall und den damaligen
Umschaltablauf zugeschnitten und können bei Fehlschlag FreeSWITCH stoppen.

## 7. Firewall vor Netz, Dienste danach

Vor Verbindung des WAN-VIF:

1. Wiederhergestellten Ruleset mit `nft --check --file /etc/nftables.conf` prüfen.
2. Regeln gezielt laden; keine bestehende Schutz-Firewall zwischendurch leeren.
   Auf dem 50er muss der normalisierte Stand der gespeicherten Soll-Firewall
   entsprechen und ausschließlich die vorgesehene Tabelle vorhanden sein.
3. Prüfen, dass andere Besitzer der produktiven LAN-/WAN-Adressen tatsächlich aus sind.
4. Über Xen-Konsole beide Rollen, MACs und IPs prüfen, erst danach die VIFs
   entsprechend dem freigegebenen Umschaltplan verbinden/Interfaces hochfahren.
5. Standardroute über öffentliche NIC, korrekte ARP-/Nachbarauflösung und
   geschützte SSH-Erreichbarkeit bestätigen. Nicht über einen pauschalen offenen
   Firewall-Notfallmodus „retten“.

Erst bei stimmiger Identität/Firewall FreeSWITCH starten. Die originalen
systemd-Units und Drop-ins aus der Sicherung benutzen; kein generisches
Paket-Unit an deren Stelle aktivieren. Passende Prompt- und CDR-Timer sowie auf
dem 38er den Firewall-Fetch-Timer prüfen. NAS-Freigabe muss die aktuelle Quell-IP
erlauben; Panel-IP-Freigabe und DB-Hostrechte müssen ebenfalls passen.

## 8. Abnahme und Rückfall

```sh
systemctl is-active freeswitch
systemctl --failed
fs_cli -x status
fs_cli -x 'global_getvar switchid'
fs_cli -x 'global_getvar default_profile'
fs_cli -x 'sofia status profile voip01'
fs_cli -x 'acl 198.96.222.228 domains'
fs_cli -x 'show calls count'
```

Zusätzlich: beide ODBC-DSNs mit einem reinen `SELECT 1` über die native FS-
Verbindung testen; ESL vom vorgesehenen Panel und lokal prüfen; XML-Abruf und
Cache, Ansagen-Sync und Rotation kontrollieren. Kein produktives Schema oder
Abrechnungskonto zum Test verändern.

Der Betreiber sendet echte manuelle Anrufe: Aufbauzeit, Ton/Ansage, beide
Medienrichtungen bei Gespräch, Auflegen. Lokale CSVs und zentrale A-/B-CDRs mit
Zeit und Dauer abgleichen. Ein Boot-/Telefonietest auf dem wiederhergestellten
System ist vor einer erfolgreichen Wiederherstellungsabnahme zwingend nachzuholen.

Wenn der neue Restore nicht abnahmefähig ist: diesen Gast stoppen und seine
beiden VIFs trennen, Zustand prüfen, **erst dann** den zuvor funktionierenden
Gast wieder starten. Niemals die IPs gleichzeitig benutzen. Nach erfolgreicher
Abnahme entschlüsselte Arbeitsdateien aus dem temporären Restore-Bereich nach
dem betrieblichen Löschverfahren entfernen und einen neuen Sicherungssatz erstellen.
