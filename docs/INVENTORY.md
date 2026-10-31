# Inventar

Stand 31.10.2026. IPs und MAC-Adressen wurden direkt in beiden laufenden Gästen
gelesen, FreeSWITCH-Version und Betriebsmodus ebenfalls. Die historischen
Xen-Netzwerk-/VIF-UUIDs stammen aus den gespeicherten Netzwerkplänen.

| Merkmal | VoIP38 | VoIP50 |
| --- | --- | --- |
| Hostname | voip38-next | voip50-next |
| Gast-VM-UUID | d30bf2b6-49e4-7ca7-c7a9-e5640b2ffdb4 | 3558e997-ebeb-1667-beab-52cda40ec3cf |
| frühere DHCP-IP | 192.168.1.213 | 192.168.1.217 |
| LAN-Gerät | enX0 | enX0 |
| LAN-MAC | 02:0c:3e:04:a5:98 | ee:8d:d8:56:54:6a |
| LAN-Adresse | 192.168.1.38/24 | 192.168.1.50/24 |
| LAN-VLAN | 4061 | 4061 |
| WAN-Gerät | enX1 | enX1 |
| WAN-MAC | de:ab:89:d1:fd:17 | ce:cc:cc:cc:cc:cc |
| WAN-Adresse | 92.61.60.38/26 | 92.61.60.50/26 |
| WAN-VLAN | 4001 | 4001 |
| Standardroute | 92.61.60.1 über enX1 | 92.61.60.1 über enX1 |
| DNS | 8.8.8.8 | 8.8.8.8 |
| Profil / default_profile | voip01 / voip01 | voip01 / voip01 |
| Switch-ID | 6 | 4 |
| Betriebsmodus | LIVE | LIVE |
| ursprüngliche VM-Ausstattung | 2 vCPU, 4 GiB RAM, 40 GiB Disk | 2 vCPU, 4 GiB RAM, 40 GiB Disk |
| Programmpräfix | /opt/freeswitch | /opt/freeswitch |
| Konfiguration | /etc/freeswitch | /etc/freeswitch |
| Lua | /var/lib/freeswitch/scripts | /var/lib/freeswitch/scripts |

FreeSWITCH meldet auf beiden Hosts:
`1.11.3-release+git~20260828T204948Z~ef32e20529~64bit`.
Das Archiv enthält den installierten Build und seine Bibliotheken. Native Lua-
Tests wurden mit Lua 5.1 durchgeführt; nicht auf 5.4-spezifische Syntax umstellen.

Die Gäste verwenden UEFI; Root liegt auf `/dev/xvda2`, die EFI-Systempartition auf
`/dev/xvda1`. Beide Partitionen sind im Dateiexport berücksichtigt. Exakte Größen,
UUIDs, Partitionstabelle, Mountoptionen, Kernel und installierte Paketversionen
stehen im jeweiligen verschlüsselten Metadatenarchiv.

Erstellungsgrundlage war „Debian 13 Cloud-init byMark“. Die dokumentierte
50er-Template-UUID ist `4ea13e9e-c8a3-64f9-069c-bbc3cf5a7778`. Für einen vollständigen
Datei-Restore ist die Verfügbarkeit dieser Vorlage nicht erforderlich; eine
passende Debian-13-UEFI-VM mit den angegebenen Ressourcen genügt als Ausgangspunkt.

## Xen-Orchestra und alte VMs

- Alte VoIP38-VM: `7aa787a8-b4ce-acd3-9f16-35b9bfdbd149`.
- Alte VoIP50-VM: `eaf27934-de77-6f2b-5e29-abcc900df8e4`.
- Die alten VMs müssen ausgeschaltet bleiben, solange die neuen dieselben IPs nutzen.
- Gastnamen/VM-Namen können noch „Pilot“ oder „Build“ enthalten; daraus nicht auf
  den tatsächlichen Betriebsmodus schließen.
- Vor Hypervisor-Aktionen die VM im aktuellen XO-Inventar suchen und UUID, MACs,
  Storage, VIFs und Netzwerkzuordnung abgleichen. Die neue 50er-UUID war später
  über den zuvor benutzten XCP-Host nicht mehr auflösbar, während der Gast mit
  identischer Hypervisor-UUID und gepinntem SSH-Schlüssel erreichbar blieb.
  Eine Migration/Inventarursache ist nicht geklärt. Keine alten CLI-IDs blind verwenden.

Die Gast-UUID kann ohne Änderung geprüft werden:

```sh
cat /sys/hypervisor/uuid
ip -br link
ip -4 -br address
ip -4 route
```

## Zugriff

`mark` mit den importierten GitHub-SSH-Schlüsseln, dann `sudo -i`.
Passwortanmeldung als `mark` in der Xen-Konsole und anschließendes sudo wurden
vom Betreiber auf beiden Ersatz-VMs bestätigt. SSH-Passwortanmeldung bleibt aus;
direktes Root-Passwort ist am neuen 50er gesperrt. Schlüssel und Passwort-Hashes
sind nur in den verschlüsselten Root-Dateisicherungen enthalten.

Die produktiven SSH-Hostschlüssel sind Teil der verschlüsselten Sicherung.
Bei Wiederverwendung mit gleicher Identität bleiben sie erhalten; bei einer neuen
Identität neue Hostschlüssel erzeugen und deren Fingerprints über die Xen-Konsole
prüfen, bevor `known_hosts` geändert wird.
