# Firewall und zwei Netzwerkkarten

Beide Switches haben einen internen und einen öffentlichen Anschluss. Die
Zuordnung wird über MAC-Adressen und Netzwerkpläne geprüft. `enX0`/`enX1`
allein sind nach neuer VM-Erstellung keine ausreichend verlässliche Identität.

Die Sicherung enthält sowohl `/etc/nftables.conf` als auch den tatsächlich
geladenen Ruleset im verschlüsselten Metadatenarchiv. Beim Restore zuerst den
öffentlichen VIF getrennt lassen und den Ruleset laden/prüfen, dann erst nach
freigegebener Umschaltung verbinden. Niemals zur Fehlerbehebung pauschal
`nft flush ruleset` ausführen.

| Verkehr | Übernommene Regel |
| --- | --- |
| INPUT / FORWARD | standardmäßig DROP |
| Loopback / bestehende Verbindungen | gemäß Original-Regelwerk zulassen |
| LAN enX0 | ursprüngliche interne `loc`-Policy |
| WAN, trust4 | TCP 21, 22, 80, 3306, 5029, 8021, 8080, 10050; UDP 5029, 5060; ICMP |
| WAN, voip4 | TCP 22; UDP 5060 |
| WAN, übrige Quellen | RTP UDP 10000–60000 und nötige ICMP-/Legacy-Ausnahmen gemäß gespeichertem Ruleset |
| ESL TCP 8021 | WAN nur trust4, zusätzlich restriktive FreeSWITCH-ESL-ACL und Passwort |
| SIP TCP/TLS | nicht als neue pauschale öffentliche Freigabe ergänzen |

Der breite RTP-Quellbereich ist vom Bestand übernommen: Medien können von
anderen IPs als die SIP-Signalisierung kommen. Deshalb nicht ohne echten
Medientest auf die Signalisierungs-Allowlist begrenzen. Gleichzeitig bedeutet
die RTP-Freigabe keine allgemeine SIP- oder ESL-Freigabe.

Auf dem 50er sind aktuell 15 normalisierte `trust4`- und 69 `voip4`-Einträge aus
der **alten tatsächlich aktiven Firewall** maßgeblich. Die vom ID4-Panel gelieferte
Liste weicht davon ab (zusätzliche 209.160.64.56 und 81.26.202.53, fehlende
89.202.102.86). Deshalb gibt es auf dem neuen 50er keinen automatischen Ersatz
des LIVE-Rulesets durch diese abweichende Panel-Liste.

Die 50er-Laufzeit prüft beim Start, dass ausschließlich `table inet voip50_live`
aktiv ist und dessen normalisierte Regeln dem geschützten
`/root/voip50-build/live-preparation/expected-firewall.json` entsprechen.
Zusätzliche Firewall-Tabellen oder ungeprüfte Änderungen können den Start zu
Recht blockieren. Den Vergleich nicht durch blindes Überschreiben des Sollwerts umgehen.

Auf dem 38er aktualisiert `voip38-firewall-fetch.timer` minütlich aus der dafür
vorgesehenen Panel-Quelle. Fehlerhafte/unvollständige Antworten werden verworfen;
der bisherige Stand bleibt erhalten. Beide Mechanismen müssen beim Restore
entsprechend ihrem tatsächlichen Switch erhalten bleiben.

Prüfung ohne Aktivierung eines neuen Rulesets:

```sh
nft --check --file /etc/nftables.conf
nft list tables
nft list ruleset
ip -4 route get 198.96.222.228
fs_cli -x 'acl 198.96.222.228 domains'
```

Auf dem 50er sind IPv6 und Forwarding für LIVE deaktiviert. Auf dem 38er kann
eine interne IPv6-Link-Local-Adresse vorhanden sein; eine neue öffentliche
IPv6-Freigabe ist nicht Teil der Übernahme. Die beiden Output-Policies sind
nicht identisch: 50 verwendet die geprüfte IPv4-/Interface-Begrenzung, 38 den
eigenen Integrator-Ruleset. Keine generische Firewall auf beide Maschinen kopieren.
