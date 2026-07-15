$ORIGIN aigw.aegisgroup.ch.
$TTL 60

@       IN SOA  dns.aigw.aegisgroup.ch. hostmaster.aigw.aegisgroup.ch. (
                    2026071501 ; serial
                    3600       ; refresh
                    900        ; retry
                    604800     ; expire
                    60         ; negative cache TTL
                )
        IN NS   dns.aigw.aegisgroup.ch.
        IN A    10.20.0.10

; Restricted internal view: only DNS itself, the inference API, developer
; portal, Open WebUI chat (owner decision: LAN-reachable, still gated by
; aigw-chat), and the minimum Keycloak browser login route are discoverable.
dns     IN A    10.20.0.10
api     IN A    10.20.0.10
portal  IN A    10.20.0.10
auth    IN A    10.20.0.10
chat    IN A    10.20.0.10
