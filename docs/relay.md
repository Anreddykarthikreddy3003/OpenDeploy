# Relay ingress

Relay mode publishes apps from a node that has no inbound ports (CGNAT, dynamic
IPs, home networks). It implements PRD §10.3 and control SC-13: the relay is
trusted for routing metadata and availability, **not** for plaintext.

```
browser ──TLS (cert + key owned by the node's Caddy)──▶ relay-server :443
                                                          │ peeks SNI only, splices raw bytes
                                                          ▼
                                     outbound mTLS tunnel (yamux), opened by relay-agent
                                                          ▼
                                                  local Caddy ──▶ workload
```

## What the relay can and cannot see

| Visible to the relay | Not visible to the relay |
|---|---|
| Client IP and port, SNI or Host, connection timing, byte counts | HTTPS request and response contents, cookies, tokens |
| Tenant and instance of each tunnel | Application TLS private keys (issued to and held by local Caddy) |

A compromised relay can drop or misroute connections. A misrouted TLS
connection fails the browser's certificate check, because the wrong instance
has no certificate for that hostname (`TestCompromisedRelayMisrouteFailsTLS`).

## Operating a relay

1. Point wildcard DNS `*.relay.example.net` and `tunnel.relay.example.net` at
   the relay host.
2. Run the relay:

   ```
   relay-server serve --data /var/lib/opendeploy-relay \
     --suffix relay.example.net --tunnel-name tunnel.relay.example.net
   ```

   It needs ports 443 and 80 (public), plus 8443 for tunnels. On first start
   it creates its CA and logs the CA fingerprint.
3. Enroll an instance:

   ```
   relay-server enroll --tenant acme --instance home-1
   ```

   This prints a one-time token of the form `odr1.<id>.<secret>.<ca-fingerprint>`.
   The token expires after `--ttl`, which defaults to 24h.

## Configuring a node

```yaml
ingress:
  mode: relay
  relay:
    server_addr: tunnel.relay.example.net:8443
    tenant_id: acme
    instance_id: home-1
    public_suffix: relay.example.net
    enroll_token_file: /etc/opendeploy/relay-token   # removed after enrollment is fine
```

The agent generates its own key, and the key never leaves the node. It pins
the relay CA using the fingerprint in the token, so a network attacker cannot
stand in for the relay during enrollment. The agent then receives a
certificate that lasts 24 hours and renews it over the live tunnel.

Generated hostnames become `<project>.home-1.relay.example.net`.

For custom domains:
- Claim the domain in the dashboard.
- Publish the `_opendeploy-challenge` TXT record it shows, and **keep it**.
  The relay re-checks that record with the domain's authoritative servers
  and withdraws the route if it disappears.
- Point the name with a CNAME to `home-1.relay.example.net`.

## Credential incidents

| Action | Effect |
|---|---|
| `relay-server revoke --instance home-1` | Live tunnels close within seconds and reconnects are refused |
| `relay-server enroll --tenant acme --instance home-1` | Issues a new token, i.e. a rotation. Once it is redeemed, every earlier certificate for the instance is rejected, including stolen copies |
| Enroll a new instance ID | A credential only authorizes its own instance's namespace, plus custom domains whose owner published a record naming that instance |

Every enrollment, tunnel authentication, route authorization or denial,
renewal and withdrawal is appended to the relay's own `audit.log`. Records
are hash-chained. Ship the log off-host.
