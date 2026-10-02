### VPNAPI

Checks an IP address against [VPNAPI.io](https://vpnapi.io/) to find out whether it is a **VPN**, **proxy**, **Tor exit node** or **relay**. It also returns location and network (ASN) information.

The API only accepts IP addresses. For `domain`, `fqdn` and `url` observables, the analyzer first resolves the host with DNS. It then checks each resulting IP, up to `max_resolved_ips`.

#### Requirements
You need a VPNAPI.io API key. The free tier allows 1,000 requests per day.

#### Configuration
- `key`: VPNAPI.io API key (required)
- `max_resolved_ips`: maximum number of resolved IPs to check for domain, FQDN and URL observables (default: 5)

#### Taxonomies
- `VPNAPI:Tor`: malicious
- `VPNAPI:VPN`, `VPNAPI:Proxy`, `VPNAPI:Relay`: suspicious
- `VPNAPI:Anonymizer="None"`: safe
- `VPNAPI:Country`, `VPNAPI:ASN`: info
