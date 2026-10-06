### ProxyCheck

Checks an IP address against [proxycheck.io](https://proxycheck.io/) (API v3) to find out whether it is a **proxy**, **VPN**, **Tor exit node**, **scraper**, **compromised** or **hosting** address. It also returns a risk score, the VPN/proxy operator (when known), attack history, location and network (ASN) information.

The analyzer only checks IP addresses. For `domain`, `fqdn` and `url` observables, it first resolves the host with DNS. It then checks the resulting IPs, up to `max_resolved_ips`, in a single API request.

#### Requirements
An API key is optional. Without one, you can make 100 queries per day. A free registered key raises this to 1,000 per day.

#### Configuration
- `key`: proxycheck.io API key (optional)
- `max_resolved_ips`: maximum number of resolved IPs to check for domain, FQDN and URL observables (default: 5)

#### Taxonomies
- `ProxyCheck:Tor`, `ProxyCheck:Compromised`: malicious
- `ProxyCheck:Proxy`, `ProxyCheck:VPN`, `ProxyCheck:Scraper`: suspicious
- `ProxyCheck:Hosting`: info
- `ProxyCheck:Anonymizer="None"`: safe
- `ProxyCheck:Risk`: the highest risk score across the checked IPs. 0-25 is safe, 26-50 info, 51-75 suspicious and 76-100 malicious
- `ProxyCheck:Country`, `ProxyCheck:ASN`: info
- `ProxyCheck:Found="False"`: info, when proxycheck.io returned no data for any checked IP
