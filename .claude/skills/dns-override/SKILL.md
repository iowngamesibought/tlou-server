---
name: dns-override
description: Points the host names the console contacts at the server through a DNS override without breaking those names for other devices. Covers where to put the override, scoping it to the console, and proxy or fake-IP exemptions. Use once AGENTS.md has given the names to override (see AGENTS.md).
---

# Point the console's host names at the server

The console reaches the server only through DNS: the host names it contacts have to resolve to the server's address. This guide sets that up. It is the same in every project that uses it; AGENTS.md has the project's specifics: which names to override, which of them other devices rely on, and the checks to run afterwards.

Change DNS, router or firewall settings only with the user's agreement. Never write the host names into the repository: they go into the user's DNS setup only.

## 1. Collect the inputs

From AGENTS.md and the user:

- **The names to override**, and for each one whether other devices or services rely on it too, for example a cloud provider's main domain. AGENTS.md says which.
- **The server's address**: its LAN address as the console sees it (the address AGENTS.md has the user set in the config).
- **The console's DNS server today**: usually the router, handed out by DHCP. Ask whether the user can change the router's DNS settings.
- **Proxies:** whether a proxy or a TUN with fake-IP runs on the network, often on the router (step 4).

## 2. Write the override

Map every name to the server's address. With dnsmasq (on the router, e.g. OpenWrt, or on a machine of its own), one line per name:

```
address=/<host name>/<server address>
```

dnsmasq's `address=` also matches every subdomain: overriding `example.com` also sends `a.example.com` to the server. Overriding a provider's main domain therefore sends every name under it to the server.

Other options: the router's own static-host or local-DNS setting, or another local DNS server with per-name records. Check whether it matches subdomains too, and keep that in mind for step 3.

## 3. Scope it: the whole network or the console only

- **A name only the game uses** can be overridden on the network's DNS server (usually the router). Other devices then resolve it to the server too, which does no harm.
- **A name other devices rely on** (or a name whose override also catches such names, see step 2) must be overridden **for the console only**. Changing it for the whole network would cut every other device off from that service. Run a small DNS forwarder for the console alone, for example dnsmasq on the server machine, holding the override lines and passing everything else to the network's usual DNS server:
  ```
  listen-address=<server address>
  no-resolv
  server=<the network's usual DNS server>
  address=/<host name>/<server address>
  ```
  On Windows, use any local DNS server that supports per-name records and forwarding. Allow inbound DNS (UDP and TCP port 53) from the console on that machine.

The console has to use the DNS server that holds the override:
- **Network-wide:** through DHCP, as usual.
- **Console only:** set manually in the console's network settings, as both the primary and the secondary DNS server. A secondary pointing elsewhere can answer without the override.

## 4. Proxies and fake-IP

A proxy or TUN with fake-IP between the console and the internet answers DNS itself with addresses of its own, so the override never reaches the console. Add every overridden name to its fake-IP filter (the exclusion list), and route those names DIRECT.

Some routers redirect all DNS traffic to themselves, which overrides the console's manual setting. Then put the override on the router, or exempt the console from the redirect.

## 5. Check

Run the checks AGENTS.md lists. Query the console's DNS server explicitly: the machine you run them on may use a different resolver.

## Troubleshooting: no request reaches the server

Work through these in order; AGENTS.md says which name the console contacts first and on which port.

1. **DNS:** `nslookup <host name> <console's DNS server>`. If it doesn't return the server's address, the override isn't on the DNS server the console uses: check the console's primary and secondary DNS settings, and whether the router redirects DNS traffic (step 4).
2. **Proxy:** if the name resolves correctly but nothing arrives, a proxy or fake-IP may still take the connection: check its exemptions (step 4).
3. **Firewall:** if neither applies, the server machine's firewall probably blocks the port: allow it from the local network.
