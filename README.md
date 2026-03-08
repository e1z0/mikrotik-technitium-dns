# Info

RouterOS v7 DHCP lease-script for Technitium DNS synchronization.
Creates/removes forward A and reverse PTR records on lease bind/unbind.
Includes hostname sanitization, dynamic PTR zone detection, and API debug mode.

Required DHCP setup:
1. Create/import this script as: dhcp-to-technitium_v2
2. Attach it to DHCP server lease-script, e.g.:`/ip dhcp-server set [find where name="dhcp-servers"] lease-script="dhcp-to-technitium_v2"`
3. DHCP lease events must provide leaseBound, leaseActIP, leaseServerName variables.

Change these CONFIG values for your environment:
- debug        true/false for verbose API logging
- domain       forward DNS zone suffix used in FQDNs (example: lab01.domain.com)
- zone         Technitium forward zone (example: domain.com)
- dnsApiUrl    Technitium API base URL (example: https://dns.domain.com/api/zones/records)
- apiKey       Technitium API token
- DHCPtag      comment marker written to Technitium records
- leaseServerName->prefix mappings if your DHCP server names differ


[Read the article](https://e1z0.net/articles/miktotik-technitium)
