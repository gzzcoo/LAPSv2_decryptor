# LAPSv2 decryptor

Decrypts Windows LAPS v2 `msLAPS-EncryptedPassword` values. It reads the encrypted value from LDAP, requests key material from MS-GKDI over RPC, and decrypts the record locally.

## Install

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The domain controller must be reachable over LDAP and MS-GKDI RPC (TCP 135 and the configured dynamic RPC port).

Set the target details used in the examples:

```bash
DC_IP='10.10.10.5'
DC_HOST='dc01.example.local'
DOMAIN='example.local'
AD_USER='alice'
COMPUTER='WS01$'
```

## Authentication

If `-p` is omitted, the tool prompts for the password. The examples use `-p 'your-password'` to make the credential mode explicit; replace the placeholder or omit `-p` and enter it at the prompt.

The NTLM examples require the domain controller to accept NTLM binds. Some domains disable NTLM; use one of the Kerberos modes in that case.

### NTLM with a password

```bash
python lapsv2_decryptor.py -dc-ip "$DC_IP" -d "$DOMAIN" \
  -u "$AD_USER" -p 'your-password' -target-computer "$COMPUTER"
```

### NTLM pass-the-hash

Use `LMHASH:NTHASH`. Leave the LM hash empty with a leading colon when you only have the NT hash.

```bash
python lapsv2_decryptor.py -dc-ip "$DC_IP" -d "$DOMAIN" \
  -u "$AD_USER" -hashes ':0123456789abcdef0123456789abcdef' \
  -target-computer "$COMPUTER"
```

### Kerberos with a password

`-dc-host` supplies the DC hostname used for Kerberos service names.

```bash
python lapsv2_decryptor.py -dc-ip "$DC_IP" -dc-host "$DC_HOST" \
  -d "$DOMAIN" -u "$AD_USER" -p 'your-password' -k \
  -target-computer "$COMPUTER"
```

### Kerberos with an NTLM hash

```bash
python lapsv2_decryptor.py -dc-ip "$DC_IP" -dc-host "$DC_HOST" \
  -d "$DOMAIN" -u "$AD_USER" -hashes ':0123456789abcdef0123456789abcdef' -k \
  -target-computer "$COMPUTER"
```

### Kerberos with a credential cache

Point `KRB5CCNAME` to a valid ticket cache and use `-no-pass` to prevent a password prompt.

```bash
export KRB5CCNAME="$PWD/alice.ccache"
python lapsv2_decryptor.py -dc-ip "$DC_IP" -dc-host "$DC_HOST" \
  -d "$DOMAIN" -u "$AD_USER" -k -no-pass \
  -target-computer "$COMPUTER"
```

## Output

The default output shows the computer, local account, and password. Add `--json` for machine-readable output. `-debug` prints protocol details and key material; keep that output private.

`-base-dn` is optional. When omitted, the base DN is built from `-d`.
