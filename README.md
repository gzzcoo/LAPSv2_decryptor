# LAPSv2 decryptor

Decrypts Windows LAPS v2 `msLAPS-EncryptedPassword` values. It reads the encrypted value from LDAP, requests key material from MS-GKDI over RPC, and decrypts the record locally.

## Install

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

The domain controller must be reachable over LDAP and MS-GKDI RPC (TCP 135 and the configured dynamic RPC port).

## Authentication

If `-p` is omitted, the tool prompts for the password. The examples use `-p 'your-password'` to make the credential mode explicit; replace the placeholder or omit `-p` and enter it at the prompt.

The NTLM examples require the domain controller to accept NTLM binds. Some domains disable NTLM; use one of the Kerberos modes in that case.

### NTLM with a password

```bash
python3 LAPSv2_decryptor.py -dc-ip $DC_IP -d $DOMAIN \
  -u 'user' -p 'password' -target-computer "COMPUTERNAME$"
```

### NTLM pass-the-hash

Use `LMHASH:NTHASH`. Leave the LM hash empty with a leading colon when you only have the NT hash.

```bash
python3 LAPSv2_decryptor.py -dc-ip $DC_IP -d $DOMAIN \
  -u 'user' -hashes ':613a519b5b0ef57c07bc6395aa1aff14' -target-computer "COMPUTERNAME$"
```

### Kerberos with a password

`-dc-host` supplies the DC hostname used for Kerberos service names.

```bash
python3 LAPSv2_decryptor.py -dc-ip $DC_IP -dc-host $DC_HOST \
  -d $DOMAIN -u 'user' -p 'password' -k \
  -target-computer "COMPUTERNAME$"
```

### Kerberos with an NTLM hash

```bash
python3 LAPSv2_decryptor.py -dc-ip $DC_IP -dc-host $DC_HOST \
  -d $DOMAIN -u 'user' -hashes ':613a519b5b0ef57c07bc6395aa1aff14' -k \
  -target-computer "COMPUTERNAME$"
```

### Kerberos with a credential cache

Point `KRB5CCNAME` to a valid ticket cache and use `-no-pass` to prevent a password prompt.

```bash
export KRB5CCNAME=user.ccache
python3 LAPSv2_decryptor.py -dc-ip $DC_IP -dc-host $DC_HOST \
  -d $DOMAIN -u 'user' -k -no-pass \
  -target-computer "COMPUTERNAME$"
```

## Output

The default output shows the computer, local account, and password. Add `--json` for machine-readable output. `-debug` prints protocol details and key material; keep that output private.

`--include-history` also decrypts values from `msLAPS-EncryptedPasswordHistory`.

`-base-dn` is optional. When omitted, the base DN is built from `-d`.
