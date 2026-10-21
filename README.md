# LAPSv2 decryptor

Decrypts Windows LAPS v2 `msLAPS-EncryptedPassword` values. It reads the encrypted value from LDAP, requests the key material from MS-GKDI over RPC, then decrypts the password locally.

## Install

Use Python 3.10 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The target must be reachable over LDAP and MS-GKDI RPC. MS-GKDI uses the RPC endpoint mapper and a dynamic RPC port.

## Run

The tool prompts for a password if `-p` is omitted.

```bash
python lapsv2_decryptor.py \
  -dc-ip 10.10.10.5 \
  -dc-host dc01.example.local \
  -d example.local \
  -u alice \
  -k \
  -target-computer WS01$
```

For a Kerberos ticket already in the credential cache:

```bash
KRB5CCNAME=/path/to/ticket.ccache python lapsv2_decryptor.py \
  -dc-ip 10.10.10.5 \
  -dc-host dc01.example.local \
  -d example.local \
  -u alice \
  -k -no-pass \
  -target-computer WS01$
```

Without `-k`, the tool uses NTLM. `-base-dn` is optional; when omitted, the base DN is built from `-d`.

The default output shows the target, local account, and password. Use `--json` for machine-readable output. `-debug` prints protocol details and key material; keep that output private.

## Notes

This tool handles encrypted Windows LAPS v2 values. It does not retrieve a password when the account lacks permission to read the encrypted attribute or obtain the required key material.
