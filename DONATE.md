# Supporting Threat Meister

Threat Meister is free and MIT-licensed, and it will stay that way. If it's been
useful to you and you'd like to support its development, there are two options
below. Neither is expected.

## GitHub Sponsors

The easiest route is the **Sponsor** button at the top of the
[repository page](https://github.com/MEISTSEC/threat_meister), which goes through
GitHub Sponsors.

## Buy Me a Coffee

One-off support, no account needed:
[buymeacoffee.com/meistsec](https://buymeacoffee.com/meistsec)

## Bitcoin

```
bc1qjeyphyc6ypnmkjclup2c3yjjts2ljn6grsqm2y
```

### Verify this address before sending anything

**Do not trust an address you read in a README — including this one — without
verifying it.** Anyone can open a pull request that swaps an address, and
donation-address tampering is a well-known attack on open-source projects.

This address is cryptographically signed with the key that controls it. You can
confirm it is genuinely the project's address, and has not been altered, by
verifying the signature below.

**Message** (must match *exactly*, including line breaks):

```
Threat Meister (github.com/MEISTSEC/threat_meister) donation address: bc1qjeyphyc6ypnmkjclup2c3yjjts2ljn6grsqm2y
Signed by meistsec, 2026-07-13.
```

**Signature:**

```
IEYwOoBnl6Ngk8jQ21YqevIAxVR0sVHthuVIxFEr5KJHVUIww1TBISQeMpV+y8cNluRu6FcD1RkuOU3PRcsc0Fs=
```

**To verify**, save the message above to a file, then check the signature against
the address. Any wallet with message verification works; the two most common:

**Electrum (CLI):**

```bash
cat > /tmp/tm_donate_msg.txt <<'EOF'
Threat Meister (github.com/MEISTSEC/threat_meister) donation address: bc1qjeyphyc6ypnmkjclup2c3yjjts2ljn6grsqm2y
Signed by meistsec, 2026-07-13.
EOF

electrum verifymessage \
  "bc1qjeyphyc6ypnmkjclup2c3yjjts2ljn6grsqm2y" \
  "IEYwOoBnl6Ngk8jQ21YqevIAxVR0sVHthuVIxFEr5KJHVUIww1TBISQeMpV+y8cNluRu6FcD1RkuOU3PRcsc0Fs=" \
  "$(cat /tmp/tm_donate_msg.txt)"
```

It prints `true` if the signature is valid.

**Electrum (GUI):** Tools → Sign/Verify Message, paste the address, message, and
signature into their fields, and click **Verify**.

**Bitcoin Core:**

```bash
bitcoin-cli verifymessage "bc1qjeyphyc6ypnmkjclup2c3yjjts2ljn6grsqm2y" "IEYwOoBnl6Ngk8jQ21YqevIAxVR0sVHthuVIxFEr5KJHVUIww1TBISQeMpV+y8cNluRu6FcD1RkuOU3PRcsc0Fs=" \
  "$(cat /tmp/tm_donate_msg.txt)"
```

A valid signature proves the address belongs to whoever holds the corresponding
private key. If verification returns `false` or errors, **do not send anything** —
the address may have been tampered with. Please open an issue if that happens.

> The message must match **byte for byte**, including the line break and the
> trailing period. A copied-in smart quote or an extra blank line will make a
> genuine signature fail to verify.

### Notes

- Donations are voluntary and non-refundable, and buy no influence over the
  project's direction, no support obligation, and no warranty (see `LICENSE`).
- This address is checked periodically, not continuously.
