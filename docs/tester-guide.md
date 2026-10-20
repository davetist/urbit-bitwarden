# Try Connect + Urbitwarden

Use your own ship and vault. Start with disposable records; keep your existing password manager.

## Connect

1. [Install both desks](install.md) and open **Urbitwarden** in Landscape over trusted HTTPS. Sign in to your ship.
2. Enroll once with an email and a strong **local vault password**. Keep that password separately: ship access cannot recover it.
3. In a current official Bitwarden client, select **Self-hosted** and enter `https://YOUR-HOST/apps/urbitwarden`.
4. Enter the enrolled email, choose **Single sign-on / Enterprise SSO**, and use organization **`urbit-vault`**. Approve in Connect, then unlock locally with your vault password.

Your ship login and vault password serve different purposes. Adding another client does not require enrolling again.

## Try a few things

- Create a login, edit it, and read it in a second client. Use **Sync now** to fetch another client's changes immediately.
- Trash and restore the item. Restart a client and unlock again.
- In **Connect**, revoke that client's session. Its next server sync should fail; sign in through SSO again. Revocation cannot erase a client's cached vault.

This alpha supports personal vaults. Shared vaults, Sends and a browser web vault are outside its scope. [Client coverage](client-support.md) · [Known limitations](known-limitations.md) · [Backup and recovery](backup.md).

When reporting a problem, include client/OS versions, the action, and what happened. Redact server identities and personal details. Never include passwords, ship codes, tokens, vault exports or unredacted logs.
