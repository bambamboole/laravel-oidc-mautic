# OpenID Connect login for Mautic

A Mautic 7 plugin that signs users in through any OpenID Connect provider — such as an app running
[`bambamboole/laravel-oidc`](https://github.com/bambamboole/laravel-oidc) — and decides who may enter by
looking at the claims the provider returns.

- Authorization code flow with PKCE and `state`, endpoints resolved from the issuer's discovery document.
- Users are matched by username (the `email` claim by default); optionally created on first login.
- **Required claims** gate every login: each configured `claim=value` line must match the userinfo response.
- **Role mapping** translates a provider role claim into a Mautic role; unmatched new users get the default role.

## Install

```bash
composer require bambamboole/laravel-oidc-mautic
php bin/console cache:clear
php bin/console mautic:plugins:reload
```

Without Composer, copy this directory to `docroot/plugins/LaravelOidcBundle` and run the same two commands.

## Configure

1. Register a **confidential** client at your provider with the redirect URI
   `https://<mautic-host>/s/sso_login_check/LaravelOidc`.
2. In Mautic go to **Settings → Plugins → OpenID Connect**, publish the plugin, and enter the issuer URL
   (the one that serves `/.well-known/openid-configuration`), client ID, and client secret. Under *Features*,
   choose whether unknown users are created automatically and which role they receive.
3. In **Settings → Configuration → OpenID Connect**, adjust scopes, claim-to-field mapping, the required
   claims, and the role mapping.

The login page then shows a **Sign in with OpenID Connect** button next to the password form.

### Required claims

One rule per line; all rules must hold. A claim name may use dots to reach nested values.

```text
roles=Super Admin      # list claims match when they contain the value
email_verified         # a bare claim requires the boolean true
hd=example.com         # scalar claims must be equal
```

Users whose claims do not satisfy every rule are rejected with a message naming the unmet rules, even
when they already exist in Mautic.

### Role mapping

Set the role claim (for example `roles`) and map its values to Mautic role IDs:

```text
Super Admin => 1
Support => 2
```

The first matching line wins. Existing users keep their role when nothing matches.

## Notes

- The plugin trusts the userinfo endpoint reached with the freshly issued access token over TLS; it does
  not validate the ID token signature itself.
- Mautic requires a first and last name: when the provider sends neither `given_name`/`family_name`
  nor a `name` claim, the local part of the username is used for both.
