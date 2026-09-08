# OpenID Connect login for Mautic

A Mautic 7 plugin that signs users in through any OpenID Connect provider — such as an app running
[`bambamboole/laravel-oidc`](https://github.com/bambamboole/laravel-oidc) — and decides who may enter by
looking at the claims the provider returns.

- Authorization code flow with PKCE, `state`, and `nonce`; endpoints resolved from the issuer's discovery document.
- The ID token's signature, issuer, audience, lifetime, and nonce are verified before the userinfo response is trusted.
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

## API access with provider tokens

A Bearer access token issued by the provider can call the Mautic API once it passes the same signature
and issuer checks as the ID token. Configure this under **Settings → Configuration → OpenID Connect**:

- **API client IDs**: the OAuth clients whose tokens are accepted, one per line. Leave empty to disable.
- **API user email**: the Mautic user that tokens act as when they carry no user claim, for example
  tokens from a `client_credentials` grant.
- **API user claim**: optional; a claim such as `email` naming the Mautic user a token acts as, so every
  call is audited under that person. A token carrying the claim must match an existing user.
- **API audience**: optional; when set, the token's `aud` claim must contain it.

Locally issued Mautic OAuth tokens keep working and take precedence.

## Security notes

- The issuer must be an `https://` URL; plain `http://` is tolerated on `localhost` only, for development.
  The discovery document must name the configured issuer.
- Every login verifies the `state` stored for that browser session and the `nonce` echoed in the ID token,
  then consumes both, so a callback cannot be replayed or injected into a session that started no login.
- ID and access tokens must be signed with RS256 by a key from the provider's JWKS; `iss`, `exp`, `nbf`,
  and `iat` are checked with 60 seconds of leeway. The `sub` claim of the userinfo response must match
  the ID token before any claim from it is used.
- JWKS and discovery documents are cached for an hour. A token signed with an unknown key ID triggers one
  fresh JWKS fetch, at most once per minute, so a key rotation takes effect immediately.
- Rejected logins name the unmet required claims in the error message. This helps administrators debug
  their configuration but also tells a rejected user which claims would have granted access.

## Notes

- Mautic requires a first and last name: when the provider sends neither `given_name`/`family_name`
  nor a `name` claim, the local part of the username is used for both.
