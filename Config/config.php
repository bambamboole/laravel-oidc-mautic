<?php

declare(strict_types=1);

return [
    'name' => 'OpenID Connect Login',
    'description' => 'Signs users in through an OpenID Connect provider and restricts access by claims.',
    'version' => '0.21.2', // x-release-please-version
    'author' => 'Manuel Christlieb',
    'parameters' => [
        'oidc_scopes' => 'openid profile email',
        'oidc_username_claim' => 'email',
        'oidc_email_claim' => 'email',
        'oidc_first_name_claim' => 'given_name',
        'oidc_last_name_claim' => 'family_name',
        'oidc_timezone_claim' => 'zoneinfo',
        'oidc_locale_claim' => 'locale',
        'oidc_required_claims' => [],
        'oidc_role_claim' => null,
        'oidc_role_mapping' => [],
        'oidc_api_user_email' => null,
        'oidc_api_allowed_client_ids' => [],
        'oidc_api_audience' => null,
    ],
];
