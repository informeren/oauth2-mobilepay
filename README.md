# MobilePay Provider for OAuth 2.0 Client

[![Build Status](https://travis-ci.com/informeren/oauth2-mobilepay.svg?branch=develop)](https://travis-ci.com/informeren/oauth2-mobilepay)

This package provides MobilePay OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

This package is compliant with [PSR-1][], [PSR-4][] and [PSR-12][]. If you notice compliance oversights, please send a patch via pull request.

[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md
[PSR-12]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-12-extended-coding-style-guide.md

## Requirements

The following versions of PHP are supported.

* PHP 7.3
* PHP 7.4

## Install

Use composer to install the package:

```sh
$ composer require informeren/oauth2-mobilepay
```

## Usage

```php
$provider = new MobilePay([
    'clientId' => 'examplecompany',
    'clientSecret' => 'yxWIQHKjeEXW1ayL7kV77mh9YInAZNmSjJGuOrG69GE',
    'discoveryUri' => 'https://www.example.com/discovery',
    'redirectUri' => 'https://www.example.com/redirect',
]);
```

The `clientId` and `clientSecret` values are provided by MobilePay. The rest of the values are provided by you.

### Create authorization URL

```php
$url = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'subscriptions', 'offline_access'],
    'response_type' => 'code id_token',
    'response_mode' => 'fragment',
    'code_verifier' => 'MVLkNAsW0uy5PnH3L3YwUzXqcPzMfNeKPIfD4K32MN4',
    'merchant_vat' => 'DK12345678',
]);
```

After the first request, you must use the same `code_verifier` value for all subsequent authorization requests, so store it in a safe place.

Open the resulting URL in a browser and accept the request. You will be redirected to the `redirectUri` and the authorization code will be available in the `code` URL parameter.

### Use authorization code to get access token

```php
$token = $provider->getAccessToken('authorization_code', [
    'code' => 'gDnCpS1n2tUB4D428D2v4Daw77mKm66N2xekzEBSmKzeDspdUfrNnCTFWuZ2Ly9F',
    'code_verifier' => 'MVLkNAsW0uy5PnH3L3YwUzXqcPzMfNeKPIfD4K32MN4',
]);
```

### Refresh access token

```php
$token = $provider->getAccessToken('refresh_token', [
    'refresh_token' => 'NDAwxVTnsE5KlHf4ganujXfG3EAAJkj0DquVuxXxZk6c4G1G0tIX8vQ40Jzxaq0j',
]);
```

### Command-line interface

The package includes a simple command-line interface to the most common operations. Run it without arguments for usage instructions.

Use the following command to generate an authorization URL and open it in your default browser. 

```sh
$ ./vendor/bin/mobilepay-auth authorize | xargs open
```

## Testing

Tests can be run with:

```sh
$ composer test
```

Static analysis can be run with:

```sh
$ composer analyze
```
Style checks can be run with:

```sh
$ composer check
```

## Documentation

- [MobilePay Subscriptions](https://developer.mobilepay.dk/subscriptions-main)
- [MobilePay OpenID Connect](https://developer.mobilepay.dk/developersupport/openid/)
- [MobilePay Subscriptions API](https://mobilepaydev.github.io/MobilePay-Subscriptions/index)

## License

The MIT License (MIT). Please see [License File](https://github.com/informeren/oauth2-mobilepay/blob/master/LICENSE) for more information.
