# Agents OAuth2 JWT Bearer

A PartyServer mixin for adding OAuth 2.0 JWT Bearer Token authentication to your PartyServer applications.

It should work with:

- PartyKit: https://docs.partykit.io/guides/authentication/
- Cloudflare Agents: https://agents.cloudflare.com/

## Overview

This package provides a mixin that adds authentication functionality to a PartyServer server using [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068). It allows you to secure your PartyServer applications by validating access tokens from requests and connections.

## Installation

```bash
npm install agents-oauth2-jwt-bearer
# or
yarn add agents-oauth2-jwt-bearer
# or
pnpm add agents-oauth2-jwt-bearer
```

## Usage

### Basic Example

```typescript
import { Server } from "partyserver";
import { WithAuth } from "agents-oauth2-jwt-bearer";

// Define your environment type
type MyEnv = {
  OIDC_ISSUER_URL: string;
  OIDC_AUDIENCE: string;
  // ... other environment variables
};

// Create your server class with authentication
class MyAuthenticatedServer extends WithAuth(Server<MyEnv>) {
  // Your server implementation
}

// Pass verify options as parameters to the mixin function
class MyAuthenticatedServer extends WithAuth(Server, {
  // Optional: specify the audience and issuer, etc
  verify: verifyOptions,
  // Optional: allow unauthenticated requests and connections
  authRequired: false,
}) {
  // Your server implementation
}

// Start the server
const server = new MyAuthenticatedServer({
  env: {
    OIDC_ISSUER_URL: "https://your-identity-provider.com",
    OIDC_AUDIENCE: "your-api-audience",
    // ... other environment variables
  },
});

server.start();
```

### Accessing User Info

Once you've added the mixin, you can access token information and claims:

```typescript
class MyAuthenticatedServer extends WithAuth(Server<MyEnv>) {
  //optionally override onAuthenticatedRequest
  onAuthenticatedRequest(req: Request) {
    // Get the JWT claims from the token
    const claims = this.getClaims();
    if (claims.sub !== expectedUserId) {
      return new Response("You are not welcome", { status: 401 });
    }
  }

  onRequest(req: Request) {
    // Get the token set from the request
    const tokenSet = this.getCredentials();

    // Get the Access Token claims from the token
    const claims = this.getClaims();

    // Now you can use the claims to identify the user
    console.log(`User ID: ${claims.sub}`);

    // Continue processing the request...
    return new Response("Hello authenticated user!");
  }

  //optionally override onAuthenticatedConnect
  onAuthenticatedConnect(connection: Connection, ctx: ConnectionContext) {
    // Get the JWT claims from the token
    const claims = this.getClaims();
    if (claims.sub !== expectedUserId) {
      connection.close(1008, "I don't like you");
    }
  }

  onConnect(connection: Connection, ctx: ConnectionContext) {
    // Get the token set from the connection
    const tokenSet = this.getCredentials();

    // Get the JWT claims from the token
    const claims = this.getClaims();

    // Use the claims in your connection handling logic
    console.log(`Connected user: ${claims.sub}`);
  }

  onMessage(connection: Connection, message: unknown) {
    // Get the token set from the connection
    const tokenSet = this.getCredentials();

    // Get the JWT claims from the token
    const claims = this.getClaims();

    // Use the claims in your message handling logic
    console.log(`Message from user: ${claims.sub}`);

    // Process the message...
  }
}
```

## Authentication Flow

1. When a client makes a request or connection:

   - The mixin extracts the bearer token from the Authorization header or the `access_token` query parameter
   - It validates the token using the JWKS from your identity provider
   - It verifies the token's issuer and audience

2. If validation succeeds:

   - The request or connection proceeds
   - Token information is stored for the connection

3. If validation fails:
   - A 401 Unauthorized response is returned for HTTP requests
   - The connection attempt is rejected

## Configuration

The `WithAuth` mixin requires the following environment variables:

- `OIDC_ISSUER_URL`: The URL of the OpenID Connect issuer (your identity provider)
- `OIDC_AUDIENCE`: The audience for the JWT, typically your API identifier

## API Reference

### `WithAuth(BaseClass)`

A mixin factory function that adds authentication functionality to a PartyServer class.

**Parameters:**

- `BaseClass`: The base class to extend from. This should be a class that extends `Server`.

**Returns:**

- A new class that extends the base class with authentication capabilities.

### Methods

#### `getCredentials(): TokenSet | void`

Gets the token set associated with the current context.

**Returns:**

- A `TokenSet` object containing:
  - `access_token`: The JWT bearer token
  - `id_token`: Optional ID token (from `x-id-token` header)
  - `refresh_token`: Optional refresh token (from `x-refresh-token` header)

#### `getClaims(reqOrConnection: Request | Connection): Record<string, unknown>`

Gets the decoded JWT claims from the access token.

**Returns:**

- An object containing the JWT claims

## Token Format

The mixin accepts tokens in the following formats:

1. Authorization header: `Authorization: Bearer <token>`
2. Query parameter: `?access_token=<token>`

## References

- This project is similar to other Auth0 middlewares like [node-oauth2-jwt-bearer](https://github.com/auth0/node-oauth2-jwt-bearer).
- [Authentication on PartyKit](https://docs.partykit.io/guides/authentication/).

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0-lab/agents-oauth2-jwt-bearer/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png"   width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">
This project is licensed under the Apache 2.0 license. See the <a href="/LICENSE"> LICENSE</a> file for more info.</p>
