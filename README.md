# Agents OAuth2 JWT Bearer

A PartyServer mixin for adding OAuth 2.0 JWT Bearer Token authentication to your PartyServer applications, with Auth0 support.

It should work with:

- PartyKit: https://docs.partykit.io/guides/authentication/
- Cloudflare Agents: https://agents.cloudflare.com/

## Overview

This package provides a mixin that adds authentication functionality to a PartyServer server using [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068). It allows you to secure your PartyServer applications by validating access tokens from requests and connections, with built-in support for Auth0.

## Installation

```bash
npm install @auth0/auth0-cloudflare-agent-api
# or
yarn add @auth0/auth0-cloudflare-agent-api
# or
pnpm add @auth0/auth0-cloudflare-agent-api
```

## Usage

### Basic Example

```typescript
import { Server } from "partyserver";
import { WithAuth } from "@auth0/auth0-cloudflare-agent-api";

// Define your environment type
type MyEnv = {
  AUTH0_DOMAIN: string;
  AUTH0_AUDIENCE: string;
  // ... other environment variables
};

// Create your server class with authentication
class MyAuthenticatedServer extends WithAuth(Server<MyEnv>) {
  // Your server implementation
}

// Pass options as parameters to the mixin function
class MyAuthenticatedServer extends WithAuth(Server, {
  // Optional: make authentication optional
  authRequired: false,
  // Optional: provide a debug function
  debug: (message, ctx) => console.log(message, ctx),
}) {
  // Your server implementation
}

// Start the server
const server = new MyAuthenticatedServer({
  env: {
    AUTH0_DOMAIN: "your-tenant.auth0.com",
    AUTH0_AUDIENCE: "your-api-audience",
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
    if (claims?.sub !== expectedUserId) {
      return new Response("You are not welcome", { status: 401 });
    }
  }

  onRequest(req: Request) {
    // Get the token set from the request
    const tokenSet = this.getCredentials();

    // Get the Access Token claims from the token
    const claims = this.getClaims();

    // Now you can use the claims to identify the user
    console.log(`User ID: ${claims?.sub}`);

    // You can also require specific scopes for certain operations
    try {
      await this.requireAuth({ scopes: "read:data" });
      // The user has the required scope
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        return error.toResponse();
      }
      // Handle other errors
      return new Response("Unknown error", { status: 500 });
    }

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
    console.log(`Connected user: ${claims?.sub}`);

    // You can also require specific scopes for certain operations
    try {
      await this.requireAuth({ scopes: ["read:data", "write:data"] });
      // The user has both required scopes
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        return error.terminateConnection(connection);
      }
      // Handle other errors
      throw error;
    }
  }

  onMessage(connection: Connection, message: unknown) {
    // Get the token set from the connection
    const tokenSet = this.getCredentials();

    // Get the JWT claims from the token
    const claims = this.getClaims();

    // Use the claims in your message handling logic
    console.log(`Message from user: ${claims?.sub}`);

    // Process the message...
  }
}
```

## Authentication Flow

1. When a client makes a request or connection:

   - The mixin extracts the bearer token from the Authorization header or the `access_token` query parameter
   - It validates the token using Auth0's token verification API
   - It verifies the token's issuer and audience claims

2. If validation succeeds:

   - The request or connection proceeds
   - Token information is stored for the connection

3. If validation fails:
   - A 401 Unauthorized response is returned for HTTP requests
   - The connection attempt is rejected

## Configuration

The `WithAuth` mixin requires the following environment variables:

- `AUTH0_DOMAIN`: Your Auth0 tenant domain (e.g., "your-tenant.auth0.com")
- `AUTH0_AUDIENCE`: The audience for the JWT, typically your API identifier

You can also configure the mixin with options:

```typescript
WithAuth(Server, {
  // Make authentication optional (default: true)
  authRequired: false,
  // Optional debug function
  debug: (message, context) => console.log(message, context),
});
```

## API Reference

### `WithAuth(BaseClass, options?)`

A mixin factory function that adds authentication functionality to a PartyServer class.

**Parameters:**

- `BaseClass`: The base class to extend from. This should be a class that extends `Server`.
- `options`: Optional configuration object:
  - `authRequired`: Boolean indicating whether authentication is required (default: true)
  - `debug`: Function for debugging (default: noop)

**Returns:**

- A new class that extends the base class with authentication capabilities.

### Methods

#### `getCredentials(): TokenSet | undefined`

Gets the token set associated with the current context.

**Returns:**

- A `TokenSet` object containing:
  - `access_token`: The JWT bearer token
  - `id_token`: Optional ID token (from `x-id-token` header)
  - `refresh_token`: Optional refresh token (from `x-refresh-token` header)

#### `getClaims(): Token | undefined`

Gets the decoded JWT claims from the access token.

**Returns:**

- An object containing the JWT claims or undefined if no token is available

#### `requireAuth(options?: { scopes?: string | string[] }): Promise<TokenSet>`

Requires authentication with optional scope checking.

**Parameters:**

- `options`: Optional configuration object:
  - `scopes`: String or array of strings representing required scopes

**Returns:**

- A promise that resolves to the token set if authentication is successful

**Throws:**

- `UnauthorizedError`: If no valid token is present
- `InvalidTokenError`: If the token is invalid
- `InsufficientScopeError`: If the token doesn't have the required scopes

## Token Format

The mixin accepts tokens in the following formats:

1. Authorization header: `Authorization: Bearer <token>`
2. Query parameter: `?access_token=<token>`

## Advanced Usage: WithOwnership Mixin

### Overview

The `WithOwnership` mixin adds ownership capabilities to a PartyServer that already has authentication provided by the `WithAuth` mixin. This is particularly useful for scenarios where you need to restrict access to resources based on ownership, such as private chats or user-specific data.

### Key Features

- Owner-based access control for connections and requests
- Integration with Durable Objects for persistent ownership data
- Automatic rejection of non-owner access attempts

### Usage Example

```typescript
// Then add ownership with WithOwnership
class MyServer extends WithOwnership(WithAuth(Server<MyEnv>), {
  // Optional: provide a debug function
  debug: (message, ctx) => console.log(message, ctx),
}) {
  // Your server implementation

  // Optionally override authorization methods
  async onAuthorizedConnect(connection, ctx) {
    console.log("Owner connected:", this.getClaims()?.sub);
    // Handle authorized connection
  }

  async onAuthorizedRequest(req) {
    console.log("Owner made a request:", this.getClaims()?.sub);
    // Handle authorized request
  }
}
```

### Ownership Methods

#### `setOwner(owner: string, overwrite: boolean = false): Promise<void>`

Sets the owner of the object. By default, it will throw an error if the owner is already set to a different user unless `overwrite` is set to `true`.

**Parameters:**

- `owner`: The user ID (sub from JWT claims) to set as the owner
- `overwrite`: Optional boolean to allow overwriting an existing owner

**Example:**

```typescript
// When initializing a new chat or resource
async onCreate() {
  const claims = this.getClaims();
  if (claims?.sub) {
    await this.setOwner(claims.sub);
  }
}
```

#### `getOwner(): Promise<string | undefined>`

Gets the current owner of the object.

**Returns:**

- The user ID (sub) of the owner, or undefined if no owner is set

**Example:**

```typescript
async checkOwnership() {
  const owner = await this.getOwner();
  console.log(`This resource is owned by: ${owner}`);
}
```

### Authorization Flow

1. When a client makes a request or connection:

   - First, the authentication checks are performed by the `WithAuth` mixin
   - Then, the ownership check verifies if the authenticated user is the owner

2. If the ownership check succeeds:

   - The `onAuthorizedConnect` or `onAuthorizedRequest` method is called
   - The connection or request is allowed to proceed

3. If the ownership check fails:
   - For WebSocket connections: Connection is closed with code 1008 and message "This chat is not yours."
   - For HTTP requests: A 403 Forbidden response is returned with message "This chat is not yours."

### DurableObject Integration

The `WithOwnership` mixin is designed to work with Cloudflare DurableObjects for storing ownership data. The mixin uses the DurableObject's storage API to persist ownership information.

**Note:** If you're not using DurableObjects, you'll need to override the `setOwner` and `getOwner` methods to implement your own storage mechanism.

## References

- This project uses the Auth0 API Client to verify access tokens: [@auth0/auth0-api-js](https://github.com/auth0/auth0-api-js)
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
