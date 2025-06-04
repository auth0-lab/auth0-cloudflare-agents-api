/* eslint-disable @typescript-eslint/no-explicit-any */
import { ApiClient as Auth0APIClient } from "@auth0/auth0-api-js";
import { AsyncLocalStorage } from "node:async_hooks";
import { Connection, ConnectionContext, Server, WSMessage } from "partyserver";
import {
  InsufficientScopeError,
  InvalidTokenError,
  UnauthorizedError,
} from "./bearer/errors.js";
import getToken from "./bearer/index.js";
import {
  AuthenticatedServer,
  Constructor,
  TokenSet,
  WithAuthParams,
} from "./types.js";

export interface Token {
  sub?: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
  [key: string]: any;
}

interface RequireAuthOptions {
  scopes?: string | string[];
}

function validateScopes(
  token: Token,
  requiredScopes: string | string[],
): boolean {
  const scopes = Array.isArray(requiredScopes)
    ? requiredScopes
    : [requiredScopes];

  // Extract token scopes (handling different formats)
  let tokenScopes: string[] = [];

  if (token.scope) {
    tokenScopes =
      typeof token.scope === "string" ? token.scope.split(" ") : token.scope;
  }

  // All required scopes must be present
  return scopes.every((required) => tokenScopes.includes(required));
}

/**
 *
 * Mixin to add authentication functionality to a PartyServer server using
 * JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens.
 *
 * The configuration Env should contain the following properties:
 * - `OIDC_ISSUER_URL`: The URL of the OpenID Connect issuer.
 * - `OIDC_AUDIENCE`: The audience for the JWT.
 *
 * @param Base - The base class to extend from. This should be a class that extends `Server`.
 * @returns - A new class that extends the base class and adds authentication functionality.
 */
export const WithAuth = <
  Env extends { AUTH0_DOMAIN: string; AUTH0_AUDIENCE: string },
  TBase extends Constructor<Server<Env>>,
>(
  Base: TBase,
  options: WithAuthParams = { authRequired: true },
) => {
  const authRequired = options.authRequired ?? true;
  const debug = options.debug ?? (() => {});
  // I had to do this because:
  // a- It seems miniflare keep recreating the server instance
  // b- connections have same properties (like id) but are different instances.
  const tokenSetPerConnection = new Map<string, TokenSet>();
  const decodedToken = new Map<string, Token>();

  return class extends Base implements AuthenticatedServer {
    #env: Env;
    #asyncTokenStorage = new AsyncLocalStorage<TokenSet>();
    #auth0APIClient: Auth0APIClient;

    constructor(...args: any[]) {
      super(...args);
      this.#env = args[args.length - 1] as Env;
      this.#auth0APIClient = new Auth0APIClient({
        domain: this.#env.AUTH0_DOMAIN,
        audience: this.#env.AUTH0_AUDIENCE,
      });
    }

    /**
     * Get the decoded claims from the current request or connection.
     *
     * Note that if the mixin is configured with `authRequired: false`,
     * you need to call `requireAuth()` before calling this method.
     *
     * @returns - The decoded claims from the current request or connection.
     */
    getClaims(): Token | undefined {
      const tokenSet = this.#asyncTokenStorage.getStore();
      if (!tokenSet) {
        return;
      }
      return decodedToken.get(tokenSet.access_token);
    }

    /**
     * Get the current credentials for the current request or connection.
     *
     * This method will return the tokenset from the headers.
     *
     * It can be called before actual validation of the tokens.
     *
     * @returns - The credentials for the current request or connection.
     */
    getCredentials(): TokenSet | undefined {
      return this.#asyncTokenStorage.getStore();
    }

    /**
     * Get the credentials for a specific connection.
     * This method can be used outside of the request/connection context.
     * You shouldn't need to use this method in most cases, instead use getCredentials().
     * @param connection - The connection to get the credentials for.
     * @returns - The credentials for the connection.
     */
    getCredentialsFromConnection(connection: Connection): TokenSet | undefined {
      return tokenSetPerConnection.get(connection.id);
    }

    #getTokenSetFromRequest(req: Request): TokenSet {
      const url = new URL(req.url);
      const token = getToken(req.headers, url.searchParams);
      const tokenSet = {
        access_token: token,
        id_token: req.headers.get("x-id-token") ?? undefined,
        refresh_token: req.headers.get("x-refresh-token") ?? undefined,
      };
      return tokenSet;
    }

    async #validateTokenFromRequest(req: Request): Promise<TokenSet> {
      const tokenSet = this.#getTokenSetFromRequest(req);
      try {
        const payload = await this.#auth0APIClient.verifyAccessToken({
          accessToken: tokenSet.access_token,
        });
        decodedToken.set(tokenSet.access_token, payload as Token);
      } catch (err) {
        throw new InvalidTokenError(
          err instanceof Error ? err.message : "Invalid Token",
        );
      }
      return tokenSet;
    }

    /**
     *
     * Require authentication for the current request or connection.
     *
     * This method will validate the access token and check the required scopes.
     *
     * It can be called in any of the following methods:
     * - onConnect() to authenticate a WebSocket connection.
     * - onRequest() to authenticate an HTTP request.
     * - onMessage() to authenticate for a particular WebSocket message.
     *
     * @param opts - Options for the authentication check.
     * @param opts.scopes - The scopes required for the request.
     * @returns - A promise that resolves to the token set if the authentication is successful.
     * @throws UnauthorizedError - If the access token is missing or invalid.
     * @throws InsufficientScopeError - If the access token does not have the required scopes.
     * @throws InvalidTokenError - If the access token is invalid.
     */
    async requireAuth(opts: RequireAuthOptions = {}) {
      const tokenSet = this.#asyncTokenStorage.getStore();
      if (!tokenSet) {
        throw new UnauthorizedError();
      }
      let payload: Token | undefined;

      try {
        payload = await this.#auth0APIClient.verifyAccessToken({
          accessToken: tokenSet.access_token,
        });
        decodedToken.set(tokenSet.access_token, payload as Token);
      } catch (err) {
        throw new InvalidTokenError(
          err instanceof Error ? err.message : "Invalid Token",
        );
      }

      if (opts.scopes && !validateScopes(payload, opts.scopes)) {
        throw new InsufficientScopeError();
      }

      return tokenSet;
    }

    /**
     * Override this method to handle the request before authentication.
     * If the request returns a response, the super `onRequest` method
     * will not be called.
     *
     * @param req  - The request to handle.
     * @returns - Either undefined or a response.
     */
    async onRequest(req: Request) {
      try {
        const tokenSet = this.#getTokenSetFromRequest(req);
        if (options.authRequired) {
          await this.#validateTokenFromRequest(req);
          return this.#asyncTokenStorage.run(tokenSet, async () => {
            const authResponse = await this.onAuthenticatedRequest(req);
            return authResponse ?? super.onRequest(req);
          });
        } else {
          return this.#asyncTokenStorage.run(tokenSet, async () =>
            super.onRequest(req),
          );
        }
      } catch (err) {
        debug(err instanceof Error ? err.message : "Unknown error", {
          error: err,
          authRequired,
        });
        if (err instanceof UnauthorizedError) {
          return err.toResponse();
        }
        return new Response("Unauthorized", {
          status: 401,
          statusText: "Unauthorized",
        });
      }
    }

    override async onConnect(connection: Connection, ctx: ConnectionContext) {
      try {
        const tokenSet = this.#getTokenSetFromRequest(ctx.request);
        tokenSetPerConnection.set(connection.id, tokenSet);
        if (authRequired) {
          await this.#validateTokenFromRequest(ctx.request);
          return this.#asyncTokenStorage.run(tokenSet, async () => {
            await this.onAuthenticatedConnect(connection, ctx);
            if (connection.readyState === connection.OPEN) {
              await super.onConnect(connection, ctx);
            }
          });
        } else {
          return this.#asyncTokenStorage.run(tokenSet, () =>
            super.onConnect(connection, ctx),
          );
        }
      } catch (err) {
        debug(err instanceof Error ? err.message : "Unknown error", {
          error: err,
          authRequired,
        });
        if (err instanceof UnauthorizedError) {
          err.terminateConnection(connection);
          return;
        }
        connection.close(1008, "Unauthorized");
      }
    }

    override onMessage(
      connection: Connection,
      message: WSMessage,
    ): void | Promise<void> {
      const credentials = tokenSetPerConnection.get(connection.id);

      if (!credentials) {
        if (authRequired) {
          connection.close(1008, "Unauthorized");
          return;
        }
        return super.onMessage(connection, message);
      }

      return this.#asyncTokenStorage.run(credentials, () => {
        return super.onMessage(connection, message);
      });
    }

    /**
     * Override this method to handle authenticated connections.
     *
     * If the connection is closed in this method, the super `onConnect` method
     * will not be called.
     *
     * @param connection  - The connection that was authenticated.
     * @param ctx - The connection context.
     */
    async onAuthenticatedConnect(
      connection: Connection,
      ctx: ConnectionContext,
    ): Promise<void> {
      debug("Authenticated connection", {
        connection,
        ctx,
      });
    }

    /**
     *
     * Override this method to handle authenticated requests.
     *
     * If the request returns a response, the super `onRequest` method
     * will not be called.
     *
     * @param req  - The request that was authenticated.
     * @returns - Either undefined or a response.
     */
    async onAuthenticatedRequest(req: Request): Promise<void | Response> {
      debug("Authenticated request", {
        req,
      });
    }

    override onClose(
      connection: Connection,
      code: number,
      reason: string,
      wasClean: boolean,
    ): void | Promise<void> {
      const tokenSet = tokenSetPerConnection.get(connection.id);
      if (tokenSet) {
        decodedToken.delete(tokenSet.access_token);
      }
      tokenSetPerConnection.delete(connection.id);
      super.onClose(connection, code, reason, wasClean);
    }
  };
};

export { OwnedAgent, WithOwnership } from "./withOwnership.js";

/**
 * Alias for `WithAuth` to maintain backward compatibility.
 * This mixin adds authentication functionality to a PartyServer server using
 * JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens.
 */
export const AuthAgent = WithAuth;

export {
  InsufficientScopeError,
  InvalidRequestError,
  InvalidTokenError,
  UnauthorizedError,
} from "./bearer/errors.js";
