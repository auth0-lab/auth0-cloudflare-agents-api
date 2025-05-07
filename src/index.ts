import {
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
  JWTVerifyOptions,
} from "jose";
import { AsyncLocalStorage } from "node:async_hooks";
import { Connection, ConnectionContext, Server, WSMessage } from "partyserver";
import { UnauthorizedError } from "./bearer/errors.js";
import getToken from "./bearer/index.js";
import { UserInfo } from "./types.js";

type Constructor<T = {}> = new (...args: any[]) => T;

type TokenSet = {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_at?: number;
  scope?: string;
  token_type?: string;
};

type DiscoveryDocument = {
  userinfo_endpoint?: string;
  jwks_uri?: string;
};

type WithAuthParams = {
  /**
   * The options to pass to the JWT verification.
   */
  verify?: JWTVerifyOptions;

  /**
   * Whether to require authentication for all requests.
   * If set to false, unauthenticated requests will be allowed.
   *
   * Defaults to true.
   */
  authRequired?: boolean;

  /**
   * An optional logger function to log debug messages.
   *
   * @param message - The message to log.
   * @param content - An optional object containing additional content to log.
   */
  debug?: (message: string, content?: Record<string, unknown>) => void;
};

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
export const WithAuth = <Env, TBase extends Constructor<Server<Env>>>(
  Base: TBase,
  options: WithAuthParams = { verify: {}, authRequired: true },
) => {
  const authRequired = options.authRequired ?? true;
  const debug = options.debug ?? (() => {});

  return class extends Base {
    #tokenSetPerConnection = new WeakMap<Connection, TokenSet>();
    #asyncTokenStorage = new AsyncLocalStorage<TokenSet>();
    #userPerToken = new Map<string, UserInfo | undefined>();

    #remoteJWKSet: ReturnType<typeof createRemoteJWKSet> | undefined;
    #env: Env;
    #discoveryDocument: DiscoveryDocument | undefined;

    constructor(...args: any[]) {
      super(...args);
      this.#env = args[args.length - 1];
    }

    /**
     * Get the current credentials for the current request or connection.
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
      return this.#tokenSetPerConnection.get(connection);
    }

    /**
     * Get the claims from the access token.
     *
     * @param reqOrConnection  - The request or connection to get the claims for.
     * If not provided, it will use the current async local storage.
     *
     * @returns - The claims from the access token.
     */
    getClaims(): Record<string, unknown> | undefined {
      const credentials = this.getCredentials();
      return credentials && decodeJwt(credentials.access_token);
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

    async #getDiscoveryDocument(): Promise<DiscoveryDocument> {
      if (this.#discoveryDocument) {
        return this.#discoveryDocument;
      }
      const resp = await fetch(
        new URL(
          "/.well-known/openid-configuration",
          this.#verifyOptions.issuer as string,
        ),
      );
      if (!resp.ok) {
        throw new Error(
          `Failed to fetch OpenID configuration: ${resp.statusText}`,
        );
      }
      this.#discoveryDocument = (await resp.json()) as DiscoveryDocument;
      return this.#discoveryDocument;
    }

    get #verifyOptions(): JWTVerifyOptions {
      let result: JWTVerifyOptions = options.verify ?? {};
      if (typeof this.#env === "object" && this.#env !== null) {
        result = {
          issuer: this.#env.hasOwnProperty("OIDC_ISSUER_URL")
            ? ((this.#env as any)["OIDC_ISSUER_URL"] as string)
            : undefined,
          audience: this.#env.hasOwnProperty("OIDC_AUDIENCE")
            ? ((this.#env as any)["OIDC_AUDIENCE"] as string)
            : undefined,
          ...options.verify,
        };
      }
      if (!result.issuer) {
        throw new Error("OIDC_ISSUER_URL is not set in env");
      }
      if (!result.audience) {
        throw new Error("OIDC_AUDIENCE is not set in env");
      }
      return result;
    }

    async #getRemoteJWKSet(): Promise<ReturnType<typeof createRemoteJWKSet>> {
      if (!this.#remoteJWKSet) {
        const { jwks_uri } = await this.#getDiscoveryDocument();
        if (!jwks_uri) {
          throw new Error("No JWKS URI found in OpenID configuration");
        }
        this.#remoteJWKSet = createRemoteJWKSet(new URL(jwks_uri));
      }
      return this.#remoteJWKSet;
    }

    async #validateTokenFromRequest(req: Request): Promise<TokenSet> {
      const tokenSet = this.#getTokenSetFromRequest(req);
      await jwtVerify(
        tokenSet.access_token,
        await this.#getRemoteJWKSet(),
        this.#verifyOptions,
      );
      return tokenSet;
    }

    /**
     *
     * Get the user info from the OpenID Connect provider.
     * This method will cache the user info for the access token.
     *
     * The cache might be refreshed if the `forceRefresh` parameter is set to true.
     *
     * @param reqOrConnection - The request or connection to get the user info for.
     * If not provided, it will use the current async local storage.
     * @param forceRefresh - If true, it will force a refresh of the user info.
     * @returns - The user info from the OpenID Connect provider.
     */
    async getUserInfo(forceRefresh = false): Promise<UserInfo | undefined> {
      const credentials = this.getCredentials();
      if (!credentials) {
        throw new Error("No credentials found");
      }

      const { access_token } = credentials;
      if (!forceRefresh && this.#userPerToken.has(access_token)) {
        return this.#userPerToken.get(access_token);
      }

      const { userinfo_endpoint } = await this.#getDiscoveryDocument();
      if (!userinfo_endpoint) {
        throw new Error("No userinfo endpoint found in OpenID configuration");
      }

      const userInfoResp = await fetch(userinfo_endpoint, {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      });
      if (!userInfoResp.ok) {
        throw new Error(
          `Failed to fetch user info: ${userInfoResp.statusText}`,
        );
      }
      const userInfo = (await userInfoResp.json()) as UserInfo;
      this.#userPerToken.set(access_token, userInfo);
      return userInfo;
    }

    async onRequest(req: Request) {
      try {
        const tokenSet = await this.#validateTokenFromRequest(req);
        return this.#asyncTokenStorage.run(tokenSet!, async () => {
          const authResponse = await this.onAuthenticatedRequest(req);
          return authResponse ?? super.onRequest(req);
        });
      } catch (err) {
        debug(err instanceof Error ? err.message : "Unknown error", {
          error: err,
          authRequired,
        });

        if (!authRequired) {
          return super.onRequest(req);
        }
        if (err instanceof UnauthorizedError) {
          return new Response(err.message, { status: err.statusCode });
        }
        return new Response("Unauthorized", {
          status: 401,
          statusText: "Unauthorized",
        });
      }
    }

    override async onConnect(connection: Connection, ctx: ConnectionContext) {
      try {
        const tokenSet = await this.#validateTokenFromRequest(ctx.request);
        this.#tokenSetPerConnection.set(connection, tokenSet);
        return this.#asyncTokenStorage.run(tokenSet, async () => {
          await this.onAuthenticatedConnect(connection, ctx);
          if (connection.readyState === connection.OPEN) {
            await super.onConnect(connection, ctx);
          }
        });
      } catch (err) {
        debug(err instanceof Error ? err.message : "Unknown error", {
          error: err,
          authRequired,
        });

        if (!authRequired) {
          return super.onConnect(connection, ctx);
        }
        if (err instanceof UnauthorizedError) {
          connection.close(1008, err.message);
          return;
        }
        connection.close(1008, "Unauthorized");
      }
    }

    override onMessage(
      connection: Connection,
      message: WSMessage,
    ): void | Promise<void> {
      const credentials = this.#tokenSetPerConnection.get(connection);

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
    ): Promise<void> {}

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
    async onAuthenticatedRequest(req: Request): Promise<void | Response> {}

    override onClose(
      connection: Connection,
      code: number,
      reason: string,
      wasClean: boolean,
    ): void | Promise<void> {
      const tokenSet = this.#tokenSetPerConnection.get(connection);
      if (tokenSet) {
        this.#userPerToken.delete(tokenSet.access_token);
      }
      this.#tokenSetPerConnection.delete(connection);
      super.onClose(connection, code, reason, wasClean);
    }
  };
};
