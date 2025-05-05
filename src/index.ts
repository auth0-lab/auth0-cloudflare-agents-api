import {
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
  JWTVerifyOptions,
} from "jose";
import { AsyncLocalStorage } from "node:async_hooks";
import { Connection, ConnectionContext, Server, WSMessage } from "partyserver";
import getToken from "./bearer";
import { UserInfo } from "./types";

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
  options: JWTVerifyOptions = {},
) => {
  return class extends Base {
    #tokenSetPerConnection = new WeakMap<Connection, TokenSet>();
    #asyncTokenStorage = new AsyncLocalStorage<TokenSet>();

    #userPerConnection = new WeakMap<Connection, UserInfo | undefined>();
    #asyncUserStorage = new AsyncLocalStorage<UserInfo | undefined>();

    #remoteJWKSet: ReturnType<typeof createRemoteJWKSet> | undefined;
    #env: Env;
    #discoveryDocument: DiscoveryDocument | undefined;

    constructor(...args: any[]) {
      super(...args);
      this.#env = args[args.length - 1];
    }

    /**
     * Get the current credentials for the current request or connection.
     *
     * If no request or connection is provided, it will return the credentials
     * for the current async local store.
     *
     * If no credentials are found, it will throw an error.
     * @param reqOrConnection - The request or connection to get the credentials for.
     * If not provided, it will use the current async local storage.
     *
     * @returns - The credentials for the current request or connection.
     */
    getCredentials(reqOrConnection?: Request | Connection): TokenSet {
      if (!reqOrConnection) {
        const tokenSet = this.#asyncTokenStorage.getStore();
        if (!tokenSet) {
          throw new Error("No token set found");
        }
        return tokenSet;
      }
      if (reqOrConnection instanceof Request) {
        const req = reqOrConnection;
        const url = new URL(req.url);
        const token = getToken(req.headers, url.searchParams);
        if (!token) {
          throw new Error("No token set found for this request");
        }
        return {
          access_token: token,
          id_token: req.headers.get("x-id-token") ?? undefined,
          refresh_token: req.headers.get("x-refresh-token") ?? undefined,
        };
      }
      const credentials = this.#tokenSetPerConnection.get(reqOrConnection);
      if (!credentials) {
        throw new Error("No token set found for this connection");
      }
      return credentials;
    }

    /**
     * Get the claims from the access token.
     *
     * @param reqOrConnection  - The request or connection to get the claims for.
     * If not provided, it will use the current async local storage.
     *
     * @returns - The claims from the access token.
     */
    getClaims(reqOrConnection?: Request | Connection): Record<string, unknown> {
      const { access_token } = this.getCredentials(reqOrConnection);
      return decodeJwt(access_token);
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
      let result: JWTVerifyOptions = options;
      if (typeof this.#env === "object" && this.#env !== null) {
        result = {
          issuer: this.#env.hasOwnProperty("OIDC_ISSUER_URL")
            ? ((this.#env as any)["OIDC_ISSUER_URL"] as string)
            : undefined,
          audience: this.#env.hasOwnProperty("OIDC_AUDIENCE")
            ? ((this.#env as any)["OIDC_AUDIENCE"] as string)
            : undefined,
          ...options,
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

    async #validateRequest(req: Request): Promise<Request | Response> {
      try {
        const { access_token } = this.getCredentials(req);
        await jwtVerify(
          access_token,
          await this.#getRemoteJWKSet(),
          this.#verifyOptions,
        );
        return req;
      } catch (err) {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    async #fetchUserInfo() {
      const { access_token } = this.getCredentials();
      const { scope } = this.getClaims();
      const { userinfo_endpoint } = await this.#getDiscoveryDocument();

      if (
        typeof scope !== "string" ||
        scope.includes("openid profile") ||
        !userinfo_endpoint
      ) {
        return;
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
      return userInfo;
    }

    async onBeforeRequest(req: Request) {
      return this.#validateRequest(req);
    }

    async onBeforeConnect(req: Request) {
      return this.#validateRequest(req);
    }

    override onMessage(
      connection: Connection,
      message: WSMessage,
    ): void | Promise<void> {
      return this.#asyncTokenStorage.run(
        this.getCredentials(connection),
        () => {
          return super.onMessage(connection, message);
        },
      );
    }

    override async onConnect(
      connection: Connection,
      ctx: ConnectionContext,
    ): Promise<void> {
      const { request: req } = ctx;
      const url = new URL(req.url);
      const token = getToken(req.headers, url.searchParams);
      const tokenSet = {
        access_token: token,
        id_token: req.headers.get("x-id-token") ?? undefined,
        refresh_token: req.headers.get("x-refresh-token") ?? undefined,
      };
      this.#tokenSetPerConnection.set(connection, tokenSet);
      return this.#asyncTokenStorage.run(tokenSet, async () => {
        const userInfo = await this.#fetchUserInfo();
        this.#userPerConnection.set(connection, userInfo);
        return this.#asyncUserStorage.run(userInfo, () => {
          return super.onConnect(connection, ctx);
        });
      });
    }

    override onClose(
      connection: Connection,
      code: number,
      reason: string,
      wasClean: boolean,
    ): void | Promise<void> {
      this.#tokenSetPerConnection.delete(connection);
      super.onClose(connection, code, reason, wasClean);
    }
  };
};
