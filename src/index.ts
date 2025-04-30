import {
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
  JWTVerifyOptions,
} from "jose";
import { Connection, ConnectionContext, type Server } from "partyserver";
import getToken from "./bearer";

type ConstructorOf<T> = new (...args: any[]) => T;

type TokenSet = {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_at?: number;
  scope?: string;
  token_type?: string;
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
export const WithAuth = <
  TBase extends ConstructorOf<Server & { env: unknown }>,
>(
  Base: TBase,
  options: JWTVerifyOptions = {},
) => {
  return class extends Base {
    #tokenSetPerConnection = new WeakMap<Connection, TokenSet>();
    #remoteJWKSet: ReturnType<typeof createRemoteJWKSet> | undefined;

    getCredentials(reqOrConnection: Request | Connection): TokenSet {
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

    getClaims(reqOrConnection: Request | Connection): Record<string, unknown> {
      const { access_token } = this.getCredentials(reqOrConnection);
      return decodeJwt(access_token);
    }

    get #verifyOptions(): JWTVerifyOptions {
      let result: JWTVerifyOptions = options;
      if (typeof this.env === "object" && this.env !== null) {
        result = {
          issuer: this.env.hasOwnProperty("OIDC_ISSUER_URL")
            ? ((this.env as any)["OIDC_ISSUER_URL"] as string)
            : undefined,
          audience: this.env.hasOwnProperty("OIDC_AUDIENCE")
            ? ((this.env as any)["OIDC_AUDIENCE"] as string)
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
        const { jwks_uri } = await resp.json();
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

    async onBeforeRequest(req: Request) {
      return this.#validateRequest(req);
    }

    async onBeforeConnect(req: Request) {
      return this.#validateRequest(req);
    }

    override onConnect(
      connection: Connection,
      ctx: ConnectionContext,
    ): void | Promise<void> {
      const { request: req } = ctx;
      const url = new URL(req.url);
      const token = getToken(req.headers, url.searchParams);
      const tokenSet = {
        access_token: token,
        id_token: req.headers.get("x-id-token") ?? undefined,
        refresh_token: req.headers.get("x-refresh-token") ?? undefined,
      };
      this.#tokenSetPerConnection.set(connection, tokenSet);
      super.onConnect(connection, ctx);
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
