import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { Connection, ConnectionContext, type Server } from "partyserver";
import getToken from "./bearer";

type ConstructorOf<T> = new (...args: any[]) => T;

type WithAuthEnv = {
  OIDC_ISSUER_URL: string;
  OIDC_AUDIENCE: string;
};

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
  Env extends WithAuthEnv,
  TBase extends ConstructorOf<Server<Env> & { env: Env }>,
>(
  Base: TBase,
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

    async #validateRequest(req: Request): Promise<Request | Response> {
      try {
        if (!this.#remoteJWKSet) {
          this.#remoteJWKSet = createRemoteJWKSet(
            new URL("/.well-known/jwks.json", this.env.OIDC_ISSUER_URL),
          );
        }
        const { access_token } = this.getCredentials(req);

        await jwtVerify(access_token, this.#remoteJWKSet, {
          issuer: this.env.OIDC_ISSUER_URL,
          audience: this.env.OIDC_AUDIENCE,
        });

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
