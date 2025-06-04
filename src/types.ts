/* eslint-disable @typescript-eslint/no-explicit-any */
export interface UserInfo {
  readonly sub: string;
  readonly name?: string;
  readonly given_name?: string;
  readonly family_name?: string;
  readonly middle_name?: string;
  readonly nickname?: string;
  readonly preferred_username?: string;
  readonly profile?: string;
  readonly picture?: string;
  readonly website?: string;
  readonly email?: string;
  readonly email_verified?: boolean;
  readonly gender?: string;
  readonly birthdate?: string;
  readonly zoneinfo?: string;
  readonly locale?: string;
  readonly phone_number?: string;
  readonly updated_at?: number;
  readonly address?: UserInfoAddress;
  readonly [claim: string]: any | undefined;
}
export interface UserInfoAddress {
  readonly formatted?: string;
  readonly street_address?: string;
  readonly locality?: string;
  readonly region?: string;
  readonly postal_code?: string;
  readonly country?: string;
  readonly [claim: string]: any | undefined;
}

/**
 * TokenSet represents the OAuth2 token information
 */
export interface TokenSet {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_at?: number;
  scope?: string;
  token_type?: string;
}

/**
 * Interface for an authenticated server with methods to handle authentication
 */
export interface AuthenticatedServer {
  /**
   * Get the current credentials for the current request or connection.
   * @returns The credentials for the current request or connection.
   */
  getCredentials(): TokenSet | undefined;

  /**
   * Override this method to handle authenticated connections.
   *
   * If the connection is closed in this method, the super `onConnect` method
   * will not be called.
   *
   * @param connection The connection that was authenticated.
   * @param ctx The connection context.
   */
  onAuthenticatedConnect(connection: any, ctx: any): Promise<void>;

  /**
   * Override this method to handle authenticated requests.
   *
   * If the request returns a response, the super `onRequest` method
   * will not be called.
   *
   * @param req The request that was authenticated.
   * @returns Either undefined or a response.
   */
  onAuthenticatedRequest(req: Request): Promise<void | Response>;

  /**
   * Get the claims from the access token.
   *
   * @param reqOrConnection  - The request or connection to get the claims for.
   * If not provided, it will use the current async local storage.
   *
   * @returns - The claims from the access token.
   */
  getClaims(): Record<string, unknown> | undefined;
}

export type Constructor<T = object> = new (...args: any[]) => T;

export type DiscoveryDocument = {
  userinfo_endpoint?: string;
  jwks_uri?: string;
};

export type WithAuthParams = {
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
 * Interface for an authenticated server with methods to handle authentication
 */
export interface AuthorizedServer extends AuthenticatedServer {
  /**
   * Method called after the request has been authenticated
   * and the user is authorized to connect to the server.
   *
   * @param connection The connection that was authenticated.
   * @param ctx The connection context.
   */
  onAuthorizedConnect(connection: any, ctx: any): Promise<void>;

  /**
   * Method called after the request has been authenticated
   * and the user is authorized.
   *
   * @param req The request that was authenticated.
   * @returns Either undefined or a response.
   */
  onAuthorizedRequest(req: Request): Promise<void | Response>;
}
