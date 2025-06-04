/* eslint-disable @typescript-eslint/no-explicit-any */
import { Server } from "partyserver";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithAuth } from "../src";
import getToken from "../src/bearer";
import {
  InsufficientScopeError,
  UnauthorizedError,
} from "../src/bearer/errors.js";

// Mock verifyAccessToken function
const mockVerifyAccessToken = vi.fn();

// Mock dependencies
vi.mock("@auth0/auth0-api-js", () => ({
  ApiClient: class MockApiClient {
    constructor() {}
    verifyAccessToken = mockVerifyAccessToken;
  },
}));

vi.mock("../src/bearer", () => ({
  default: vi.fn(),
}));

global.fetch = vi.fn();

const onSpecialMessage = vi.fn();

vi.mock("partyserver", () => {
  return {
    Server: class MockServer {
      public onConnect() {}
      public onClose() {}
      public onBeforeRequest() {}
      public onBeforeConnect() {}
      public onRequest() {
        return new Response("OK");
      }
      public onMessage() {
        onSpecialMessage();
      }
    },
  };
});

// Create a mock Connection class
class MockConnection {
  id = "connection-id-1";
  readyState = 1;
  OPEN = 1;
  close = vi.fn();
  send = vi.fn();
}

// Create a mock ConnectionContext
const createMockContext = (
  headers = new Headers(),
  url = "https://example.com",
) => {
  const request = new Request(url, { headers });
  return { request };
};

describe("WithAuth Mixin", () => {
  let AuthenticatedServer: any;
  let server: any;
  const onAuthenticatedRequest = vi.fn();
  const onAuthenticatedConnect = vi.fn();

  beforeEach(() => {
    vi.resetAllMocks();

    // Setup default mocked behavior
    mockVerifyAccessToken.mockResolvedValue({
      sub: "user123",
      iss: "https://auth0.example.com",
      aud: "api",
      scope: "read:data write:data",
    });

    (getToken as any).mockReturnValue("mock-token");

    // Create the authenticated server class
    AuthenticatedServer = WithAuth(Server);
    server = new AuthenticatedServer({
      AUTH0_DOMAIN: "auth0.example.com",
      AUTH0_AUDIENCE: "api",
    });
    server.onAuthenticatedRequest = onAuthenticatedRequest;
    server.onAuthenticatedConnect = onAuthenticatedConnect;
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("getCredentials", () => {
    it("should get credentials from a request", async () => {
      // Setup
      const headers = new Headers({
        Authorization: "Bearer token123",
        "x-id-token": "id-token123",
        "x-refresh-token": "refresh-token123",
      });
      const req = new Request("https://example.com", { headers });
      (getToken as any).mockReturnValue("token123");

      // Test
      let credentials: any = null;
      server.onAuthenticatedRequest.mockImplementation(() => {
        credentials = server.getCredentials();
        return new Response("OK");
      });
      await server.onRequest(req);

      // Verify
      expect(getToken).toHaveBeenCalledWith(
        headers,
        expect.any(URLSearchParams),
      );
      expect(credentials).toEqual({
        access_token: "token123",
        id_token: "id-token123",
        refresh_token: "refresh-token123",
      });
    });

    it("should return undef if no token found in the context", () => {
      // Test & Verify
      expect(server.getCredentials()).toBeUndefined();
    });

    it("should get credentials from a connection", async () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({
        Authorization: "Bearer token123",
        "x-id-token": "id-token123",
        "x-refresh-token": "refresh-token123",
      });
      const ctx = createMockContext(headers);

      //test
      let credentials: any = null;
      server.onAuthenticatedConnect.mockImplementation(() => {
        credentials = server.getCredentials();
      });
      await server.onConnect(connection, ctx);

      // Verify
      expect(credentials).toEqual({
        access_token: "mock-token",
        id_token: "id-token123",
        refresh_token: "refresh-token123",
      });
    });
  });

  describe("getClaims", () => {
    it("should return claims from verified token", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("token123");
      const mockClaims = {
        sub: "user456",
        iss: "https://auth0.example.com",
        scope: "read:data write:data",
      };
      mockVerifyAccessToken.mockResolvedValue(mockClaims);

      // Test
      let claims: any = null;
      server.onAuthenticatedRequest.mockImplementation(() => {
        claims = server.getClaims();
        return new Response("OK");
      });
      await server.onRequest(req);

      // Verify
      expect(mockVerifyAccessToken).toHaveBeenCalledWith({
        accessToken: "token123",
      });
      expect(claims).toEqual(mockClaims);
    });

    it("should return undefined if no token is found", () => {
      // Test
      const claims = server.getClaims();

      // Verify
      expect(claims).toBeUndefined();
    });
  });

  describe("requireAuth", () => {
    it("should successfully validate a token with required scopes", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("valid-token");
      mockVerifyAccessToken.mockResolvedValue({
        sub: "user123",
        scope: "read:data write:data",
      });

      // Test
      let tokenSet;
      server.onAuthenticatedRequest.mockImplementation(async () => {
        tokenSet = await server.requireAuth({ scopes: "read:data" });
        return new Response("OK");
      });

      await server.onRequest(req);

      // Verify
      expect(mockVerifyAccessToken).toHaveBeenCalledWith({
        accessToken: "valid-token",
      });
      expect(tokenSet).toEqual({
        access_token: "valid-token",
        id_token: undefined,
        refresh_token: undefined,
      });
    });

    it("should throw InsufficientScopeError if token lacks required scopes", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("valid-token");
      mockVerifyAccessToken.mockResolvedValue({
        sub: "user123",
        scope: "read:data", // Missing write:data scope
      });

      // Test & Verify
      server.onAuthenticatedRequest.mockImplementation(async () => {
        await expect(
          server.requireAuth({ scopes: "write:data" }),
        ).rejects.toThrow(InsufficientScopeError);
        return new Response("OK");
      });

      await server.onRequest(req);
    });

    it("should throw UnauthorizedError if no token is found", async () => {
      // Test & Verify
      await expect(server.requireAuth()).rejects.toThrow(UnauthorizedError);
    });
  });

  describe("onRequest", () => {
    it("should validate and allow valid requests", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("valid-token");

      // Test
      const resp = await server.onRequest(req);

      // Verify
      expect(mockVerifyAccessToken).toHaveBeenCalledWith({
        accessToken: "valid-token",
      });
      expect(resp.status).toBe(200);
    });

    it("should return a 401 response for invalid tokens", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("invalid-token");
      mockVerifyAccessToken.mockRejectedValue(new Error("Invalid token"));

      // Test
      const result = await server.onRequest(req);

      // Verify
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(401);
    });

    it("should skip auth validation when authRequired is false", async () => {
      // Setup
      const req = new Request("https://example.com");
      const AuthenticatedServerOptional = WithAuth(Server, {
        authRequired: false,
      });
      const optionalServer = new AuthenticatedServerOptional(
        {},
        {
          AUTH0_DOMAIN: "auth0.example.com",
          AUTH0_AUDIENCE: "api",
        },
      );

      // Test
      await optionalServer.onRequest(req);

      // Verify
      expect(mockVerifyAccessToken).not.toHaveBeenCalled();
    });
  });

  describe("onConnect", () => {
    it("should validate and allow valid connection requests", async () => {
      // Setup
      (getToken as any).mockReturnValue("valid-token");
      const connection = new MockConnection();
      const ctx = createMockContext();

      // Test
      await server.onConnect(connection, ctx);

      // Verify
      expect(mockVerifyAccessToken).toHaveBeenCalledWith({
        accessToken: "valid-token",
      });
      expect(connection.close).not.toHaveBeenCalled();
    });

    it("should properly close the connection when the token is invalid", async () => {
      // Setup
      (getToken as any).mockReturnValue("invalid-token");
      mockVerifyAccessToken.mockRejectedValue(new Error("Invalid token"));
      const connection = new MockConnection();
      const ctx = createMockContext();

      // Test
      await server.onConnect(connection, ctx);

      // Verify
      expect(connection.close).toHaveBeenCalledWith(1008, "Invalid token");
    });

    it("should skip auth validation when authRequired is false", async () => {
      // Setup
      const AuthenticatedServerOptional = WithAuth(Server, {
        authRequired: false,
      });
      const optionalServer = new AuthenticatedServerOptional(
        {},
        {
          AUTH0_DOMAIN: "auth0.example.com",
          AUTH0_AUDIENCE: "api",
        },
      );
      const connection = new MockConnection();
      const ctx = createMockContext();

      // Test
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      //@ts-expect-error
      await optionalServer.onConnect(connection, ctx);

      // Verify
      expect(mockVerifyAccessToken).not.toHaveBeenCalled();
    });
  });

  describe("connection lifecycle", () => {
    it("should store token set when connection is established", async () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({
        Authorization: "Bearer token-xyz",
        "x-id-token": "id-token-xyz",
        "x-refresh-token": "refresh-token-xyz",
      });
      const ctx = createMockContext(headers);

      // Test
      let credentials: any = null;
      server.onAuthenticatedConnect.mockImplementation(() => {
        credentials = server.getCredentialsFromConnection(connection);
      });
      await server.onConnect(connection, ctx);

      // Verify - test by retrieving credentials
      expect(credentials).toEqual({
        access_token: "mock-token",
        id_token: "id-token-xyz",
        refresh_token: "refresh-token-xyz",
      });
    });

    it("should delete token set when connection is closed", async () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({ Authorization: "Bearer token123" });
      const ctx = createMockContext(headers);

      // First connect to store credentials
      await server.onConnect(connection, ctx);

      // Test - can get credentials before close
      expect(
        server.getCredentialsFromConnection(connection),
      ).not.toBeUndefined();

      // Close the connection
      server.onClose(connection, 1000, "Normal closure", true);

      // Verify - should be undefined after close
      expect(server.getCredentialsFromConnection(connection)).toBeUndefined();
    });
  });

  describe("onMessage (async local storage)", () => {
    it("should return credentials onMessage", async () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({ Authorization: "Bearer token123" });
      const ctx = createMockContext(headers);
      let credentials: any;

      onSpecialMessage.mockImplementation(() => {
        // without connection
        credentials = server.getCredentials();
      });

      await server.onConnect(connection, ctx);

      // Test
      await server.onMessage(connection, "message");

      // Verify
      expect(onSpecialMessage).toHaveBeenCalled();
      expect(credentials).toEqual({
        access_token: "mock-token",
      });
    });
  });

  describe("onAuthenticatedConnect and onAuthenticatedRequest", () => {
    it("should call onAuthenticatedConnect when a connection is authenticated", async () => {
      // Setup
      const connection = new MockConnection();
      const ctx = createMockContext();

      // Test
      await server.onConnect(connection, ctx);

      // Verify
      expect(onAuthenticatedConnect).toHaveBeenCalledWith(connection, ctx);
    });

    it("should call onAuthenticatedRequest when a request is authenticated", async () => {
      // Setup
      const req = new Request("https://example.com");

      // Test
      await server.onRequest(req);

      // Verify
      expect(onAuthenticatedRequest).toHaveBeenCalledWith(req);
    });
  });
});
