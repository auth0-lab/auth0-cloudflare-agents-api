import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { Server } from "partyserver";
import { afterEach, beforeEach, describe, expect, it, Mock, vi } from "vitest";
import { WithAuth } from "../src";
import getToken from "../src/bearer";

// Mock dependencies
vi.mock("jose", () => ({
  createRemoteJWKSet: vi.fn(),
  decodeJwt: vi.fn(),
  jwtVerify: vi.fn(),
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
  let mockJWKSet: any;
  const onAuthenticatedRequest = vi.fn();
  const onAuthenticatedConnect = vi.fn();
  beforeEach(() => {
    vi.resetAllMocks();

    mockJWKSet = vi.fn();

    (global.fetch as Mock).mockImplementation((uri) => {
      if (
        uri.toString() ===
        "https://auth.example.com/.well-known/openid-configuration"
      ) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              jwks_uri: "https://auth.example.com/jwks.json",
            }),
        });
      }
    });

    (createRemoteJWKSet as any).mockReturnValue(mockJWKSet);

    // Setup default mocked behavior
    (decodeJwt as any).mockReturnValue({
      sub: "user123",
      iss: "https://auth.example.com",
      aud: "api",
    });

    (jwtVerify as any).mockResolvedValue({
      payload: { sub: "user123" },
      protectedHeader: {},
    });

    (getToken as any).mockReturnValue("mock-token");

    // Create the authenticated server class
    AuthenticatedServer = WithAuth(Server);
    server = new AuthenticatedServer({
      OIDC_ISSUER_URL: "https://auth.example.com",
      OIDC_AUDIENCE: "api",
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
    it("should decode and return claims from request token", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("token123");
      const mockClaims = { sub: "user456", iss: "https://auth.example.com" };
      (decodeJwt as any).mockReturnValue(mockClaims);

      // Test
      let claims: any = null;
      server.onAuthenticatedRequest.mockImplementation(() => {
        claims = server.getClaims(req);
        return new Response("OK");
      });
      await server.onRequest(req);

      // Verify
      expect(decodeJwt).toHaveBeenCalledWith("token123");
      expect(claims).toEqual(mockClaims);
    });

    it("should decode and return claims from connection token", async () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({ Authorization: "Bearer token123" });
      const ctx = createMockContext(headers);
      server.onConnect(connection, ctx);

      const mockClaims = { sub: "user789", iss: "https://auth.example.com" };
      (decodeJwt as any).mockReturnValue(mockClaims);

      // Test
      let claims: any = null;
      server.onAuthenticatedConnect.mockImplementation(() => {
        claims = server.getClaims(connection);
      });
      await server.onConnect(connection, ctx);

      // Verify
      expect(decodeJwt).toHaveBeenCalledWith("mock-token");
      expect(claims).toEqual(mockClaims);
    });
  });

  describe("onRequest", () => {
    it("should validate and allow valid requests", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("valid-token");

      // Test
      const resp = await server.onRequest(req);

      expect(jwtVerify).toHaveBeenCalled();
      // Verify
      expect(jwtVerify).toHaveBeenCalledWith(
        "valid-token",
        expect.any(Function),
        {
          issuer: "https://auth.example.com",
          audience: "api",
        },
      );
      expect(resp.status).toBe(200);
    });

    it("should return a 401 response for invalid tokens", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("invalid-token");
      (jwtVerify as any).mockRejectedValue(new Error("Invalid token"));

      // Test
      const result = await server.onRequest(req);

      // Verify
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(401);
      expect(await result.text()).toBe("Unauthorized");
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
      expect(jwtVerify).toHaveBeenCalledWith(
        "valid-token",
        expect.any(Function),
        {
          issuer: "https://auth.example.com",
          audience: "api",
        },
      );

      expect(connection.close).not.toHaveBeenCalled();
    });

    it("should properly close the connection when the token is invalid", async () => {
      // Setup
      (getToken as any).mockReturnValue("invalid-token");
      (jwtVerify as any).mockRejectedValue(new Error("Invalid token"));
      const connection = new MockConnection();
      const ctx = createMockContext();

      // Test
      await server.onConnect(connection, ctx);

      // Verify
      expect(connection.close).toHaveBeenCalledWith(1008, "Unauthorized");
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
        credentials = server.getCredentials(connection);
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
      expect(server.getCredentialsFromConnection(connection)).not.toBeNull();

      // Close the connection
      server.onClose(connection, 1000, "Normal closure", true);

      // Verify - should throw after close
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
});
