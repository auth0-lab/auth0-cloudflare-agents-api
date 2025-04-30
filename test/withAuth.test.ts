import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
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

// Mock PartyServer components
class MockServer {
  env: {
    OIDC_ISSUER_URL: string;
    OIDC_AUDIENCE: string;
  };
  constructor({ env = {} } = {}) {
    // @ts-ignore
    this.env = env;
  }

  onConnect() {}
  onClose() {}
}

// Create a mock Connection class
class MockConnection {}

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
    // @ts-ignore
    AuthenticatedServer = WithAuth(MockServer);
    server = new AuthenticatedServer({
      env: {
        OIDC_ISSUER_URL: "https://auth.example.com",
        OIDC_AUDIENCE: "api",
      },
    });
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("getCredentials", () => {
    it("should get credentials from a request", () => {
      // Setup
      const headers = new Headers({
        Authorization: "Bearer token123",
        "x-id-token": "id-token123",
        "x-refresh-token": "refresh-token123",
      });
      const req = new Request("https://example.com", { headers });
      (getToken as any).mockReturnValue("token123");

      // Test
      const credentials = server.getCredentials(req);

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

    it("should throw an error if no token found for request", () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue(null);

      // Test & Verify
      expect(() => server.getCredentials(req)).toThrow(
        "No token set found for this request",
      );
    });

    it("should get credentials from a connection", () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({
        Authorization: "Bearer token123",
        "x-id-token": "id-token123",
        "x-refresh-token": "refresh-token123",
      });
      const ctx = createMockContext(headers);

      // First connect to store credentials
      server.onConnect(connection, ctx);

      // Test
      const credentials = server.getCredentials(connection);

      // Verify
      expect(credentials).toEqual({
        access_token: "mock-token",
        id_token: "id-token123",
        refresh_token: "refresh-token123",
      });
    });

    it("should throw an error if no token found for connection", () => {
      // Setup
      const connection = new MockConnection();

      // Test & Verify
      expect(() => server.getCredentials(connection)).toThrow(
        "No token set found for this connection",
      );
    });
  });

  describe("getClaims", () => {
    it("should decode and return claims from request token", () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("token123");
      const mockClaims = { sub: "user456", iss: "https://auth.example.com" };
      (decodeJwt as any).mockReturnValue(mockClaims);

      // Test
      const claims = server.getClaims(req);

      // Verify
      expect(decodeJwt).toHaveBeenCalledWith("token123");
      expect(claims).toEqual(mockClaims);
    });

    it("should decode and return claims from connection token", () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({ Authorization: "Bearer token123" });
      const ctx = createMockContext(headers);
      server.onConnect(connection, ctx);

      const mockClaims = { sub: "user789", iss: "https://auth.example.com" };
      (decodeJwt as any).mockReturnValue(mockClaims);

      // Test
      const claims = server.getClaims(connection);

      // Verify
      expect(decodeJwt).toHaveBeenCalledWith("mock-token");
      expect(claims).toEqual(mockClaims);
    });
  });

  describe("onBeforeRequest", () => {
    it("should validate and allow valid requests", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("valid-token");

      // Test
      const result = await server.onBeforeRequest(req);

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
      expect(result).toBe(req); // Should return the original request
    });

    it("should return a 401 response for invalid tokens", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("invalid-token");
      (jwtVerify as any).mockRejectedValue(new Error("Invalid token"));

      // Test
      const result = await server.onBeforeRequest(req);

      // Verify
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(401);
      expect(await result.text()).toBe("Unauthorized");
    });
  });

  describe("onBeforeConnect", () => {
    it("should validate and allow valid connection requests", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("valid-token");

      // Test
      const result = await server.onBeforeConnect(req);

      // Verify
      expect(jwtVerify).toHaveBeenCalledWith(
        "valid-token",
        expect.any(Function),
        {
          issuer: "https://auth.example.com",
          audience: "api",
        },
      );
      expect(result).toBe(req); // Should return the original request
    });

    it("should return a 401 response for invalid tokens on connection", async () => {
      // Setup
      const req = new Request("https://example.com");
      (getToken as any).mockReturnValue("invalid-token");
      (jwtVerify as any).mockRejectedValue(new Error("Invalid token"));

      // Test
      const result = await server.onBeforeConnect(req);

      // Verify
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(401);
      expect(await result.text()).toBe("Unauthorized");
    });
  });

  describe("connection lifecycle", () => {
    it("should store token set when connection is established", () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({
        Authorization: "Bearer token-xyz",
        "x-id-token": "id-token-xyz",
        "x-refresh-token": "refresh-token-xyz",
      });
      const ctx = createMockContext(headers);

      // Test
      server.onConnect(connection, ctx);

      // Verify - test by retrieving credentials
      const credentials = server.getCredentials(connection);
      expect(credentials).toEqual({
        access_token: "mock-token",
        id_token: "id-token-xyz",
        refresh_token: "refresh-token-xyz",
      });
    });

    it("should delete token set when connection is closed", () => {
      // Setup
      const connection = new MockConnection();
      const headers = new Headers({ Authorization: "Bearer token123" });
      const ctx = createMockContext(headers);

      // First connect to store credentials
      server.onConnect(connection, ctx);

      // Test - can get credentials before close
      expect(() => server.getCredentials(connection)).not.toThrow();

      // Close the connection
      server.onClose(connection, 1000, "Normal closure", true);

      // Verify - should throw after close
      expect(() => server.getCredentials(connection)).toThrow(
        "No token set found for this connection",
      );
    });
  });
});
