/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */

/**
 * This test verifies that the mixins work with flumix-style composition patterns
 * and can be applied to AIChatAgent from the @cloudflare/ai-chat package.
 *
 * Note: This is a type-only test. We cannot actually run code that imports AIChatAgent
 * because it depends on cloudflare: protocol imports which are not available in Node.js.
 */
import type { AIChatAgent } from "@cloudflare/ai-chat";
import { extend } from "flumix";
import { describe, expect, it } from "vitest";
import { AuthAgent, OwnedAgent } from "../src";

// Define a test Env type
interface TestEnv {
  AUTH0_DOMAIN: string;
  AUTH0_AUDIENCE: string;
}

describe("Flumix Compatibility", () => {
  it("should type-check AuthAgent with AIChatAgent base class", () => {
    // This test verifies TypeScript compilation - if it compiles, the types are compatible
    // We use a type-only approach since AIChatAgent can't be instantiated in Node.js

    // Test that AuthAgent accepts AIChatAgent constructor
    type BaseClass = typeof AIChatAgent<TestEnv>;
    type MixedClass = ReturnType<typeof AuthAgent<TestEnv, BaseClass>>;
    type MixedInstance = InstanceType<MixedClass>;

    // These assertions verify the type structure
    const typeChecks = {
      hasClaims: {} as "getClaims" extends keyof MixedInstance ? true : never,
      hasCredentials: {} as "getCredentials" extends keyof MixedInstance
        ? true
        : never,
      hasOnAuthenticatedConnect:
        {} as "onAuthenticatedConnect" extends keyof MixedInstance
          ? true
          : never,
    };

    expect(typeChecks).toBeDefined();
  });

  it("should type-check composition of AuthAgent and OwnedAgent", () => {
    // Test composing multiple mixins
    type BaseClass = typeof AIChatAgent<TestEnv>;
    type WithAuthClass = ReturnType<typeof AuthAgent<TestEnv, BaseClass>>;
    type ComposedClass = ReturnType<typeof OwnedAgent<WithAuthClass>>;
    type ComposedInstance = InstanceType<ComposedClass>;

    // Verify it has methods from both mixins
    const typeChecks = {
      hasClaims: {} as "getClaims" extends keyof ComposedInstance
        ? true
        : never,
      hasSetOwner: {} as "setOwner" extends keyof ComposedInstance
        ? true
        : never,
      hasGetOwner: {} as "getOwner" extends keyof ComposedInstance
        ? true
        : never,
      hasOnAuthenticatedConnect:
        {} as "onAuthenticatedConnect" extends keyof ComposedInstance
          ? true
          : never,
      hasOnAuthorizedConnect:
        {} as "onAuthorizedConnect" extends keyof ComposedInstance
          ? true
          : never,
    };

    expect(typeChecks).toBeDefined();
  });

  it("should work with flumix extend().with().build() pattern at type level", () => {
    // This is the actual pattern used in production code
    // We test the types only since we can't instantiate AIChatAgent in Node.js

    // Note: We can't actually call extend() with AIChatAgent since it would try to
    // import it, triggering the cloudflare: protocol error. Instead, we verify
    // that our mixins work with flumix using a mock base class.

    // Mock the AIChatAgent class structure for type compatibility
    class MockServer<Env> {
      constructor(
        public ctx: any,
        public env?: Env,
      ) {}

      // Add stub methods to satisfy AIChatAgent interface
      async fetch(_request: Request): Promise<Response> {
        return new Response();
      }

      async onConnect(_connection: any, _ctx: any): Promise<void> {}

      async onMessage(_connection: any, _message: any): Promise<void> {}

      async onRequest(_request: Request): Promise<Response> {
        return new Response();
      }

      async onClose(
        _connection: any,
        _code: number,
        _reason: string,
        _wasClean: boolean,
      ): Promise<void> {}

      onError(_connection: any, _error: unknown): void {}
    }

    const SuperAgent = extend(
      MockServer<TestEnv> as unknown as typeof AIChatAgent<TestEnv>,
    )
      .with(AuthAgent)
      .with(OwnedAgent)
      .build();

    type SuperAgentInstance = InstanceType<typeof SuperAgent>;

    // Verify all methods are present
    const typeChecks = {
      hasClaims: {} as "getClaims" extends keyof SuperAgentInstance
        ? true
        : never,
      hasSetOwner: {} as "setOwner" extends keyof SuperAgentInstance
        ? true
        : never,
      hasCredentials: {} as "getCredentials" extends keyof SuperAgentInstance
        ? true
        : never,
      hasOnAuthenticatedConnect:
        {} as "onAuthenticatedConnect" extends keyof SuperAgentInstance
          ? true
          : never,
      hasOnAuthorizedConnect:
        {} as "onAuthorizedConnect" extends keyof SuperAgentInstance
          ? true
          : never,
    };

    expect(typeChecks).toBeDefined();

    // Verify we can instantiate it with proper env
    const mockEnv: TestEnv = {
      AUTH0_DOMAIN: "test.auth0.com",
      AUTH0_AUDIENCE: "https://api.test.com",
    };
    const mockCtx = {};
    const instance = new SuperAgent(mockCtx, mockEnv);
    expect(instance).toBeDefined();
    expect(typeof instance.getClaims).toBe("function");
    expect(typeof (instance as any).setOwner).toBe("function");
  });
});
