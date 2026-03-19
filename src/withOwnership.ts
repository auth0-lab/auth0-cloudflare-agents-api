/* eslint-disable @typescript-eslint/no-explicit-any */
import type { AIChatAgent } from "@cloudflare/ai-chat";
import { Connection, Server } from "partyserver";
import { AuthenticatedServer, AuthorizedServer, Constructor } from "./types.js";

interface DurableObjectState {
  readonly storage: {
    get<T = unknown>(key: string, options?: any): Promise<T | undefined>;
    put<T>(key: string, value: T, options?: any): Promise<void>;
  };
}

const isDurableObjectState = (state: any): state is DurableObjectState => {
  return (
    state &&
    typeof state.storage === "object" &&
    typeof state.storage.get === "function" &&
    typeof state.storage.put === "function"
  );
};

/**
 * Mixin to add ownership functionality to an Authenticated and DurableObject server.
 *
 * The setOwner method should be called when the object is created.
 *
 * Every time a connection or request is made, the ownership is checked.
 *
 * @param Base - The base class to extend from. This should be a class that extends `Server` or `AIChatAgent` and implements `AuthenticatedServer`.
 *
 * @returns - A new class that extends the base class with ownership functionality.
 */
export const WithOwnership = <
  TBase extends
    | Constructor<Server<any> & AuthenticatedServer>
    | Constructor<AIChatAgent<any> & AuthenticatedServer>,
>(
  Base: TBase,
  options: { debug?: (message: string, ctx: any) => void } = {},
): TBase & Constructor<AuthorizedServer> => {
  const debug = options.debug ?? (() => {});

  return class WithOwnership extends Base {
    async onAuthorizedConnect(connection: any, ctx: any): Promise<void> {
      debug("Authenticated connection", {
        connection,
        ctx,
      });
    }

    async onAuthorizedRequest(req: Request): Promise<void | Response> {
      debug("Authenticated request", {
        req,
      });
    }

    /**
     * Checks if the current user in the connection or request
     * is the actual owner of the chat.
     *
     * Note that the owner is set when the chat is created.
     *
     * @returns - A boolean indicating if the current user is the owner.
     */
    async #isCurrentUserOwner(): Promise<boolean> {
      // Base class implements AuthenticatedServer, so getClaims() is available
      const userInfo = (this as any as AuthenticatedServer).getClaims();
      const objectOwner = await this.getOwner();
      if (objectOwner !== userInfo?.sub) {
        return false;
      }
      return true;
    }

    async onAuthenticatedConnect(
      connection: Connection,
      ctx: any,
    ): Promise<void> {
      await super.onAuthenticatedConnect(connection, ctx);
      if (!(await this.#isCurrentUserOwner())) {
        connection.close(1008, "This chat is not yours.");
        return;
      }
      this.onAuthorizedConnect(connection, ctx);
    }

    async onAuthenticatedRequest(request: Request): Promise<void | Response> {
      await super.onAuthenticatedRequest(request);
      if (!(await this.#isCurrentUserOwner())) {
        return new Response("This chat is not yours.", { status: 403 });
      }
      return await this.onAuthorizedRequest(request);
    }

    #getDurableStorage() {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const ctx = this.ctx;
      if (!isDurableObjectState(ctx)) {
        throw new Error(
          "WithOwnership used on a non-DurableObject context. Please overwrite setOwner and getOwner methods.",
        );
      }
      return ctx.storage;
    }

    async setOwner(owner: string, overwrite: boolean = false): Promise<void> {
      if (!owner) {
        throw new Error("Owner cannot be empty");
      }
      const currentOwner = await this.getOwner();
      if (currentOwner && currentOwner !== owner && !overwrite) {
        throw new Error("The owner is already set to another user");
      }
      await this.#getDurableStorage().put("owner", owner);
    }

    async getOwner(): Promise<string | undefined> {
      return this.#getDurableStorage().get("owner");
    }
  } as unknown as TBase & Constructor<AuthorizedServer>;
};

/**
 * Alias for the WithOwnership mixin.
 * This is used to provide a more descriptive name for the mixin.
 */
export const OwnedAgent = WithOwnership;
