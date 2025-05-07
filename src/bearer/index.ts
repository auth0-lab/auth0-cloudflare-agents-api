// Imported from :
// https://github.com/auth0/node-oauth2-jwt-bearer/tree/1504b05101745d4d2efa4c309b28086e31b64154/packages/oauth2-bearer/src

/**
 * Get a Bearer Token from a request per https://tools.ietf.org/html/rfc6750#section-2
 */
import { InvalidRequestError, UnauthorizedError } from "./errors.js";

const TOKEN_RE = /^Bearer (.+)$/i;

const getTokenFromHeader = (headers: Headers) => {
  const authorization = headers.get("authorization");
  if (typeof authorization !== "string") {
    return;
  }
  const match = authorization.match(TOKEN_RE);
  if (!match) {
    return;
  }
  return match[1];
};

const getTokenFromQuery = (query?: URLSearchParams) => {
  const accessToken = query?.get("access_token");
  if (typeof accessToken === "string") {
    return accessToken;
  }
};

/**
 * Get a Bearer Token from a request.
 *
 * @param headers An object containing the request headers, usually `req.headers`.
 * @param query An object containing the request query parameters, usually `req.query`.
 * @param body An object containing the request payload, usually `req.body` or `req.payload`.
 * @param urlEncoded true if the request's Content-Type is `application/x-www-form-urlencoded`.
 */
export default function getToken(
  headers: Headers,
  query?: URLSearchParams,
): string {
  const fromHeader = getTokenFromHeader(headers);
  const fromQuery = getTokenFromQuery(query);

  if (!fromQuery && !fromHeader) {
    throw new UnauthorizedError();
  }

  if (+!!fromQuery + +!!fromHeader > 1) {
    throw new InvalidRequestError(
      "More than one method used for authentication",
    );
  }

  return (fromQuery || fromHeader) as string;
}
