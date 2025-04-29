import { describe, it, expect } from 'vitest';
import getToken from '../src/bearer';
import { InvalidRequestError, UnauthorizedError } from '../src/bearer/errors';

describe('Bearer Token Extraction', () => {
  describe('getToken', () => {
    it('should extract token from Authorization header', () => {
      const headers = new Headers({
        'Authorization': 'Bearer token123'
      });
      
      const token = getToken(headers);
      expect(token).toBe('token123');
    });

    it('should extract token from query parameter', () => {
      const headers = new Headers();
      const query = new URLSearchParams({
        'access_token': 'query-token'
      });
      
      const token = getToken(headers, query);
      expect(token).toBe('query-token');
    });

    it('should throw UnauthorizedError when no token is provided', () => {
      const headers = new Headers();
      const query = new URLSearchParams();
      
      expect(() => getToken(headers, query)).toThrow(UnauthorizedError);
    });

    it('should throw InvalidRequestError when token is provided in both header and query', () => {
      const headers = new Headers({
        'Authorization': 'Bearer header-token'
      });
      const query = new URLSearchParams({
        'access_token': 'query-token'
      });
      
      expect(() => getToken(headers, query)).toThrow(InvalidRequestError);
      expect(() => getToken(headers, query)).toThrow('More than one method used for authentication');
    });

    it('should ignore non-Bearer authorization headers', () => {
      const headers = new Headers({
        'Authorization': 'Basic dXNlcjpwYXNz'
      });
      const query = new URLSearchParams();
      
      expect(() => getToken(headers, query)).toThrow(UnauthorizedError);
    });

    it('should be case-insensitive for Bearer token', () => {
      const headers = new Headers({
        'Authorization': 'bearer token123'
      });
      
      const token = getToken(headers);
      expect(token).toBe('token123');
    });
  });
});