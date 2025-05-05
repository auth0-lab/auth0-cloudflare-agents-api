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
