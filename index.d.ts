// greenboxal: This file exists because I couldn't get an external type definition to work here.

import { Handler } from "express";
import Koa = require("koa");
import { IncomingMessage, ServerResponse } from "http";
import { Http2ServerRequest, Http2ServerResponse } from "http2";
import EventEmitter = require("events");
import { isRegExp } from "util";

export type SubjectType = "public" | "parwise";
export type AuthMethod = |"none" | "client_secret_basic" | "client_secret_post" | "client_secret_jwt" | "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth";
export type EncryptionAlgValue = |"RSA-OAEP" | "RSA1_5" | "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" | "A128KW" | "A192KW" | "A256KW" | "A128GCMKW" | "A192GCMKW" | "A256GCMKW" | "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW";
export type EncryptionEncValue = |"A128CBC-HS256" | "A128GCM" | "A192CBC-HS384" | "A192GCM" | "A256CBC-HS512" | "A256GCM";
export type SigningAlgValue = |"HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512";
export type OptionalSigningAlgValue = SigningAlgValue | "none";
export type Use = "sig" | "enc";

export interface IRsaKeyBasic {
  kty: 'RSA';
  e: string;
  n: string;
  use?: Use;
  kid?: string;
  alg?: string;
}

export interface IEcKeyBasic {
  kty: 'EC';
  crv: string;
  x: string;
  y: string;
  use?: Use;
  kid?: string;
  alg?: string;
}

export interface IRsaKey extends IRsaKeyBasic {
  d: string;
  dp: string;
  dq: string;
  p: string;
  q: string;
  qi: string;
}

export interface IEcKey extends IEcKeyBasic {
  d: string;
}

export interface IClient {
  application_type?: "web" | "native";
  authorization_encrypted_response_alg?: EncryptionAlgValue;
  authorization_encrypted_response_enc?: EncryptionEncValue;
  authorization_signed_response_alg?: SigningAlgValue;
  backchannel_logout_session_required?: boolean;
  backchannel_logout_uri?: string;
  client_id: string;
  client_name?: string;
  client_secret?: string;
  contacts?: string[];
  default_acr_values?: string[];
  default_max_age?: number;
  frontchannel_logout_session_required?: boolean;
  frontchannel_logout_uri?: string;
  grant_types: string[];
  id_token_encrypted_response_alg?: EncryptionAlgValue;
  id_token_encrypted_response_enc?: EncryptionEncValue;
  id_token_signed_response_alg?: SigningAlgValue;
  initiate_login_uri?: string;
  introspection_encrypted_response_alg?: EncryptionAlgValue;
  introspection_encrypted_response_enc?: EncryptionEncValue;
  introspection_endpoint_auth_method?: AuthMethod;
  introspection_endpoint_auth_signing_alg?: SigningAlgValue;
  introspection_signed_response_alg?: SigningAlgValue;
  jwks?: {
    keys: (IRsaKeyBasic | IEcKeyBasic)[]
  };
  jwks_uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  post_logout_redirect_uris?: string[];
  request_object_encryption_alg?: EncryptionAlgValue;
  request_object_encryption_enc?: EncryptionEncValue;
  request_object_signing_alg?: SigningAlgValue;
  redirect_uris: string[];
  request_uris?: string[];
  require_auth_time?: boolean;
  response_types: string[];
  revocation_endpoint_auth_method?: AuthMethod;
  revocation_endpoint_auth_signing_alg?: SigningAlgValue;
  sector_identifier_uri?: string;
  subject_type?: SubjectType;
  tls_client_auth_subject_dn?: string;
  tls_client_certificate_bound_access_tokens?: boolean;
  token_endpoint_auth_method?: AuthMethod;
  token_endpoint_auth_signing_alg?: SigningAlgValue;
  tos_uri?: string;
  userinfo_encrypted_response_alg?: EncryptionAlgValue;
  userinfo_encrypted_response_enc?: EncryptionEncValue;
  userinfo_signed_response_alg?: SigningAlgValue;
  web_message_uris?: string[];
}

export interface IAdapter {
  upsert: (id: string, payload: object, expiresIn: number) => Promise<void>;
  find: (id: string) => Promise<object>;
  findByUserCode: (userCode: string) => Promise<object>;
  consume: (id: string) => Promise<void>;
  destroy: (id: string) => Promise<void>;
  connect?: (provider: IProvider) => Promise<void>;
}

export interface IKeystore {
  keys: (IRsaKey | IEcKey)[];
}

export interface ISession {
  _id: string;
  accountId: string | null;
  expiresAt: Date;
  save(time: number): Promise<void>;
  sidFor(client_id: string): boolean;
  login: {};
  interaction: {
    error?: "login_required";
    error_description: string;
    reason: "no_session" | "consent_prompt" | "client_not_authorized";
    reason_description: string;
  };
  params: {
    client_id: string;
    redirect_uri: string;
    response_mode: "query";
    response_type: "code";
    login_hint?: string;
    scope: "openid";
    state: string;
  };
  returnTo: string;
  signed: null;
  uuid: string;
  id: string;
}

export interface IConfigurationFeatures {
  devInteractions?: boolean;
  discovery?: boolean;
  requestUri?: boolean;
  oauthNativeApps?: boolean;
  pkce?: boolean;
  alwaysIssueRefresh?: boolean;
  backchannelLogout?: boolean;
  certificateBoundAccessTokens?: boolean;
  claimsParameter?: boolean;
  clientCredentials?: boolean;
  conformIdTokenClaims?: boolean;
  deviceFlow?: boolean;
  encryption?: boolean;
  frontchannelLogout?: boolean;
  introspection?: boolean;
  jwtIntrospection?: boolean;
  jwtResponseModes?: boolean;
  registration?: boolean;
  registrationManagement?: boolean;
  resourceIndicators?: boolean;
  request?: boolean;
  revocation?: boolean;
  sessionManagement?: boolean;
  webMessageResponseMode?: boolean;
}

export interface ICookieOptions {
  secure?: boolean;
  signed?: boolean;
  httpOnly?: boolean;
  maxAge?: number;
}

export type InteractionResult = |boolean | {
  error: string;
  error_description: string;
  reason: string;
  reason_description: string;
};

export interface IRoutes {
  authorization?: string;
  certificates?: string;
  check_session?: string;
  device_authorization?: string;
  end_session?: string;
  introspection?: string;
  registration?: string;
  revocation?: string;
  token?: string;
  userinfo?: string;
  code_verification?: string;
}

export interface IConfiguration {
  features?: IConfigurationFeatures;
  acrValues?: string[];
  audiences?: (ctx: Koa.Context, sub: string, token: string, use: "id_token" | "userinfo" | "access_token" | "client_credentials") => string[] | boolean;
  claims?: {
    [name: string]: string | Array<string> | null
  };
  clientCacheDuration?: number;
  clockTolerance?: number;
  cookies?: {
    keys: string[];
    long?: ICookieOptions;
    names?: object;
    short?: ICookieOptions;
  };
  deviceFlowSuccess?: (ctx: Koa.Context) => void;
  discovery?: object;
  dynamicScopes?: RegExp[];
  extraClientMetadata?: {
    properties?: string[];
    validator?: (key: string, value: string, metadata: object) => void;
  };
  extraParams?: string[];
  findById?: (ctx: Koa.Context, sub: string, token: string) => Promise<{
    accountId: string;
    claims: (use: string, scope: string, claims: object, rejected: string[]) => Promise<object> | object;
  }>;
  formats?: {
    default?: string;
    AccessToken?: string | ((token: string) => string);
    AuthorizationCode?: string | ((token: string) => string);
    RefreshToken?: string | ((token: string) => string);
    DeviceCode?: string | ((token: string) => string);
    ClientCredentials?: string | ((token: string) => string);
    InitialAccessToken?: string | ((token: string) => string);
    RegistrationAccessToken?: string | ((token: string) => string);
  };
  frontchannelLogoutPendingSource?: (ctx: Koa.Context, frames: string[], postLogoutRedirectUri: string, timeout: number) => void;
  interactionCheck?: (ctx: Koa.Context) => InteractionResult;
  interactionUrl?: (ctx: Koa.Context, interaction: InteractionResult) => void;
  introspectionEndpointAuthMethods?: AuthMethod[];
  logoutSource?: (ctx: Koa.Context, form: string) => void;
  pairwiseIdentifier?: (accountId: string, client: object) => string;
  postLogoutRedirectUri?: (ctx: Koa.Context) => string;
  prompts?: string[];
  refreshTokenRotation?: "rotateAndConsume" | "none";
  renderError?: (ctx: Koa.Context, out: object, error: Error) => void;
  responseTypes?: string[];
  revocationEndpointAuthMethods?: AuthMethod[];
  routes?: IRoutes;
  scopes?: string[];
  subjectTypes?: SubjectType;
  tokenEndpointAuthMethods?: AuthMethod[];
  ttl?: {
    AccessToken?: number;
    AuthorizationCode?: number;
    ClientCredentials?: number;
    DeviceCode?: number;
    IdToken?: number;
    RefreshToken?: number;
  };
  uniqueness?: (ctx: Koa.Context, jti: string, expiresAt: number) => boolean;
  userCodeConfirmSource?: (ctx: Koa.Context, form: string, client: object, deviceInfo: object) => void;
  userCodeInputSource?: (ctx: Koa.Context, form: string, out: object, err: Error) => void;
  whitelistedJWA?: {
    authorizationEncryptionAlgValues?: EncryptionAlgValue[];
    authorizationEncryptionEncValues?: EncryptionEncValue[];
    authorizationSigningAlgValues?: SigningAlgValue[];
    idTokenEncryptionAlgValues?: EncryptionAlgValue[];
    idTokenEncryptionEncValues?: EncryptionEncValue[];
    idTokenSigningAlgValues?: OptionalSigningAlgValue[];
    introspectionEncryptionAlgValues?: EncryptionAlgValue[];
    introspectionEncryptionEncValues?: EncryptionEncValue[];
    introspectionEndpointAuthSigningAlgValues?: SigningAlgValue[];
    introspectionSigningAlgValues?: OptionalSigningAlgValue[];
    requestObjectEncryptionAlgValues?: EncryptionAlgValue[];
    requestObjectEncryptionEncValues?: EncryptionEncValue[];
    requestObjectSigningAlgValues?: OptionalSigningAlgValue[];
    revocationEndpointAuthSigningAlgValues?: SigningAlgValue[];
    tokenEndpointAuthSigningAlgValues?: SigningAlgValue[];
    userinfoEncryptionAlgValues?: EncryptionAlgValue[];
    userinfoEncryptionEncValues?: EncryptionEncValue[];
    userinfoSigningAlgValues?: OptionalSigningAlgValue[];
  };
}

export interface IRepository<T> {
  find(id: string): Promise<T>
}

export interface IExtendedTypes {
  Client: any
}

export type IDataTypes<T extends IExtendedTypes> = {
  Client: IClient & T["Client"]
  Session: ISession
}

type RepositoryCollection<T> = {
  [P in keyof T]: IRepository<T[P]>
}

export type KoaContext = Koa.Context & {
  oidc: {
    route: string
    params: { [k: string]: string }
  }
}

export type GrantHandler = (ctx: KoaContext, next: () => Promise<void>) => Promise<void>

export type GrantHandlerFactory<TProvider = IBaseProvider> = (provider: TProvider) => GrantHandler

export interface IBaseProvider {
  app: Koa;

  proxy: boolean;

  initialize(config: {
    adapter?: new (name: string) => IAdapter;
    clients?: IClient[];
    keystore?: IKeystore | any;
  }): Promise<this>;

  use(handler: GrantHandler): this

  interactionDetails(ctx: IncomingMessage | Http2ServerRequest): Promise<ISession>;

  setProviderSession(req: IncomingMessage | Http2ServerRequest, res: ServerResponse | Http2ServerResponse, { }): Promise<ISession>;

  interactionFinished(req: IncomingMessage | Http2ServerRequest, res: ServerResponse | Http2ServerResponse, { }): Promise<void>;

  interactionResult(req: IncomingMessage | Http2ServerRequest, res: ServerResponse | Http2ServerResponse, { }): Promise<string>;

  registerGrantType(name: string, handler: GrantHandlerFactory<this>, allowedAttributes: string[], allowedClaims: string[]): void;

  callback: Handler;
  listen(port: string | number): void;
}

export type IExtendedProvider<T> = IBaseProvider & RepositoryCollection<T>

export type IProvider = IExtendedProvider<{}>

export class Provider<T = {}> implements IExtendedProvider<T> {
  constructor(url: string, config?: IConfiguration)
}
