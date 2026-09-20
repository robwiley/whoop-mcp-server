import { createHash, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import Database from 'better-sqlite3';
import express, { type Express, type RequestHandler, type Response } from 'express';
import { mcpAuthRouter, mcpAuthMetadataRouter, createOAuthMetadata } from '@modelcontextprotocol/sdk/server/auth/router.js';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidClientMetadataError, InvalidGrantError, InvalidScopeError, InvalidTargetError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const random = () => randomBytes(32).toString('base64url');
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
const equal = (a: string, b: string) => timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)));
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const now = () => Math.floor(Date.now() / 1000);
type Grant = { clientId: string; resource: string; scopes: string[]; family: string; redirectUri?: string; challenge?: string };
type Flow = { client: OAuthClientInformationFull; params: AuthorizationParams; resource: string; cookie: string; expires: number };

/** Single-owner OAuth provider. Upstream WHOOP OAuth is separate and unchanged. */
export class PersonalOAuth implements OAuthServerProvider {
  private db: Database.Database;
  private key: Buffer;
  private flows = new Map<string, Flow>();
  private attempts: number[] = [];
  readonly resources: Map<string, string>;

  constructor(readonly issuer: URL, path: string, private password: string, encryptionSecret: string, hevy: boolean) {
    if (issuer.protocol !== 'https:' || password.length < 32 || encryptionSecret.length < 32) throw new Error('Strong OAuth configuration required');
    this.key = createHash('sha256').update(encryptionSecret).digest();
    this.resources = new Map([[new URL('/mcp', issuer).href, 'whoop:read']]);
    if (hevy) this.resources.set(new URL('/hevy/mcp', issuer).href, 'hevy:manage');
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS oauth_grants (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);`);
  }
  close() { this.db.close(); }
  private encrypt(value: unknown) {
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
  }
  private decrypt(value: string) {
    const data = Buffer.from(value, 'base64'), cipher = createDecipheriv('aes-256-gcm', this.key, data.subarray(0, 12));
    cipher.setAuthTag(data.subarray(12, 28));
    return JSON.parse(Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString());
  }
  get clientsStore() {
    return {
      getClient: (id: string): OAuthClientInformationFull | undefined => {
        const row = this.db.prepare('SELECT value FROM oauth_clients WHERE id=?').get(id) as {value:string} | undefined;
        return row ? this.decrypt(row.value) : undefined;
      },
      registerClient: (client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>): OAuthClientInformationFull => {
        if (!client.redirect_uris.length || client.redirect_uris.length > 5 || !client.redirect_uris.every(uri => {
          const u = new URL(uri);
          return u.origin === 'https://chatgpt.com' && !u.search && !u.hash &&
            (u.pathname === '/connector_platform_oauth_redirect' || /^\/connector\/oauth\/[A-Za-z0-9_-]+$/.test(u.pathname));
        })) throw new InvalidClientMetadataError('Only ChatGPT connector redirect URLs are supported');
        if (client.token_endpoint_auth_method && !['none', 'client_secret_post'].includes(client.token_endpoint_auth_method)) throw new InvalidClientMetadataError('Unsupported client authentication');
        const count = this.db.prepare('SELECT COUNT(*) AS n FROM oauth_clients').get() as {n:number};
        if (count.n >= 100) throw new InvalidClientMetadataError('Client registration limit reached');
        const full = {...client, client_id: random(), client_id_issued_at: now(), client_secret_expires_at: 0};
        this.db.prepare('INSERT INTO oauth_clients VALUES (?,?)').run(full.client_id, this.encrypt(full));
        return full;
      },
    };
  }
  private resource(resource?: URL): string {
    if (!resource || !this.resources.has(resource.href)) throw new InvalidTargetError('An exact supported MCP resource is required');
    return resource.href;
  }
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) {
    const resource = this.resource(params.resource), scope = this.resources.get(resource)!;
    if (params.scopes?.some(s => s !== scope)) throw new InvalidScopeError('Scope does not match resource');
    for (const [id, flow] of this.flows) if (flow.expires < now()) this.flows.delete(id);
    if (this.flows.size >= 100) { res.status(429).send('Too many pending requests'); return; }
    const id = random(), cookie = random();
    this.flows.set(id, {client, params, resource, cookie, expires: now() + 600});
    res.cookie('__Host-fitness-connect', cookie, {secure:true, httpOnly:true, sameSite:'lax', path:'/', maxAge:600000});
    res.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    const permission = scope === 'whoop:read' ? 'Read your WHOOP recovery, sleep, and training data.' : 'Read and modify your Hevy workouts and routines.';
    res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Functional Strength</title><body><h1>Connect Functional Strength to ChatGPT</h1><p>${permission}</p><p>Return address: ${escape(params.redirectUri)}</p><p>Enter the AUTH_TOKEN from the whoop-mcp service in Railway. This is your private connection password, not your WHOOP password.</p><form method="post" action="/connect"><input type="hidden" name="flow" value="${id}"><label>Connection password <input type="password" name="password" required autocomplete="current-password"></label><button type="submit">Authorize ChatGPT</button></form><p>Close this window to cancel.</p></body></html>`);
  }
  consent: RequestHandler = (req, res) => {
    this.attempts = this.attempts.filter(t => t > now() - 900);
    if (this.attempts.length >= 30) { res.status(429).send('Try again in 15 minutes.'); return; }
    this.attempts.push(now());
    const id = typeof req.body.flow === 'string' ? req.body.flow : '';
    const flow = this.flows.get(id);
    this.flows.delete(id);
    const cookie = req.headers.cookie?.split(';').map(s => s.trim()).find(s => s.startsWith('__Host-fitness-connect='))?.split('=')[1] ?? '';
    if (!flow || flow.expires < now() || !equal(cookie, flow.cookie) || req.headers.origin !== this.issuer.origin ||
      typeof req.body.password !== 'string' || !equal(req.body.password, this.password)) {
      res.status(403).send('Connection not authorized. Start a new connection from ChatGPT.'); return;
    }
    const grant: Grant = {clientId:flow.client.client_id, resource:flow.resource, scopes:[this.resources.get(flow.resource)!], family:random(), redirectUri:flow.params.redirectUri, challenge:flow.params.codeChallenge};
    const code = this.save('code', grant, 300), redirect = new URL(flow.params.redirectUri);
    redirect.searchParams.set('code', code);
    if (flow.params.state) redirect.searchParams.set('state', flow.params.state);
    res.clearCookie('__Host-fitness-connect', {secure:true, httpOnly:true, sameSite:'lax', path:'/'});
    res.redirect(303, redirect.href);
  };
  private save(kind: string, grant: Grant, ttl: number) {
    const token = random();
    this.db.prepare('DELETE FROM oauth_grants WHERE expires < ?').run(now());
    this.db.prepare('INSERT INTO oauth_grants(hash,kind,value,expires) VALUES (?,?,?,?)').run(hash(token), kind, JSON.stringify(grant), now()+ttl);
    return token;
  }
  private read(token: string, kind: string, clientId?: string, allowUsed = false): Grant {
    const row = this.db.prepare('SELECT value,expires,used FROM oauth_grants WHERE hash=? AND kind=?').get(hash(token), kind) as {value:string;expires:number;used:number} | undefined;
    if (!row || row.expires <= now()) throw new InvalidGrantError('Invalid or expired grant');
    const grant = JSON.parse(row.value) as Grant;
    if (clientId && grant.clientId !== clientId) throw new InvalidGrantError('Client mismatch');
    if (row.used && !allowUsed) {
      this.revokeFamily(grant.family);
      throw new InvalidGrantError('Grant already used; reconnect');
    }
    return grant;
  }
  private revokeFamily(family: string) { this.db.prepare("DELETE FROM oauth_grants WHERE json_extract(value,'$.family')=?").run(family); }
  private tokens(grant: Grant): OAuthTokens {
    const {redirectUri, challenge, ...base} = grant;
    return {access_token:this.save('access', base, 3600), refresh_token:this.save('refresh', base, 90*86400), token_type:'Bearer', expires_in:3600, scope:base.scopes.join(' ')};
  }
  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string) { return this.read(code,'code',client.client_id).challenge!; }
  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    return this.db.transaction(() => {
      const grant = this.read(code,'code',client.client_id);
      if (redirectUri !== grant.redirectUri || this.resource(resource) !== grant.resource) throw new InvalidGrantError('Redirect or resource mismatch');
      this.db.prepare('UPDATE oauth_grants SET used=1 WHERE hash=?').run(hash(code));
      return this.tokens(grant);
    })();
  }
  async exchangeRefreshToken(client: OAuthClientInformationFull, token: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    // Check replays outside the transaction so family revocation survives an error.
    this.read(token,'refresh',client.client_id);
    return this.db.transaction(() => {
      const grant = this.read(token,'refresh',client.client_id);
      if (this.resource(resource) !== grant.resource || scopes?.some(s => !grant.scopes.includes(s))) throw new InvalidGrantError('Scope or resource mismatch');
      this.db.prepare('UPDATE oauth_grants SET used=1 WHERE hash=?').run(hash(token));
      return this.tokens(grant);
    })();
  }
  async verifyAccessToken(token: string) {
    try {
      const grant = this.read(token,'access');
      const row = this.db.prepare('SELECT expires FROM oauth_grants WHERE hash=?').get(hash(token)) as {expires:number};
      return {token, clientId:grant.clientId, scopes:grant.scopes, resource:new URL(grant.resource), expiresAt:row.expires};
    } catch { throw new InvalidTokenError('Invalid or expired access token'); }
  }
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest) {
    for (const kind of ['access','refresh']) {
      try { this.revokeFamily(this.read(request.token,kind,client.client_id,true).family); } catch { /* idempotent */ }
    }
  }
  guard(resource: URL, legacyToken?: string): RequestHandler {
    return async (req,res,next) => {
      const header = req.headers.authorization ?? '';
      if (legacyToken && equal(header, 'Bearer '+legacyToken)) { next(); return; }
      try {
        if (!header.startsWith('Bearer ')) throw new Error();
        const info = await this.verifyAccessToken(header.slice(7));
        if (info.resource.href !== resource.href || !info.scopes.includes(this.resources.get(resource.href)!)) throw new Error();
        next();
      } catch {
        res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${this.issuer.origin}/.well-known/oauth-protected-resource${resource.pathname}"`);
        res.status(401).json({error:'Unauthorized'});
      }
    };
  }
}

export function installOAuth(app: Express, provider: PersonalOAuth) {
  const options = {provider, issuerUrl:provider.issuer, scopesSupported:[...provider.resources.values()]};
  app.use(mcpAuthMetadataRouter({oauthMetadata:createOAuthMetadata(options), resourceServerUrl:new URL('/mcp',provider.issuer), scopesSupported:['whoop:read'], resourceName:'Functional Strength WHOOP'}));
  app.use(mcpAuthRouter({...options, resourceServerUrl:new URL('/mcp',provider.issuer), resourceName:'Functional Strength WHOOP'}));
  if (provider.resources.has(new URL('/hevy/mcp',provider.issuer).href)) {
    app.use(mcpAuthMetadataRouter({oauthMetadata:createOAuthMetadata(options), resourceServerUrl:new URL('/hevy/mcp',provider.issuer), scopesSupported:['hevy:manage'], resourceName:'Functional Strength Hevy'}));
  }
  app.post('/connect',express.urlencoded({extended:false,limit:'4kb'}),provider.consent);
}
