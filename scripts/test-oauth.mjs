import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import express from 'express';
import {PersonalOAuth,installOAuth} from '../dist/mcp-oauth.js';
import {installHevyProxy} from '../dist/hevy-proxy.js';

const dir=mkdtempSync(join(tmpdir(),'fitness-oauth-'));
const issuer=new URL('https://fitness.example.test/');
const secret=randomBytes(32).toString('hex');
const encryption=randomBytes(32).toString('hex');
let provider=new PersonalOAuth(issuer,join(dir,'oauth.db'),secret,encryption,true);
const app=express();
app.use(express.json());
installOAuth(app,provider);
app.get('/mcp',provider.guard(new URL('/mcp',issuer)),(_req,res)=>res.json({ok:true}));
const upstreamSecret=randomBytes(32).toString('hex');
installHevyProxy(app,provider,'https://hevy.example.test/mcp',upstreamSecret);
const realFetch=globalThis.fetch;
globalThis.fetch=async(url,options)=>{
  if(String(url)==='https://hevy.example.test/mcp') {
    assert.equal(options.headers.Authorization,'Bearer '+upstreamSecret);
    assert.equal(options.headers['mcp-session-id'],'session-test');
    assert.equal(options.redirect,'error');
    return new Response('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n',{headers:{'content-type':'text/event-stream','mcp-session-id':'session-test'}});
  }
  return realFetch(url,options);
};
const server=app.listen(0,'127.0.0.1');
await new Promise(r=>server.once('listening',r));
const root='http://127.0.0.1:'+server.address().port;
const req=(path,opts={})=>fetch(root+path,{redirect:'manual',...opts});
const post=(path,data,headers={})=>req(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams(data)});
const redirect='https://chatgpt.com/connector/oauth/fixture';
try {
  let r=await req('/mcp'); assert.equal(r.status,401); assert.match(r.headers.get('www-authenticate'),/resource_metadata/);
  r=await req('/.well-known/oauth-protected-resource/mcp');assert.deepEqual((await r.json()).scopes_supported,['whoop:read']);
  r=await req('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uris:['https://attacker.example/callback'],token_endpoint_auth_method:'none'})});assert.equal(r.status,400);
  r=await req('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uris:[redirect],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']})});assert.equal(r.status,201);
  const client=await r.json();
  const verifier=randomBytes(32).toString('base64url');
  const challenge=createHash('sha256').update(verifier).digest('base64url');
  async function flow(resource='/mcp',scope='whoop:read') {
    const q=new URLSearchParams({client_id:client.client_id,response_type:'code',redirect_uri:redirect,scope,resource:issuer.origin+resource,code_challenge:challenge,code_challenge_method:'S256',state:'test-state'});
    const r=await req('/authorize?'+q);assert.equal(r.status,200);
    return {cookie:r.headers.get('set-cookie').split(';')[0],id:(await r.text()).match(/name="flow" value="([^"]+)"/)[1]};
  }
  let f=await flow();r=await post('/connect',{flow:f.id,password:secret},{Origin:issuer.origin});assert.equal(r.status,403);
  f=await flow();r=await post('/connect',{flow:f.id,password:'wrong'},{Cookie:f.cookie,Origin:issuer.origin});assert.equal(r.status,403);
  f=await flow();r=await post('/connect',{flow:f.id,password:secret},{Cookie:f.cookie,Origin:'https://attacker.example'});assert.equal(r.status,403);
  f=await flow();r=await post('/connect',{flow:f.id,password:secret},{Cookie:f.cookie,Origin:issuer.origin});assert.equal(r.status,303);
  const callback=new URL(r.headers.get('location'));assert.equal(callback.searchParams.get('state'),'test-state');
  const data={grant_type:'authorization_code',client_id:client.client_id,code:callback.searchParams.get('code'),code_verifier:verifier,redirect_uri:redirect,resource:issuer.origin+'/mcp'};
  r=await post('/token',{...data,code_verifier:randomBytes(32).toString('base64url')});assert.equal(r.status,400);
  r=await post('/token',{...data,resource:issuer.origin+'/hevy/mcp'});assert.equal(r.status,400);
  r=await post('/token',data);assert.equal(r.status,200);const first=await r.json();
  r=await req('/mcp',{headers:{Authorization:'Bearer '+first.access_token}});assert.equal(r.status,200);
  r=await req('/hevy/mcp',{headers:{Authorization:'Bearer '+first.access_token}});assert.equal(r.status,401);
  f=await flow('/hevy/mcp','hevy:manage');r=await post('/connect',{flow:f.id,password:secret},{Cookie:f.cookie,Origin:issuer.origin});assert.equal(r.status,303);
  const hevyCode=new URL(r.headers.get('location')).searchParams.get('code');
  r=await post('/token',{...data,code:hevyCode,resource:issuer.origin+'/hevy/mcp'});assert.equal(r.status,200);const hevyTokens=await r.json();
  r=await req('/hevy/mcp',{method:'POST',headers:{Authorization:'Bearer '+hevyTokens.access_token,'Content-Type':'application/json','mcp-session-id':'session-test'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
  assert.equal(r.status,200);assert.equal(r.headers.get('mcp-session-id'),'session-test');assert.match(await r.text(),/event: message/);
  r=await req('/mcp',{headers:{Authorization:'Bearer '+hevyTokens.access_token}});assert.equal(r.status,401);
  // Restart the provider against the same database: clients and grants persist.
  provider.close();provider=new PersonalOAuth(issuer,join(dir,'oauth.db'),secret,encryption,true);
  assert.equal(provider.clientsStore.getClient(client.client_id).client_id,client.client_id);
  await provider.verifyAccessToken(first.access_token);
  const second=await provider.exchangeRefreshToken(client,first.refresh_token,undefined,new URL('/mcp',issuer));
  assert.notEqual(second.refresh_token,first.refresh_token);
  await assert.rejects(provider.exchangeRefreshToken(client,first.refresh_token,undefined,new URL('/mcp',issuer)));
  await assert.rejects(provider.verifyAccessToken(second.access_token));
  await assert.rejects(provider.exchangeAuthorizationCode(client,data.code,undefined,redirect,new URL('/mcp',issuer)));
  console.log('PASS: metadata, restricted registration, consent/CSRF/password, PKCE, audience binding, Hevy credential isolation/session streaming, persistence, refresh rotation/replay, code replay');
} finally {globalThis.fetch=realFetch;server.close();provider.close();rmSync(dir,{recursive:true,force:true});}
