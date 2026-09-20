import type { Express } from 'express';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { PersonalOAuth } from './mcp-oauth.js';

/** Fixed upstream only; caller credentials are never forwarded to Hevy. */
export function installHevyProxy(app: Express, oauth: PersonalOAuth, endpoint: string, token: string) {
  const upstream = new URL(endpoint);
  if (upstream.protocol !== 'https:' || token.length < 32) throw new Error('Invalid Hevy upstream configuration');
  app.use('/hevy/mcp', oauth.guard(new URL('/hevy/mcp',oauth.issuer)));
  app.all('/hevy/mcp', async (req,res) => {
    if (!['POST','GET','DELETE'].includes(req.method)) { res.sendStatus(405); return; }
    const abort = new AbortController();
    res.on('close', () => abort.abort());
    const headers: Record<string,string> = {Authorization:'Bearer '+token,Accept:'application/json, text/event-stream'};
    for (const name of ['mcp-session-id','mcp-protocol-version','last-event-id']) {
      const value = req.headers[name];
      if (typeof value === 'string') headers[name] = value;
    }
    if (req.method === 'POST') headers['Content-Type']='application/json';
    try {
      const response = await fetch(upstream,{method:req.method,headers,body:req.method === 'POST' ? JSON.stringify(req.body) : undefined,signal:abort.signal,redirect:'error'});
      res.status(response.status);
      for (const name of ['content-type','mcp-session-id','mcp-protocol-version']) {
        const value=response.headers.get(name); if(value)res.setHeader(name,value);
      }
      if (response.body) await pipeline(Readable.fromWeb(response.body as never),res);
      else res.end();
    } catch {
      if (!res.headersSent) res.status(502).json({error:'Hevy upstream unavailable'});
      else res.end();
    }
  });
}
