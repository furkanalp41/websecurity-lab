// SPDX-License-Identifier: MIT
import type { IncomingMessage } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { loadOrCreateToken } from '../util/token.js';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 5174;
const ALLOWED_ORIGINS = new Set(['http://localhost:5173', 'http://127.0.0.1:5173']);

export interface DaemonOptions {
  host?: string;
  port?: number;
}

/**
 * Start the local control daemon. Binds to loopback only, allowlists the hub
 * origin, and requires the per-install bearer token (Authorization: Bearer ...,
 * or the `bearer.<token>` websocket subprotocol). P0 skeleton: only handles
 * `session.hello`; lab lifecycle ops arrive in a later phase.
 */
export function startDaemon(opts: DaemonOptions = {}): WebSocketServer {
  const token = loadOrCreateToken();
  const wss = new WebSocketServer({
    host: opts.host ?? DEFAULT_HOST,
    port: opts.port ?? DEFAULT_PORT,
    verifyClient: (info, done) => {
      const origin = info.origin || info.req.headers.origin || '';
      // NOTE (ui-phase-2-lab-runner): this rejects any client without an Origin
      // header, which is correct for the browser hub but will need an explicit
      // exemption (e.g. a bearer-only allowance) for a non-browser labctl WS client.
      if (!ALLOWED_ORIGINS.has(origin)) {
        done(false, 403, 'forbidden origin');
        return;
      }
      done(true);
    },
  });

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    if (!isAuthorized(req, token)) {
      ws.close(1008, 'unauthorized');
      return;
    }
    ws.on('message', (raw: WebSocket.RawData) => handleMessage(ws, raw.toString()));
  });

  return wss;
}

function isAuthorized(req: IncomingMessage, token: string): boolean {
  const auth = req.headers['authorization'];
  const bearer = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7) : undefined;
  const proto = req.headers['sec-websocket-protocol'];
  const viaProto =
    typeof proto === 'string'
      ? proto
          .split(',')
          .map((s) => s.trim())
          .find((s) => s.startsWith('bearer.'))
          ?.slice('bearer.'.length)
      : undefined;
  return (bearer ?? viaProto) === token;
}

interface Request {
  id?: string;
  op?: string;
}

function handleMessage(ws: WebSocket, raw: string): void {
  let msg: Request;
  try {
    msg = JSON.parse(raw) as Request;
  } catch {
    ws.send(JSON.stringify({ ok: false, error: 'invalid json' }));
    return;
  }
  if (msg.op === 'session.hello') {
    ws.send(
      JSON.stringify({ id: msg.id, ok: true, data: { catalog_version: 'dev', running_labs: [] } }),
    );
    return;
  }
  ws.send(JSON.stringify({ id: msg.id, ok: false, error: `unknown op: ${String(msg.op)}` }));
}
