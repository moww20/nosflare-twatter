import { NostrEvent, NostrFilter, RateLimiter, WebSocketSession, Env, DOBroadcastRequest } from './types';
import {
  PUBKEY_RATE_LIMIT,
  REQ_RATE_LIMIT,
  PAY_TO_RELAY_ENABLED,
  isPubkeyAllowed,
  isEventKindAllowed,
  containsBlockedContent,
  isTagAllowed,
  excludedRateLimitKinds
} from './config';
import { verifyEventSignature, hasPaidForRelay, processEvent, queryEventsWithArchive } from './relay-worker';
import { SimplePool, Filter } from 'nostr-tools';

// Session attachment data structure
interface SessionAttachment {
  sessionId: string;
  bookmark: string;
  host: string;
  doName: string;
}

export class RelayWebSocket implements DurableObject {
  private sessions: Map<string, WebSocketSession>;
  private env: Env;
  private state: DurableObjectState;
  private region: string;
  private doId: string;
  private doName: string;
  private processedEvents: Map<string, number> = new Map(); // eventId -> timestamp
  private upstreamPool: SimplePool | null = null;
  private upstreamRelays: string[] = [];
  private upstreamSince: Record<string, number> = { k0: 0, k3: 0, kcomm: 0, kcontent: 0 };
  private upstreamSubsCloser: any | null = null;
  private relayHealth: Map<string, { ok: number; fail: number; backoffMs: number; nextAt: number }>; 

  // Define allowed endpoints
  private static readonly ALLOWED_ENDPOINTS = [
    'relay-WNAM-primary',  // Western North America
    'relay-ENAM-primary',  // Eastern North America
    'relay-WEUR-primary',  // Western Europe
    'relay-EEUR-primary',  // Eastern Europe
    'relay-APAC-primary',  // Asia-Pacific
    'relay-OC-primary',    // Oceania
    'relay-SAM-primary',   // South America (redirects to enam)
    'relay-AFR-primary',   // Africa (redirects to weur)
    'relay-ME-primary'     // Middle East (redirects to eeur)
  ];

  // Map endpoints to their proper location hints
  private static readonly ENDPOINT_HINTS: Record<string, string> = {
    'relay-WNAM-primary': 'wnam',
    'relay-ENAM-primary': 'enam',
    'relay-WEUR-primary': 'weur',
    'relay-EEUR-primary': 'eeur',
    'relay-APAC-primary': 'apac',
    'relay-OC-primary': 'oc',
    'relay-SAM-primary': 'enam',  // SAM redirects to ENAM
    'relay-AFR-primary': 'weur',   // AFR redirects to WEUR
    'relay-ME-primary': 'eeur'     // ME redirects to EEUR
  };

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.sessions = new Map();
    this.env = env;
    this.doId = crypto.randomUUID();
    this.region = 'unknown';
    this.doName = 'unknown';
    this.processedEvents = new Map();
    this.relayHealth = new Map();
    // Initialize upstream relays from config/env (top 20)
    try {
      const envList = (env as any).UPSTREAM_RELAYS as string | undefined;
      const defaults = [
        'wss://relay.damus.io','wss://relay.primal.net','wss://nos.lol','wss://relay.snort.social','wss://eden.nostr.land',
        'wss://nostr.wine','wss://relay.nostr.band','wss://nostr.mom','wss://purplepag.es','wss://nostr.w3ird.tech',
        'wss://relay.nostr.net','wss://relay.current.fyi','wss://nostr-relay.siamstr.com','wss://relay.nostr.bg','wss://relay.wavlake.com',
        'wss://nostr.vulpem.com','wss://relay.orangepill.dev','wss://relay.nostr.it','wss://relay.nostrich.land','wss://relay.kronkltd.net'
      ];
      const list = [...new Set(String(envList||'').split(',').map(s=>s.trim()).filter(Boolean).concat(defaults))];
      this.upstreamRelays = list.slice(0, 20);
    } catch { this.upstreamRelays = []; }
    try { this.state.blockConcurrencyWhile(async () => { await this.initUpstream(); await this.startPersistentUpstream(); }); } catch {}
  }

  // Storage helper methods for subscriptions
  private async saveSubscriptions(sessionId: string, subscriptions: Map<string, NostrFilter[]>): Promise<void> {
    const key = `subs:${sessionId}`;
    const data = Array.from(subscriptions.entries());
    await this.state.storage.put(key, data);
  }

  private async loadSubscriptions(sessionId: string): Promise<Map<string, NostrFilter[]>> {
    const key = `subs:${sessionId}`;
    const data = await this.state.storage.get<[string, NostrFilter[]][]>(key);
    return new Map(data || []);
  }

  private async deleteSubscriptions(sessionId: string): Promise<void> {
    const key = `subs:${sessionId}`;
    await this.state.storage.delete(key);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Extract and set DO name from URL if provided
    const urlDoName = url.searchParams.get('doName');
    if (urlDoName && urlDoName !== 'unknown' && RelayWebSocket.ALLOWED_ENDPOINTS.includes(urlDoName)) {
      this.doName = urlDoName;
    }

    // DO-to-DO broadcast endpoint
    if (url.pathname === '/do-broadcast') {
      return await this.handleDOBroadcast(request);
    }

    // Handle WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    // Extract region info and DO name
    this.region = url.searchParams.get('region') || this.region || 'unknown';
    const colo = url.searchParams.get('colo') || 'default';

    console.log(`WebSocket connection to DO: ${this.doName} (region: ${this.region}, colo: ${colo})`);

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    // Create session data
    const sessionId = crypto.randomUUID();
    const host = request.headers.get('host') || url.host;

    // Serialize and attach minimal session data to the WebSocket
    const attachment: SessionAttachment = {
      sessionId,
      bookmark: 'first-unconstrained',
      host,
      doName: this.doName
    };
    server.serializeAttachment(attachment);

    // Use hibernatable WebSocket accept
    this.state.acceptWebSocket(server);

    console.log(`New WebSocket session: ${sessionId} on DO ${this.doName}`);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // WebSocket Hibernation API handler methods
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string): Promise<void> {
    const attachment = ws.deserializeAttachment() as SessionAttachment | null;
    if (!attachment) {
      console.error('No session attachment found');
      ws.close(1011, 'Session not found');
      return;
    }

    // Get or recreate session
    let session = this.sessions.get(attachment.sessionId);
    if (!session) {
      // Restore DO name from attachment
      if (attachment.doName && this.doName === 'unknown') {
        this.doName = attachment.doName;
      }
      // Load subscriptions from storage
      const subscriptions = await this.loadSubscriptions(attachment.sessionId);

      // Recreate session from attachment
      session = {
        id: attachment.sessionId,
        webSocket: ws,
        subscriptions,
        pubkeyRateLimiter: new RateLimiter(PUBKEY_RATE_LIMIT.rate, PUBKEY_RATE_LIMIT.capacity),
        reqRateLimiter: new RateLimiter(REQ_RATE_LIMIT.rate, REQ_RATE_LIMIT.capacity),
        bookmark: attachment.bookmark,
        host: attachment.host
      };
      this.sessions.set(attachment.sessionId, session);
    }

    try {
      let parsedMessage: any;

      if (typeof message === 'string') {
        parsedMessage = JSON.parse(message);
      } else {
        const decoder = new TextDecoder();
        const text = decoder.decode(message);
        parsedMessage = JSON.parse(text);
      }

      await this.handleMessage(session, parsedMessage);

      // Update attachment with latest session state
      const updatedAttachment: SessionAttachment = {
        sessionId: session.id,
        bookmark: session.bookmark,
        host: session.host,
        doName: this.doName
      };
      ws.serializeAttachment(updatedAttachment);

    } catch (error) {
      console.error('Error handling message:', error);
      if (error instanceof SyntaxError) {
        this.sendError(ws, 'Invalid JSON format');
      } else {
        this.sendError(ws, 'Failed to process message');
      }
    }
  }

  private async initUpstream(): Promise<void> {
    const now = Math.floor(Date.now()/1000);
    try {
      const session = this.env.RELAY_DATABASE.withSession('first-unconstrained');
      const keys = ['bookmark:k0','bookmark:k3','bookmark:kcomm','bookmark:kcontent'];
      for (const key of keys) {
        try {
          const row = await session.prepare(`SELECT value FROM system_config WHERE key=?`).bind(key).first();
          const val = Number((row as any)?.value || 0);
          if (key.endsWith('k0')) this.upstreamSince.k0 = val || (now - 3600);
          if (key.endsWith('k3')) this.upstreamSince.k3 = val || (now - 3600);
          if (key.endsWith('kcomm')) this.upstreamSince.kcomm = val || (now - 3600);
          if (key.endsWith('kcontent')) this.upstreamSince.kcontent = val || (now - 3600);
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    // Defaults
    if (!this.upstreamSince.k0) this.upstreamSince.k0 = now - 3600;
    if (!this.upstreamSince.k3) this.upstreamSince.k3 = now - 3600;
    if (!this.upstreamSince.kcomm) this.upstreamSince.kcomm = now - 3600;
    if (!this.upstreamSince.kcontent) this.upstreamSince.kcontent = now - 3600;
  }

  private groupForKind(kind: number): 'k0'|'k3'|'kcomm'|'kcontent' {
    if (kind === 0) return 'k0';
    if (kind === 3) return 'k3';
    if (kind === 34550 || kind === 4550) return 'kcomm';
    return 'kcontent';
  }

  private async updateBookmark(kind: number, createdAt: number): Promise<void> {
    try {
      const group = this.groupForKind(kind);
      if (!createdAt) return;
      if (createdAt <= (this.upstreamSince[group] || 0)) return;
      this.upstreamSince[group] = createdAt;
      const session = this.env.RELAY_DATABASE.withSession('first-primary');
      await session.prepare(`INSERT INTO system_config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`).bind(`bookmark:${group}`, String(createdAt)).run();
    } catch { /* ignore */ }
  }

  private async startPersistentUpstream(): Promise<void> {
    if (!this.upstreamRelays.length) return;
    if (!this.upstreamPool) this.upstreamPool = new SimplePool();
    const pool = this.upstreamPool as any;
    const filters: Filter[] = [
      { kinds: [0], since: this.upstreamSince.k0 },
      { kinds: [3], since: this.upstreamSince.k3 },
      { kinds: [34550,4550], since: this.upstreamSince.kcomm },
      { kinds: [1,6,7,9735], since: this.upstreamSince.kcontent }
    ] as any;
    try {
      if (this.upstreamSubsCloser) { try { this.upstreamSubsCloser.close(); } catch {} }
      this.upstreamSubsCloser = pool.subscribeMany(this.upstreamRelays, filters, {
        onevent: async (ev: any) => {
          try {
            if (!ev || typeof ev.id !== 'string') return;
            const res = await processEvent(ev, 'upstream', this.env);
            if (res?.success) await this.broadcastEvent(ev);
            if (typeof ev.created_at === 'number') await this.updateBookmark(ev.kind, ev.created_at);
          } catch { /* ignore */ }
        },
        oneose: () => { /* ignore */ }
      });
    } catch (e) {
      console.error('Upstream subscribe failed:', e);
      // Retry later
      try { setTimeout(() => { this.startPersistentUpstream().catch(()=>{}); }, 10000); } catch {}
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    const attachment = ws.deserializeAttachment() as SessionAttachment | null;
    if (attachment) {
      console.log(`WebSocket closed: ${attachment.sessionId} on DO ${this.doName}`);
      this.sessions.delete(attachment.sessionId);

      // Clean up stored subscriptions
      await this.deleteSubscriptions(attachment.sessionId);
    }
  }

  async webSocketError(ws: WebSocket, error: any): Promise<void> {
    const attachment = ws.deserializeAttachment() as SessionAttachment | null;
    if (attachment) {
      console.error(`WebSocket error for session ${attachment.sessionId}:`, error);
      this.sessions.delete(attachment.sessionId);
    }
  }

  private async handleDOBroadcast(request: Request): Promise<Response> {
    try {
      const data: DOBroadcastRequest = await request.json();
      const { event, sourceDoId } = data;

      // Prevent duplicate processing
      if (this.processedEvents.has(event.id)) {
        return new Response(JSON.stringify({ success: true, duplicate: true }));
      }

      this.processedEvents.set(event.id, Date.now());

      console.log(`DO ${this.doName} received event ${event.id} from ${sourceDoId}`);

      // Broadcast to local sessions
      await this.broadcastToLocalSessions(event);

      // Clean up old processed events periodically
      const fiveMinutesAgo = Date.now() - 300000;
      let cleaned = 0;
      for (const [eventId, timestamp] of this.processedEvents) {
        if (timestamp < fiveMinutesAgo) {
          this.processedEvents.delete(eventId);
          cleaned++;
        }
      }

      return new Response(JSON.stringify({ success: true }));
    } catch (error) {
      console.error('Error handling DO broadcast:', error);
      // @ts-ignore
      return new Response(JSON.stringify({ success: false, error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private async handleMessage(session: WebSocketSession, message: any[]): Promise<void> {
    if (!Array.isArray(message)) {
      this.sendError(session.webSocket, 'Invalid message format: expected JSON array');
      return;
    }

    const [type, ...args] = message;

    try {
      switch (type) {
        case 'EVENT':
          await this.handleEvent(session, args[0]);
          break;
        case 'REQ':
          await this.handleReq(session, message);
          break;
        case 'CLOSE':
          await this.handleCloseSubscription(session, args[0]);
          break;
        default:
          this.sendError(session.webSocket, `Unknown message type: ${type}`);
      }
    } catch (error) {
      console.error(`Error handling ${type} message:`, error);
      this.sendError(session.webSocket, `Failed to process ${type} message`);
    }
  }

  private async handleEvent(session: WebSocketSession, event: NostrEvent): Promise<void> {
    try {
      // Validate event object
      if (!event || typeof event !== 'object') {
        this.sendOK(session.webSocket, '', false, 'invalid: event object required');
        return;
      }

      // Check required fields
      if (!event.id || !event.pubkey || !event.sig || !event.created_at ||
        event.kind === undefined || !Array.isArray(event.tags) ||
        event.content === undefined) {
        this.sendOK(session.webSocket, event.id || '', false, 'invalid: missing required fields');
        return;
      }

      // Rate limiting (skip for excluded kinds)
      if (!excludedRateLimitKinds.has(event.kind)) {
        if (!session.pubkeyRateLimiter.removeToken()) {
          console.log(`Rate limit exceeded for pubkey ${event.pubkey}`);
          this.sendOK(session.webSocket, event.id, false, 'rate-limited: slow down there chief');
          return;
        }
      }

      // Verify signature
      const isValidSignature = await verifyEventSignature(event);
      if (!isValidSignature) {
        console.error(`Signature verification failed for event ${event.id}`);
        this.sendOK(session.webSocket, event.id, false, 'invalid: signature verification failed');
        return;
      }

      // Check if pay to relay is enabled
      if (PAY_TO_RELAY_ENABLED) {
        const hasPaid = await hasPaidForRelay(event.pubkey, this.env);
        if (!hasPaid) {
          const protocol = 'https:';
          const relayUrl = `${protocol}//${session.host}`;
          console.error(`Event denied. Pubkey ${event.pubkey} has not paid for relay access.`);
          this.sendOK(session.webSocket, event.id, false, `blocked: payment required. Visit ${relayUrl} to pay for relay access.`);
          return;
        }
      }

      // Check if pubkey is allowed (bypassed for kind 1059)
      if (event.kind !== 1059 && !isPubkeyAllowed(event.pubkey)) {
        console.error(`Event denied. Pubkey ${event.pubkey} is not allowed.`);
        this.sendOK(session.webSocket, event.id, false, 'blocked: pubkey not allowed');
        return;
      }

      // Check if event kind is allowed
      if (!isEventKindAllowed(event.kind)) {
        console.error(`Event denied. Event kind ${event.kind} is not allowed.`);
        this.sendOK(session.webSocket, event.id, false, `blocked: event kind ${event.kind} not allowed`);
        return;
      }

      // Check for blocked content
      if (containsBlockedContent(event)) {
        console.error('Event denied. Content contains blocked phrases.');
        this.sendOK(session.webSocket, event.id, false, 'blocked: content contains blocked phrases');
        return;
      }

      // Check tags
      for (const tag of event.tags) {
        if (!isTagAllowed(tag[0])) {
          console.error(`Event denied. Tag '${tag[0]}' is not allowed.`);
          this.sendOK(session.webSocket, event.id, false, `blocked: tag '${tag[0]}' not allowed`);
          return;
        }
      }

      // Process the event (save to database)
      const result = await processEvent(event, session.id, this.env);

      if (result.success) {
        // Send OK to the sender
        this.sendOK(session.webSocket, event.id, true, result.message);

        // Mark as processed
        this.processedEvents.set(event.id, Date.now());

        // Broadcast to all (local + remote)
        console.log(`DO ${this.doName} broadcasting event ${event.id}`);
        await this.broadcastEvent(event);

        // Blast to upstream relays as well (fan-out)
        try { await this.publishToUpstream(event); } catch {}
      } else {
        this.sendOK(session.webSocket, event.id, false, result.message);
      }

    } catch (error: any) {
      console.error('Error handling event:', error);
      this.sendOK(session.webSocket, event?.id || '', false, `error: ${error.message}`);
    }
  }

  private async handleReq(session: WebSocketSession, message: any[]): Promise<void> {
    const [_, subscriptionId, ...filters] = message;

    if (!subscriptionId || typeof subscriptionId !== 'string' || subscriptionId === '' || subscriptionId.length > 64) {
      this.sendError(session.webSocket, 'Invalid subscription ID: must be non-empty string of max 64 chars');
      return;
    }

    // Rate limiting
    if (!session.reqRateLimiter.removeToken()) {
      console.error(`REQ rate limit exceeded for subscription: ${subscriptionId}`);
      this.sendClosed(session.webSocket, subscriptionId, 'rate-limited: slow down there chief');
      return;
    }

    // Validate filters
    if (filters.length === 0) {
      this.sendClosed(session.webSocket, subscriptionId, 'error: at least one filter required');
      return;
    }

    // Validate each filter
    for (const filter of filters) {
      if (typeof filter !== 'object' || filter === null) {
        this.sendClosed(session.webSocket, subscriptionId, 'invalid: filter must be an object');
        return;
      }

      // Validate IDs format
      if (filter.ids) {
        for (const id of filter.ids) {
          if (!/^[a-f0-9]{64}$/.test(id)) {
            this.sendClosed(session.webSocket, subscriptionId, `invalid: Invalid event ID format: ${id}`);
            return;
          }
        }
      }

      // Validate authors format
      if (filter.authors) {
        for (const author of filter.authors) {
          if (!/^[a-f0-9]{64}$/.test(author)) {
            this.sendClosed(session.webSocket, subscriptionId, `invalid: Invalid author pubkey format: ${author}`);
            return;
          }
        }
      }

      // Check blocked kinds
      if (filter.kinds) {
        const blockedKinds = filter.kinds.filter((kind: number) => !isEventKindAllowed(kind));
        if (blockedKinds.length > 0) {
          console.error(`Blocked kinds in subscription: ${blockedKinds.join(', ')}`);
          this.sendClosed(session.webSocket, subscriptionId, `blocked: kinds ${blockedKinds.join(', ')} not allowed`);
          return;
        }
      }

      // Validate limits
      if (filter.ids && filter.ids.length > 5000) {
        this.sendClosed(session.webSocket, subscriptionId, 'invalid: too many event IDs (max 5000)');
        return;
      }

      if (filter.limit && filter.limit > 5000) {
        this.sendClosed(session.webSocket, subscriptionId, 'invalid: limit too high (max 5000)');
        return;
      }

      // Set default limit if not provided
      if (!filter.limit) {
        filter.limit = 5000;
      }
    }

    // Store subscription
    session.subscriptions.set(subscriptionId, filters);

    // Save to storage
    await this.saveSubscriptions(session.id, session.subscriptions);

    console.log(`New subscription ${subscriptionId} for session ${session.id} on DO ${this.doName}`);

    try {
      // Query events from database (including archive if needed)
      const result = await queryEventsWithArchive(filters, session.bookmark, this.env);

      // Update session bookmark
      if (result.bookmark) {
        session.bookmark = result.bookmark;
      }

      // Send events to client
      for (const event of result.events) {
        this.sendEvent(session.webSocket, subscriptionId, event);
      }

      // Send EOSE
      this.sendEOSE(session.webSocket, subscriptionId);

    } catch (error: any) {
      console.error(`Error processing REQ for subscription ${subscriptionId}:`, error);
      this.sendClosed(session.webSocket, subscriptionId, 'error: could not connect to the database');
    }
  }

  private async handleCloseSubscription(session: WebSocketSession, subscriptionId: string): Promise<void> {
    if (!subscriptionId) {
      this.sendError(session.webSocket, 'Invalid subscription ID for CLOSE');
      return;
    }

    const deleted = session.subscriptions.delete(subscriptionId);
    if (deleted) {
      // Save updated subscriptions to storage
      await this.saveSubscriptions(session.id, session.subscriptions);

      console.log(`Closed subscription ${subscriptionId} for session ${session.id} on DO ${this.doName}`);
      this.sendClosed(session.webSocket, subscriptionId, 'Subscription closed');
    } else {
      this.sendClosed(session.webSocket, subscriptionId, 'Subscription not found');
    }
  }

  private async broadcastEvent(event: NostrEvent): Promise<void> {
    // Broadcast to local sessions & other DOs concurrently
    await Promise.allSettled([
      this.broadcastToLocalSessions(event),
      this.broadcastToOtherDOs(event)
    ]);
  }

  private async broadcastToLocalSessions(event: NostrEvent): Promise<void> {
    let broadcastCount = 0;

    // Get all active WebSockets (including hibernated ones)
    const activeWebSockets = this.state.getWebSockets();

    for (const ws of activeWebSockets) {
      const attachment = ws.deserializeAttachment() as SessionAttachment | null;
      if (!attachment) continue;

      // Get or recreate session
      let session = this.sessions.get(attachment.sessionId);
      if (!session) {
        // Load subscriptions from storage
        const subscriptions = await this.loadSubscriptions(attachment.sessionId);

        // Recreate minimal session for broadcast
        session = {
          id: attachment.sessionId,
          webSocket: ws,
          subscriptions,
          pubkeyRateLimiter: new RateLimiter(PUBKEY_RATE_LIMIT.rate, PUBKEY_RATE_LIMIT.capacity),
          reqRateLimiter: new RateLimiter(REQ_RATE_LIMIT.rate, REQ_RATE_LIMIT.capacity),
          bookmark: attachment.bookmark,
          host: attachment.host
        };
        this.sessions.set(attachment.sessionId, session);
      }

      for (const [subscriptionId, filters] of session.subscriptions) {
        if (this.matchesFilters(event, filters)) {
          try {
            this.sendEvent(ws, subscriptionId, event);
            broadcastCount++;
          } catch (error) {
            console.error(`Error broadcasting to subscription ${subscriptionId}:`, error);
          }
        }
      }
    }

    if (broadcastCount > 0) {
      console.log(`Event ${event.id} broadcast to ${broadcastCount} local subscriptions on DO ${this.doName}`);
    }
  }

  private async broadcastToOtherDOs(event: NostrEvent): Promise<void> {
    const broadcasts: Promise<Response>[] = [];

    // Broadcast to all allowed endpoints except ourselves
    for (const endpoint of RelayWebSocket.ALLOWED_ENDPOINTS) {
      if (endpoint === this.doName) continue;

      broadcasts.push(this.sendToSpecificDO(endpoint, event));
    }

    // Execute broadcasts in parallel with timeout
    const results = await Promise.allSettled(
      broadcasts.map(p => Promise.race([
        p,
        new Promise<Response>((_, reject) =>
          setTimeout(() => reject(new Error('Broadcast timeout')), 3000)
        )
      ]))
    );

    const successful = results.filter(r => r.status === 'fulfilled').length;
    console.log(`Event ${event.id} broadcast from DO ${this.doName} to ${successful}/${broadcasts.length} remote DOs`);
  }

  private async publishToUpstream(event: NostrEvent): Promise<void> {
    if (!this.upstreamRelays.length) return;
    if (!this.upstreamPool) this.upstreamPool = new SimplePool();
    try {
      const now = Date.now();
      const relays = this.upstreamRelays.filter(r => {
        const h = this.relayHealth.get(r);
        return !h || now >= (h.nextAt || 0);
      });
      const pubs = (this.upstreamPool as any).publish(relays, event);
      const results = await Promise.allSettled(pubs);
      let ok = 0;
      results.forEach((res, i) => {
        const relay = relays[i];
        const h = this.relayHealth.get(relay) || { ok:0, fail:0, backoffMs: 0, nextAt: 0 };
        if (res.status === 'fulfilled') { h.ok++; h.backoffMs = 0; h.nextAt = 0; ok++; }
        else { h.fail++; h.backoffMs = Math.min(h.backoffMs ? h.backoffMs*2 : 500, 60000); h.nextAt = now + h.backoffMs; }
        this.relayHealth.set(relay, h);
      });
      console.log(`Event ${event.id} published to ${ok}/${relays.length} upstream relays`);
    } catch (error) {
      console.error('Error publishing to upstream relays:', error);
    }
  }

  private async sendToSpecificDO(doName: string, event: NostrEvent): Promise<Response> {
    try {
      // Ensure we're only using allowed endpoints
      if (!RelayWebSocket.ALLOWED_ENDPOINTS.includes(doName)) {
        throw new Error(`Invalid DO name: ${doName}`);
      }

      const id = this.env.RELAY_WEBSOCKET.idFromName(doName);
      const locationHint = RelayWebSocket.ENDPOINT_HINTS[doName] || 'auto';
      const stub = this.env.RELAY_WEBSOCKET.get(id, { locationHint });

      // Include the target DO name in the URL
      const url = new URL('https://internal/do-broadcast');
      url.searchParams.set('doName', doName);

      return await stub.fetch(new Request(url.toString(), {
        method: 'POST',
        body: JSON.stringify({
          event,
          sourceDoId: this.doId
        } as DOBroadcastRequest)
      }));
    } catch (error) {
      console.error(`Failed to broadcast to ${doName}:`, error);
      throw error;
    }
  }

  private matchesFilters(event: NostrEvent, filters: NostrFilter[]): boolean {
    // Fast path: group filters to reduce checks
    for (const filter of filters) {
      if (this.matchesFilter(event, filter)) return true;
    }
    return false;
  }

  private matchesFilter(event: NostrEvent, filter: NostrFilter): boolean {
    // Quick rejects by kind and time first
    if (filter.kinds && filter.kinds.length > 0 && !filter.kinds.includes(event.kind)) return false;
    if (filter.since && event.created_at < filter.since) return false;
    if (filter.until && event.created_at > filter.until) return false;

    // Check IDs
    if (filter.ids && filter.ids.length > 0 && !filter.ids.includes(event.id)) {
      return false;
    }

    // Check authors
    if (filter.authors && filter.authors.length > 0 && !filter.authors.includes(event.pubkey)) {
      return false;
    }

    // Check tag filters
    for (const [key, values] of Object.entries(filter)) {
      if (key.startsWith('#') && Array.isArray(values) && values.length > 0) {
        const tagName = key.substring(1);
        const eventTagValues = event.tags
          .filter(tag => tag[0] === tagName)
          .map(tag => tag[1]);

        // Check if any of the filter values match any of the event's tag values
        const hasMatch = values.some(v => eventTagValues.includes(v));
        if (!hasMatch) {
          return false;
        }
      }
    }

    return true;
  }

  private sendOK(ws: WebSocket, eventId: string, status: boolean, message: string): void {
    try {
      const okMessage = ['OK', eventId, status, message || ''];
      ws.send(JSON.stringify(okMessage));
    } catch (error) {
      console.error('Error sending OK:', error);
    }
  }

  private sendError(ws: WebSocket, message: string): void {
    try {
      const noticeMessage = ['NOTICE', message];
      ws.send(JSON.stringify(noticeMessage));
    } catch (error) {
      console.error('Error sending NOTICE:', error);
    }
  }

  private sendEOSE(ws: WebSocket, subscriptionId: string): void {
    try {
      const eoseMessage = ['EOSE', subscriptionId];
      ws.send(JSON.stringify(eoseMessage));
    } catch (error) {
      console.error('Error sending EOSE:', error);
    }
  }

  private sendClosed(ws: WebSocket, subscriptionId: string, message: string): void {
    try {
      const closedMessage = ['CLOSED', subscriptionId, message];
      ws.send(JSON.stringify(closedMessage));
    } catch (error) {
      console.error('Error sending CLOSED:', error);
    }
  }

  private sendEvent(ws: WebSocket, subscriptionId: string, event: NostrEvent): void {
    try {
      const eventMessage = ['EVENT', subscriptionId, event];
      ws.send(JSON.stringify(eventMessage));
    } catch (error) {
      console.error('Error sending EVENT:', error);
    }
  }
}