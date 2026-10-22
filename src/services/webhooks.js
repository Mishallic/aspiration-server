import crypto from 'node:crypto';
import { hmacSha256 } from '../lib/crypto.js';

const RETRY_DELAYS_MS = [1_000, 5_000, 25_000];
const TIMEOUT_MS = 5_000;

// Signature header format: "t=<unix seconds>,v1=<hex HMAC-SHA256 of `${t}.${body}`>".
// Receivers recompute the HMAC with WEBHOOK_SECRET and reject old timestamps.
export function signPayload(secret, body, timestamp = Math.floor(Date.now() / 1000)) {
  return `t=${timestamp},v1=${hmacSha256(secret, `${timestamp}.${body}`)}`;
}

export function createWebhooks({ config, logger = console, fetchImpl = globalThis.fetch, sleep }) {
  const wait = sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms).unref?.()));
  const pending = new Set();

  async function deliver(event) {
    const body = JSON.stringify(event);
    for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt += 1) {
      try {
        const response = await fetchImpl(config.webhook.url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'webhook-id': event.id,
            'webhook-signature': signPayload(config.webhook.secret, body),
          },
          body,
          redirect: 'error',
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (response.ok) return true;
        logger.warn(`Webhook ${event.type} got HTTP ${response.status} (attempt ${attempt + 1})`);
      } catch (err) {
        logger.warn(`Webhook ${event.type} failed: ${err.message} (attempt ${attempt + 1})`);
      }
      if (attempt < RETRY_DELAYS_MS.length) await wait(RETRY_DELAYS_MS[attempt]);
    }
    logger.error(`Webhook ${event.type} ${event.id} was not delivered after retries`);
    return false;
  }

  // Fire and forget: delivery never blocks or fails the request that caused it.
  function emit(type, data) {
    if (!config.webhook) return null;
    const event = { id: crypto.randomUUID(), type, createdAt: new Date().toISOString(), data };
    const delivery = deliver(event).finally(() => pending.delete(delivery));
    pending.add(delivery);
    return event;
  }

  // Lets tests and graceful shutdown wait for in-flight deliveries.
  const flush = () => Promise.allSettled([...pending]);

  return { emit, flush };
}
