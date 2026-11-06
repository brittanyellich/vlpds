import { DurableObject } from "cloudflare:workers";
import { permitted, forwarded } from "./routing.ts";
import { runtimeArgs } from "./runtime.ts";

interface Env {
  PDS: DurableObjectNamespace<Pds>;
  PUBLIC_HOST: string;
  HANDLE_DOMAIN: string;
  S3_BUCKET: string;
  S3_PREFIX: string;
  ENABLED: string;
  CF_ACCOUNT_ID: string;
  S3_ACCESS_KEY: string;
  S3_SECRET_KEY: string;
  JWT_SECRET: string;
  ADMIN_TOKEN: string;
  INTERNAL_TOKEN: string;
  KEK: string;
  PLC_ROTATION_KEY_HEX: string;
  PLC_RECOVERY_DID_KEY: string;
  EMAIL_FROM_ADDRESS: string;
  EMAIL_API_URL: string;
  EMAIL_API_TOKEN: string;
}

// Never change this name for an existing bucket/prefix: all traffic owns one instance.
const INSTANCE = "crate-pds-single";
const INACTIVITY_MS = 60 * 60 * 1000;
const HEARTBEAT_MS = 5 * 60 * 1000;

export class Pds extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    if (ctx.container?.running) {
      void ctx.blockConcurrencyWhile(() => ctx.container!.setInactivityTimeout(INACTIVITY_MS));
    }
  }

  private async ensureRunning(): Promise<void> {
    if (this.env.ENABLED !== "true") throw new Error("Deployment is not enabled");
    const c = this.ctx.container!;
    if (!c.running) {
      const env = this.environment();
      c.start({ image: c.images.pds, instance: "standard-3", enableInternet: true, env,
        entrypoint: ["/usr/bin/tini", "--", "vlpds", ...runtimeArgs] });
    }
    await c.setInactivityTimeout(INACTIVITY_MS);
    await this.ctx.storage.setAlarm(Date.now() + HEARTBEAT_MS);
  }

  private environment(): Record<string, string> {
    const e = this.env;
    const values: Record<string, string> = {
      VLPDS_PUBLIC_URL: `https://${e.PUBLIC_HOST}`,
      VLPDS_HANDLE_DOMAIN: e.HANDLE_DOMAIN,
      VLPDS_SERVICE_DID: `did:web:${e.PUBLIC_HOST}`,
      VLPDS_S3_ENDPOINT: `https://${e.CF_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      VLPDS_S3_REGION: "auto", VLPDS_S3_BUCKET: e.S3_BUCKET, VLPDS_PREFIX: e.S3_PREFIX,
      VLPDS_S3_ACCESS_KEY: e.S3_ACCESS_KEY, VLPDS_S3_SECRET_KEY: e.S3_SECRET_KEY,
      VLPDS_JWT_SECRET: e.JWT_SECRET, VLPDS_ADMIN_TOKEN: e.ADMIN_TOKEN,
      VLPDS_INTERNAL_TOKEN: e.INTERNAL_TOKEN, VLPDS_KEK: e.KEK,
      VLPDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX: e.PLC_ROTATION_KEY_HEX,
      VLPDS_PLC_RECOVERY_DID_KEY: e.PLC_RECOVERY_DID_KEY,
      VLPDS_EMAIL_FROM_ADDRESS: e.EMAIL_FROM_ADDRESS,
      VLPDS_EMAIL_API_URL: e.EMAIL_API_URL, VLPDS_EMAIL_API_TOKEN: e.EMAIL_API_TOKEN,
      VLPDS_SPACES: "true", VLPDS_INVITE_REQUIRED: "true",
      VLPDS_NODE_ID: "single", VLPDS_SHARDS: "1", VLPDS_LEASE_TTL_MS: "60000",
      VLPDS_SLATEDB_MANIFEST_POLL: "60s", VLPDS_MEMORY_BUDGET_MB: "3072",
      VLPDS_CACHE_DIR: "/var/lib/vlpds/cache", VLPDS_DISK_CACHE_MB: "1024",
      VLPDS_METRICS_LISTEN: "0.0.0.0:9583", VLPDS_LOG_FORMAT: "json",
    };
    for (const [key, value] of Object.entries(values)) {
      if (!value) throw new Error(`Missing required configuration: ${key}`);
    }
    if (!/^[a-f0-9]{32}$/.test(e.CF_ACCOUNT_ID)) throw new Error("Invalid Cloudflare account ID");
    return values;
  }

  async alarm(): Promise<void> {
    if (this.env.ENABLED !== "true") {
      if (this.ctx.container?.running) this.ctx.container.signal(15);
      return;
    }
    // Schedule before startup so a failed start does not lose the recovery heartbeat.
    await this.ctx.storage.setAlarm(Date.now() + HEARTBEAT_MS);
    await this.ensureRunning();
  }

  async fetch(request: Request): Promise<Response> {
    if (!permitted(new URL(request.url), this.env.PUBLIC_HOST, this.env.HANDLE_DOMAIN)) return new Response("Not found", { status: 404 });
    if (this.env.ENABLED !== "true") return new Response("Deployment pending preflight", { status: 503 });
    await this.ensureRunning();
    const port = this.ctx.container!.getTcpPort(2583);
    // Probe separately: retrying a user's POST after a connection failure could duplicate a write.
    try {
      const health = await port.fetch("http://container/xrpc/_health", { signal: AbortSignal.timeout(5000) });
      await health.body?.cancel();
      if (!health.ok) return new Response("PDS starting", { status: 503, headers: { "Retry-After": "5" } });
    } catch {
      return new Response("PDS starting", { status: 503, headers: { "Retry-After": "5" } });
    }
    // Preserve streams and WebSocket upgrades; never buffer archives or blobs in the Worker.
    return port.fetch(request);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!permitted(new URL(request.url), env.PUBLIC_HOST, env.HANDLE_DOMAIN)) return new Response("Not found", { status: 404 });
    return env.PDS.getByName(INSTANCE).fetch(forwarded(request));
  },
} satisfies ExportedHandler<Env>;
