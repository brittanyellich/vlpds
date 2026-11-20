import { DurableObject } from "cloudflare:workers";
import { permitted, forwarded, containerRequest } from "./routing.ts";
import { OperatorGateway, operatorPath, secure } from "./operator.ts";
import { agentEnvironment, runtimeEntrypoint } from "./runtime.ts";

interface Env {
  PDS: DurableObjectNamespace<Pds>;
  PUBLIC_HOST: string;
  AGENT_A2A_ENABLED?: string;
  AGENT_A2A_RUNTIME?: string;
  AGENT_A2A_SIGNED_CARD_JSON?: string;
  AGENT_A2A_CARD_KEY_MULTIBASE?: string;
  AGENT_A2A_CALLER_DID?: string;
  AGENT_A2A_BRIDGE_KEY?: string;
  AGENT_A2A_KODY_TOKEN?: string;
  AGENT_A2A_CAPACITY?: string;
  ADMIN_HOST?: string;
  OPERATOR_DID?: string;
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
  DEPLOY_TOKEN?: string;
}

// Never change this name for an existing bucket/prefix: all traffic owns one instance.
const INSTANCE = "crate-pds-single";
const INACTIVITY_MS = 60 * 60 * 1000;
const HEARTBEAT_MS = 5 * 60 * 1000;
const DEPLOY_PATHS = new Set(["/_deploy/status", "/_deploy/restart"]);

async function deployAuthorized(request: Request, token?: string): Promise<boolean> {
  const supplied = request.headers.get("authorization")?.match(/^Bearer ([a-f0-9]{64})$/)?.[1];
  if (!token || !/^[a-f0-9]{64}$/.test(token) || !supplied) return false;
  const digest = async (value: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  const [a, b] = await Promise.all([digest(token), digest(supplied)]);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

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
        entrypoint: runtimeEntrypoint(this.env.AGENT_A2A_ENABLED === "true") });
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
      ...agentEnvironment(e),
    };
    for (const [key, value] of Object.entries(values)) {
      if (!value) throw new Error(`Missing required configuration: ${key}`);
    }
    if (!/^[a-f0-9]{32}$/.test(e.CF_ACCOUNT_ID)) throw new Error("Invalid Cloudflare account ID");
    return values;
  }

  private operator(): OperatorGateway | undefined {
    if (!this.env.ADMIN_HOST || !this.env.OPERATOR_DID) return;
    return new OperatorGateway(this.ctx.storage, {ADMIN_HOST:this.env.ADMIN_HOST, OPERATOR_DID:this.env.OPERATOR_DID, ADMIN_TOKEN:this.env.ADMIN_TOKEN});
  }

  async alarm(): Promise<void> {
    await this.operator()?.cleanup();
    if (this.env.ENABLED !== "true") {
      if (this.ctx.container?.running) this.ctx.container.signal(15);
      return;
    }
    // Schedule before startup so a failed start does not lose the recovery heartbeat.
    await this.ctx.storage.setAlarm(Date.now() + HEARTBEAT_MS);
    await this.ensureRunning();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (this.env.ADMIN_HOST && url.protocol === "https:" && !url.port &&
        url.hostname === this.env.ADMIN_HOST && DEPLOY_PATHS.has(url.pathname)) {
      if (!await deployAuthorized(request, this.env.DEPLOY_TOKEN)) return new Response("Not found", { status: 404 });
      const container = this.ctx.container!;
      const desired = container.images.pds;
      if (url.pathname === "/_deploy/status" && request.method === "GET") {
        const current = await container.inspect();
        return secure(Response.json({ desired, running: container.running, current: current?.image ?? null }));
      }
      if (url.pathname === "/_deploy/restart" && request.method === "POST") {
        if (request.headers.get("x-deploy-image") !== desired || !desired) {
          return new Response("Image mismatch", { status: 409 });
        }
        // inspect().image is not proof of which UI the running process serves.
        // A repeat deploy must actually stop the container even if its image
        // reference matches: otherwise a stale process can pass the old gate.
        const restarted = container.running;
        if (restarted) {
          // SIGTERM may produce a nonzero exit code; that still confirms exit.
          // A monitor failure without an exit code is not proof of shutdown.
          const stopped = container.monitor().then(
            () => "exited",
            (error: unknown) => typeof (error as { exitCode?: unknown })?.exitCode === "number" ? "exited" : "monitor-failed",
          );
          container.signal(15);
          let timer: ReturnType<typeof setTimeout> | undefined;
          const outcome = await Promise.race([
            stopped,
            new Promise<string>((resolve) => { timer = setTimeout(() => resolve("timeout"), 60_000); }),
          ]);
          if (timer) clearTimeout(timer);
          if (outcome !== "exited" || container.running)
            return secure(new Response("Container exit was not confirmed; no new image started", { status: 503 }));
        }
        await this.ensureRunning();
        return secure(Response.json({ restarted, desired, starting: true }, { status: 202 }));
      }
      return new Response("Method not allowed", { status: 405 });
    }
    if (this.env.ADMIN_HOST && url.hostname === this.env.ADMIN_HOST) {
      try {
        const gateway = this.operator();
        if (!gateway || this.env.ENABLED !== "true") return new Response("Unavailable", {status:503});
        return secure(await gateway.handle(request, r => this.proxy(r)));
      } catch {
        // Never log OAuth URLs, codes, tokens or SDK exception payloads.
        return secure(new Response("Sign-in unavailable. Start again from the operator homepage.", {status:502}));
      }
    }
    if (!permitted(url, this.env.PUBLIC_HOST, this.env.HANDLE_DOMAIN, this.env.AGENT_A2A_ENABLED === "true")) return new Response("Not found", { status: 404 });
    if (this.env.ENABLED !== "true") return new Response("Deployment pending preflight", { status: 503 });
    return this.proxy(request);
  }

  private async proxy(request: Request): Promise<Response> {
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
    return port.fetch(containerRequest(request));
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const admin = !!env.ADMIN_HOST && operatorPath(url, env.ADMIN_HOST);
    const deploy = !!env.ADMIN_HOST && url.protocol === "https:" && !url.port &&
      url.hostname === env.ADMIN_HOST && DEPLOY_PATHS.has(url.pathname);
    if (!admin && !deploy && !permitted(url, env.PUBLIC_HOST, env.HANDLE_DOMAIN, env.AGENT_A2A_ENABLED === "true")) return new Response("Not found", { status: 404 });
    return env.PDS.getByName(INSTANCE).fetch(forwarded(request));
  },
} satisfies ExportedHandler<Env>;
