// Match the upstream tiny profile; the default server settings exceed 3 GiB.
export const runtimeArgs = [
  '--shards', '1', '--spaces', '--memory-budget-mb', '3072',
  '--max-exports', '4', '--firehose-max-backfills', '4',
  '--lazy-mst-node-cache-mb', '64', '--firehose-ring-mb', '64',
  '--firehose-merge-queue-mb', '32', '--firehose-max-lag-mb', '64',
  '--live-ring-mb', '32', '--backfill-readahead-mb', '16',
  '--backfill-cache-mb', '32', '--firehose-threads', '1',
];

export interface AgentRuntimeConfig { AGENT_A2A_SIGNED_CARD_JSON?: string; AGENT_A2A_CARD_KEY_MULTIBASE?: string; AGENT_A2A_ENABLED?: string; AGENT_A2A_RUNTIME?: string; AGENT_A2A_CALLER_DID?: string; AGENT_A2A_BRIDGE_KEY?: string; AGENT_A2A_KODY_TOKEN?: string; AGENT_A2A_CAPACITY?: string }
export function agentEnvironment(e: AgentRuntimeConfig): Record<string,string> {
 if (e.AGENT_A2A_ENABLED !== "true") return {};
 const capacity=e.AGENT_A2A_CAPACITY ?? "1000";
 if(!e.AGENT_A2A_SIGNED_CARD_JSON || e.AGENT_A2A_SIGNED_CARD_JSON.length>8192 || !e.AGENT_A2A_CARD_KEY_MULTIBASE?.startsWith("z") || e.AGENT_A2A_CARD_KEY_MULTIBASE.length>128) throw new Error("Production signed Card required");
 try { JSON.parse(e.AGENT_A2A_SIGNED_CARD_JSON); } catch { throw new Error("Invalid signed Card JSON"); }
 if(e.AGENT_A2A_RUNTIME !== "native-profile-v1" || e.AGENT_A2A_CALLER_DID !== "did:plc:vsgwub3c3pupqt3yhxfmecma" || !/^[a-f0-9]{64}$/.test(e.AGENT_A2A_BRIDGE_KEY ?? "") || !e.AGENT_A2A_KODY_TOKEN?.startsWith("kody_at_") || !/^\d{1,6}$/.test(capacity) || Number(capacity)<1 || Number(capacity)>100000) throw new Error("Invalid native agent configuration");
 return {VLPDS_AGENT_A2A_SIGNED_CARD:e.AGENT_A2A_SIGNED_CARD_JSON,VLPDS_AGENT_A2A_CARD_KEY:e.AGENT_A2A_CARD_KEY_MULTIBASE,VLPDS_AGENT_A2A_ENABLED:"true",VLPDS_AGENT_A2A_CALLER:e.AGENT_A2A_CALLER_DID,VLPDS_AGENT_BRIDGE_KEY:e.AGENT_A2A_BRIDGE_KEY!,VLPDS_AGENT_KODY_TOKEN:e.AGENT_A2A_KODY_TOKEN,VLPDS_AGENT_A2A_CAPACITY:capacity};
}
export function runtimeEntrypoint(agentEnabled = false): string[] {
 return agentEnabled ? ["/usr/bin/tini","--","/usr/local/bin/node","/opt/agent-contact-pilot/production/supervisor.mjs",...runtimeArgs] : ["/usr/bin/tini","--","vlpds",...runtimeArgs];
}
