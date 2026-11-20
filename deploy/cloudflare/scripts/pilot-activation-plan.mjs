// Pure planning and injected secret-transfer seam. No network, process spawn,
// filesystem writes, environment reads, or live CLI entrypoint.
export const PILOT = Object.freeze({
  digest: 'sha256:2e254f9394937be2141e192b715f88867a349bbd85c80d9279e435282b11161d',
  revision: '21117d08d00b6d1bb95430c0cc4a89eb5ec59785',
  offWorker: '7572d63f-a93e-4bb3-876a-bba6348cba7e',
  caller: 'did:plc:vsgwub3c3pupqt3yhxfmecma',
  org: 'c74cb336bbed5cca02db72fff3998b10f977c015aab112f0878d421d55d15ecf',
  profile: 'prf_642a5cf465fa4528a8f7e075f29557c4',
  cardHash: 'f02d7b8eb0a81f42fa8b3bcde924af57bc5a21bb4f768e9bff782d51fd4db94f',
  cardKey: 'zDnaeyNSrMXCKbWdCmMWCcPv8qCCXGzQs3JLwH4KUWcq8ogna',
});
const fail = () => { throw new Error('Pilot planning gate refused'); };
export function normalizeCredentialMetadata(raw, {now,expectedOrg}) {
  // The custodian must remove the one-time token value before passing metadata.
  const allowed=['id','created_at','expires_at','max_expires_at','idle_ttl_seconds','profile_id','org_binding','org_id','scopes','status'];
  if (expectedOrg!==PILOT.org || !raw || !exact(Object.keys(raw).sort(),allowed.sort()) || typeof expectedOrg!=='string' || !/^[A-Za-z0-9_-]{1,128}$/.test(expectedOrg) ||
      raw.org_id!==expectedOrg || raw.status!=='active' || raw.profile_id!==PILOT.profile || raw.org_binding!=='org' ||
      !exact(raw.scopes,['org:execute']) || raw.idle_ttl_seconds!==900 || typeof raw.id!=='string' || !/^[A-Za-z0-9_-]{1,128}$/.test(raw.id)) fail();
  const seconds=value=>{if(typeof value!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value)) fail();const ms=Date.parse(value);if(!Number.isFinite(ms))fail();return Math.floor(ms/1000);};
  const issuedAt=seconds(raw.created_at),expiresAt=seconds(raw.expires_at),maxExpiresAt=seconds(raw.max_expires_at);
  if (!fresh(issuedAt,now,600) || expiresAt<=now || expiresAt>Math.min(now+900,maxExpiresAt) || maxExpiresAt<=now || maxExpiresAt>issuedAt+3600) fail();
  return {id:raw.id,idleSeconds:900,maxSeconds:3600,orgBinding:'org',profileId:PILOT.profile,scopes:['org:execute'],issuedAt,expiresAt,maxExpiresAt};
}
const exact = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const fresh = (at,now,age=30) => Number.isSafeInteger(at) && at<=now && now-at<=age;

// Evidence is an input contract, NOT an authentication mechanism. Future runner
// must independently fetch/authenticate it immediately before each mutation.
export function activationPlan({account,now,evidence,credential}) {
  if (!/^[a-f0-9]{32}$/.test(account??'') || !Number.isSafeInteger(now)) fail();
  const image=`registry.cloudflare.com/${account}/vlpds@${PILOT.digest}`;
  const e=evidence;
  if (!e || !fresh(e.checkedAt,now) || e.desired!==image || e.current!==image || e.running!==true ||
      e.runtime!=='native-profile-v1' || e.revision!==PILOT.revision || e.platform!=='linux/amd64' ||
      e.workerVersion!==PILOT.offWorker || e.enabled!==false || e.agentSecretBindings!==0 ||
      !exact(e.publicChecks,{health:200,ui:200,card:404}) || e.cardCurrentKey!==PILOT.cardKey ||
      e.cardSignatureVerified!==true || e.cardSha256!==PILOT.cardHash) fail();
  // Metadata only; reject token/extra fields. No credential needed for preflight.
  if (credential) {
    if (!exact(Object.keys(credential).sort(),['id','idleSeconds','maxSeconds','orgBinding','profileId','scopes','issuedAt','expiresAt','maxExpiresAt'].sort()) ||
        typeof credential.id!=='string' || !/^[A-Za-z0-9_-]{1,128}$/.test(credential.id) || credential.profileId!==PILOT.profile ||
        credential.orgBinding!=='org' || !exact(credential.scopes,['org:execute']) ||
        credential.idleSeconds!==900 || credential.maxSeconds!==3600 || !fresh(credential.issuedAt,now,600) ||
        !Number.isSafeInteger(credential.expiresAt) || !Number.isSafeInteger(credential.maxExpiresAt) ||
        credential.expiresAt<=now || credential.maxExpiresAt<=now || credential.expiresAt>now+900 ||
        credential.maxExpiresAt>credential.issuedAt+3600 || credential.expiresAt>credential.maxExpiresAt) fail();
  }
  return {
    version:1, executable:false, image, caller:PILOT.caller,
    vars:{AGENT_A2A_ENABLED:'true',AGENT_A2A_RUNTIME:'native-profile-v1',
      AGENT_A2A_CALLER_DID:PILOT.caller,AGENT_A2A_CAPACITY:'1000',
      AGENT_A2A_SIGNED_CARD_JSON_SOURCE:`verified-artifact-sha256:${PILOT.cardHash}`,AGENT_A2A_CARD_KEY_MULTIBASE:PILOT.cardKey},
    tokenRequest:{name:'EXP-710 identity-test first activation',scopes:['org:execute'],org_binding:'org',
      profile_id:PILOT.profile,idle_ttl_seconds:900,max_lifetime_seconds:3600},
    secretNames:['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN'],
    deadline:credential?.maxExpiresAt??null,
    steps:['approval','fresh-off-preflight','mint-and-validate-metadata','provision-while-off',
      'verify-off-after-provision','review-new-worker-artifact-binding','activate-with-guarded-restart',
      'otto-acceptance','disable-edge-and-runtime','revoke-confirm','remove-new-bindings-verify-off'],
    rollback:{image,preserve:['account-data','durable-object','S3','CAS-and-pending'],
      revokeTokenId:credential?.id??null,deleteOnly:['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN']},
  };
}

// Injected transport must implement a reviewed pinned Wrangler secret-bulk stdin
// child. This module intentionally cannot select a process, endpoint or token.
// Values never enter argv/childEnv/return value/errors; Buffer is wiped afterward.
// JS strings and transport copies cannot be reliably zeroized; runner is ephemeral.
export async function transferSecrets({bridgeKey,profileToken,cloudflareToken,account}, transport) {
  if (typeof transport!=='function' || !/^[a-f0-9]{64}$/.test(bridgeKey??'') ||
      typeof profileToken!=='string' || !/^kody_at_[A-Za-z0-9_-]{8,4096}$/.test(profileToken) ||
      !/^[A-Za-z0-9_-]{20,256}$/.test(cloudflareToken??'') || !/^[a-f0-9]{32}$/.test(account??'')) fail();
  const stdin=Buffer.from(JSON.stringify({AGENT_A2A_BRIDGE_KEY:bridgeKey,AGENT_A2A_KODY_TOKEN:profileToken}));
  try {
    // Transport handles all raw child output privately; only exact boolean ACK
    // crosses this seam. An ambiguous call is never retried here.
    if (await transport({stdin,args:['secret','bulk','--name','crate-pds'],
      childEnv:{CLOUDFLARE_API_TOKEN:cloudflareToken,CLOUDFLARE_ACCOUNT_ID:account}})!==true) fail();
    return {transferred:true,names:['AGENT_A2A_BRIDGE_KEY','AGENT_A2A_KODY_TOKEN']};
  } catch { throw new Error('Pilot secret transfer failed; do not retry automatically'); }
  finally { stdin.fill(0); }
}
export function sanitizedPlan(plan) {
  return {version:plan.version,executable:false,digest:PILOT.digest,caller:PILOT.caller,
    secretNames:plan.secretNames,deadline:plan.deadline,steps:plan.steps};
}
