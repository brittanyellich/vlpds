import {createHash} from 'node:crypto';
import {prepareDeployment} from './prepare-deploy.mjs';
import {PILOT} from './pilot-activation-plan.mjs';
export function preparePilotConfig(env,card,enabled,deadline,{ownerConsentRequired=false}={}) {
 if(typeof ownerConsentRequired!=='boolean')throw new Error('Explicit consent mode required');
 const requested=JSON.parse(env.DEPLOY_CONFIG??'{}').vars?.AGENT_A2A_REQUIRE_OWNER_CONSENT;
 if(enabled&&requested==='true'&&!ownerConsentRequired)throw new Error('Consent policy cannot silently downgrade');
 if(enabled && (!Number.isSafeInteger(deadline) || deadline<=0))throw new Error('Pilot lease required');
 if(typeof enabled!=='boolean' || typeof card!=='string' || createHash('sha256').update(card).digest('hex')!==PILOT.cardHash)throw new Error('Pilot Card artifact refused');
 const image=`registry.cloudflare.com/${env.CLOUDFLARE_ACCOUNT_ID}/vlpds@${PILOT.digest}`;
 if(JSON.parse(env.DEPLOY_CONFIG??'{}').keep_vars===true)throw new Error('Pilot cannot preserve stale activation vars');
 const config=prepareDeployment({...env,OPERATION:'rollback',RUNTIME:'pds-runtime',ROLLBACK_IMAGE:image});
 // OFF always removes the temporary policy binding; private consent rows survive.
 delete config.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT;
 if(enabled&&ownerConsentRequired)config.vars.AGENT_A2A_REQUIRE_OWNER_CONSENT='true';
 config.vars.AGENT_A2A_ENABLED=enabled?'true':'false';config.vars.AGENT_A2A_RUNTIME='native-profile-v1';
 for(const key of ['AGENT_A2A_EXPIRES_AT','AGENT_A2A_CALLER_DID','AGENT_A2A_CAPACITY','AGENT_A2A_SIGNED_CARD_JSON','AGENT_A2A_CARD_KEY_MULTIBASE'])delete config.vars[key];
 if(enabled)Object.assign(config.vars,{AGENT_A2A_EXPIRES_AT:String(deadline),AGENT_A2A_CALLER_DID:PILOT.caller,AGENT_A2A_CAPACITY:'1000',AGENT_A2A_SIGNED_CARD_JSON:card,AGENT_A2A_CARD_KEY_MULTIBASE:PILOT.cardKey});
 return config;
}
