// Independent Node crypto/JCS check of a public, synthetic Rust test vector.
import {readFileSync} from 'node:fs';import{createPublicKey,ECDH,verify}from'node:crypto';
import assert from 'node:assert/strict';import{pathToFileURL}from'node:url';import{cardPayload,publicMultibase}from'../signed-card.mjs';
const bytes=readFileSync(process.argv[2]);assert.ok(bytes.length<32768);
const v=JSON.parse(bytes);assert.equal(v.keyOrigin,'Disposable synthetic P256; never a live DID key');
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}':JSON.stringify(value);
const point=ECDH.convertKey(Buffer.from(v.publicSec1Hex,'hex'),'prime256v1',undefined,undefined,'uncompressed');
const key=createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')}});
assert.equal(publicMultibase(key),v.publicPin);const card=v.signedCard,{signatures,...unsigned}=card;
assert.deepEqual(unsigned,v.template);assert.ok(unsigned.securitySchemes.atprotoService.httpAuthSecurityScheme);
assert.deepEqual(unsigned.securityRequirements,[{schemes:{atprotoService:{}}}]);assert.equal(Object.hasOwn(unsigned,'security'),false);
const header=signatures[0].protected;const payload=Buffer.from(canonical(unsigned)).toString('base64url');
assert.equal(verify('sha256',Buffer.from(header+'.'+payload),{key,dsaEncoding:'ieee-p1363'},Buffer.from(signatures[0].signature,'base64url')),true);
if(process.env.KODY_CANONICALIZE_MODULE){const library=(await import(pathToFileURL(process.env.KODY_CANONICALIZE_MODULE).href)).default;assert.equal(library(unsigned),canonical(unsigned));}
assert.notEqual(cardPayload(card),payload,'legacy recursive-empty profile must not silently verify this Card');
assert.equal(verify('sha256',Buffer.from(header+'.'+cardPayload(card)),{key,dsaEncoding:'ieee-p1363'},Buffer.from(signatures[0].signature,'base64url')),false);
console.log(JSON.stringify({sameProductionDid:true,syntheticKeyOnly:true,nativeSignatureVerifiedByNode:true,standardSecurityRequirementPreserved:true,legacyEmptyRemovalNotAccepted:true,liveKeyUsed:false}));
