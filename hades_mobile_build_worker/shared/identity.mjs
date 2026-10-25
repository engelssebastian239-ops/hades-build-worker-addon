import {createHash,createPublicKey} from 'node:crypto';
export function identityId(key){const pub=key?.type==='public'?key:createPublicKey(key);return 'sha256:'+createHash('sha256').update(pub.export({type:'spki',format:'der'})).digest('hex');}
