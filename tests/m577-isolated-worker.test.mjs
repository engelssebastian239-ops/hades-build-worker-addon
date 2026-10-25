import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const read=x=>fs.readFileSync(path.join(root,x),'utf8');

test('parallel add-ons default to PLAN off and INSTALL off with no broad Worker grants',()=>{
  const worker=read('hades_mobile_build_worker/config.yaml');
  for(const required of ['mobile_plan_enabled: false','mobile_install_enabled: false','hassio_api: false','docker_api: false','full_access: false','map: []','ports: {}','host_network: false'])assert.ok(worker.includes(required),required);
  const installer=read('hades_mobile_installer/config.yaml');
  for(const required of ['enabled: false','hassio_role: manager','docker_api: false','full_access: false','ports: {}','read_only: false'])assert.ok(installer.includes(required),required);
});

test('new Worker ships only isolated Mobile modules and Installer uses a unique slug/profile',()=>{
  const docker=read('hades_mobile_build_worker/Dockerfile');
  assert.ok(docker.includes('mobile-install-github.mjs'));assert.ok(docker.includes('mobile-credential-provisioner.mjs'));
  assert.equal(docker.includes('worker/main.mjs ./worker/main.mjs\nCOPY worker/package-stage.mjs'),false);
  assert.ok(!docker.includes('hades_build_worker/worker/main.mjs'));
  const profile=read('hades_mobile_installer/apparmor.txt');
  assert.ok(profile.includes('profile c406e920_hades_m574_installer'));
  assert.ok(profile.includes('/addons/hades_m2_mobile/Dockerfile rw'));
  assert.ok(!profile.includes('/addons/** rw'));
  const client=read('hades_mobile_build_worker/worker/mobile-install-client.mjs');
  assert.ok(client.includes('http://c406e920-hades-m574-installer:8767'));
});

test('M577 source tree parser accepts Git left-padded size fields',()=>{
  const record='100644 blob 25efc39e595922a21e6baab3baa69d87715a7610                   1967\t.github/workflows/m57-worker-validation.yml';
  const tab=record.indexOf('\t');
  const metadata=record.slice(0,tab);
  assert.match(metadata,/  +\d+$/,'Git pads the size field with leading spaces');
  const [mode,type,blob,sizeText]=metadata.trim().split(/\s+/);
  assert.equal([mode,type,blob,sizeText].length,4);
  assert.ok(Number.isSafeInteger(Number(sizeText)));
  const source=read('tools/hash-m577-source.mjs');
  assert.ok(source.includes("record.slice(0,tab).trim().split(/\\s+/)"));
});
