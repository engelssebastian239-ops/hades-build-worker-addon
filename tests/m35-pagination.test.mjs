import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createGithub } from '../hades_m35_puller/m35-source/src/github.mjs';
import { runCycle } from '../hades_m35_puller/m35-source/src/worker.mjs';
import { parseTask, receiptFor } from '../hades_m35_puller/m35-source/src/task.mjs';

const owner = 'engelssebastian239-ops';
const repository = `${owner}/hades-hermes-queue`;
const config = {
  repository,
  authorizedAuthors: [owner],
  pollSeconds: 120,
  maxIssuesPerCycle: 3,
  mode: 'intake-only',
  tokenFile: '/data/hades-dev-workspace/hades-m35-secrets-20261011/github-token',
};

function issue(number) {
  return {
    number,
    title: '[HADES] Pagination fixture',
    user: { login: owner },
    body: JSON.stringify({
      version: 'HADES_TASK_V1',
      action: 'proposal-only',
      taskId: `HADES-M35-${number}`,
      goal: 'Verify bounded issue pagination behavior.',
      acceptance: ['The later page is considered'],
      files: [],
    }),
  };
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hades-m35-pagination-'));
  fs.chmodSync(directory, 0o700);
  return { directory, close: () => fs.rmSync(directory, { recursive: true, force: true }) };
}

function response(value) {
  return { ok: true, json: async () => value, headers: { get: () => null } };
}

test('older invalid issue backlog does not hide a valid task on the next page', async () => {
  const calls = [];
  const postedIssues = [];
  const olderInvalidIssues = Array.from({ length: 100 }, (_, index) => ({
    number: index + 1,
    title: 'not a HADES task',
    user: { login: owner },
    body: 'invalid fixture',
  }));
  const gh = createGithub({
    repo: repository,
    token: 'test-fixture-token',
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      calls.push({ path: parsed.pathname, page: parsed.searchParams.get('page'), method: init.method });
      if (parsed.pathname === `/repos/${repository}/issues` && init.method === 'GET') {
        return response(parsed.searchParams.get('page') === '1' ? olderInvalidIssues : [issue(101)]);
      }
      if (parsed.pathname === `/repos/${repository}/issues/101/comments` && init.method === 'GET') {
        return response([]);
      }
      if (parsed.pathname === `/repos/${repository}/issues/101/comments` && init.method === 'POST') {
        postedIssues.push(101);
        return response({});
      }
      throw Error(`unexpected_fixture_request:${parsed.pathname}`);
    },
  });
  const state = fixture();
  try {
    const result = await runCycle(gh, state.directory, config);
    assert.equal(result.new, 1);
    assert.deepEqual(postedIssues, [101]);
    assert.deepEqual(calls.filter(call => call.path.endsWith('/issues') && call.method === 'GET').map(call => call.page), ['1', '2']);
  } finally {
    state.close();
  }
});

test('receipt lookup continues through comment page two', async () => {
  const taskIssue = issue(7);
  const parsedTask = parseTask(taskIssue, config);
  const marker = receiptFor(parsedTask, repository).body;
  const commentPages = [];
  let posted = false;
  const gh = createGithub({
    repo: repository,
    token: 'test-fixture-token',
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      if (parsed.pathname === `/repos/${repository}/issues` && init.method === 'GET') {
        return response(parsed.searchParams.get('page') === '1' ? [taskIssue] : []);
      }
      if (parsed.pathname === `/repos/${repository}/issues/7/comments` && init.method === 'GET') {
        const page = parsed.searchParams.get('page');
        commentPages.push(page);
        return response(page === '1'
          ? Array.from({ length: 100 }, (_, index) => ({ body: `unrelated ${index}`, user: { login: 'other-user' } }))
          : [{ body: marker, user: { login: owner } }]);
      }
      if (parsed.pathname === `/repos/${repository}/issues/7/comments` && init.method === 'POST') {
        posted = true;
        return response({});
      }
      throw Error(`unexpected_fixture_request:${parsed.pathname}`);
    },
  });
  const state = fixture();
  try {
    const result = await runCycle(gh, state.directory, config);
    assert.equal(result.recovered, 1);
    assert.deepEqual(commentPages, ['1', '2']);
    assert.equal(posted, false);
  } finally {
    state.close();
  }
});

test('issue and comment pagination stop at the configured page bound instead of accepting partial history', async () => {
  const calls = [];
  const gh = createGithub({
    repo: repository,
    token: 'test-fixture-token',
    fetchFn: async url => {
      const parsed = new URL(url);
      calls.push(parsed.pathname);
      return response(Array.from({ length: 100 }, (_, index) => ({ number: index + 1 })));
    },
  });

  await assert.rejects(gh.listIssues(), /github_pagination_limit_reached/);
  assert.equal(calls.filter(pathname => pathname === `/repos/${repository}/issues`).length, 10);
  calls.length = 0;
  await assert.rejects(gh.listComments(7), /github_pagination_limit_reached/);
  assert.equal(calls.filter(pathname => pathname === `/repos/${repository}/issues/7/comments`).length, 10);
});
