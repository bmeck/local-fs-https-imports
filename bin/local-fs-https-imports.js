#!/usr/bin/env node
import parser from '@babel/parser';
import traverse from '@babel/traverse';
import types from '@babel/types';
import https from 'https';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import url from 'url';
import { format } from 'util';

let entry = new URL(process.argv[2], url.pathToFileURL(process.cwd() + '/'));
if (!process.argv[3]) {
  throw new Error('must supply policy location');
}
const policyFile = path.resolve(process.argv[3]);
const policyDir = path.dirname(policyFile);
let pendingPathResolutions = [];
function getAsyncPolicyRelative(filepath) {
  let jsonPath; 
  pendingPathResolutions.push({
    then() {
      return Promise.resolve(
        fs.realpath(filepath).then((_) => {
          return jsonPath = _;
        })
      );
    }
  });
  return {
    toJSON() {
      if (!jsonPath) throw new Error('still waiting on path resolution for ' + filepath);
      return `./${path.relative(policyDir, jsonPath)}`
    }
  }
}
function getPolicyRelative(filepath) {
  return `./${path.relative(policyDir, filepath)}`;
}
async function findNodeModules() {
  let cwd = process.cwd();
  let oldNeedle;
  let needle = cwd;
  let createDir = true;
  while (needle !== oldNeedle) {
    if (path.basename(needle) === 'node_modules') {
      break;
    }
    let stat = await fs.stat(path.join(needle, 'node_modules'));
    if (stat.isDirectory()) {
      createDir = false;
      break;
    }
    oldNeedle = needle;
    needle = path.dirname(oldNeedle);
  }
  if (createDir) {
    needle = cwd;
  }
  let cacheDir = path.join(needle, 'node_modules', '.https');
  let policyDir = needle;
  await fs.mkdir(cacheDir, {
    recursive: true,
  });
  return {
    cache: cacheDir,
    policy: policyDir,
    getFilePathForHREF(href) {
      // YEA YEA YEA, you can get a double extensions, but this allows absolute
      // clarity that the final extension is from this script.
      return path.join(
        this.cache,
        `${encodeURIComponent(href)
          .replaceAll('_', '__')
          .replaceAll('%', '_')}.mjs`
      );
    },
  };
}
let outDir = await findNodeModules();

let visited = new Set();
let toVisit = new Set([entry.href]);
const JavaScriptMIMEPattern = /^(?:text|application)\/(?:javascript|ecmascript)(?:;[\s\S]+)?$/iu;
function isJavaScriptMIME(str) {
  return JavaScriptMIMEPattern.test(str);
}
let scope = {
  integrity: true,
  dependencies: {},
  cascade: true,
};
let policy = {
  resources: {},
  scopes: {
    [url.pathToFileURL(outDir.policy).href + '/']: scope,
  },
};
/**
 *
 * @param {string} body
 * @returns {Set<string>}
 */
function gatherDeps(body, sourceFilename) {
  let gatheredDeps = new Set();
  traverse.default(
    parser.parse(body, {
      sourceType: 'module',
      sourceFilename,
      allowAwaitOutsideFunction: true,
    }),
    {
      enter(path) {
        const node = path.node;
        let foundDep = null;
        if (types.isCallExpression(node)) {
          if (node.callee.type === 'Import') {
            if (node.arguments[0].type !== 'StringLiteral') {
              throw new Error(
                `Cannot have dynamic import to expression ${path} on ${sourceFilename}:${node.loc.start.line}`
              );
            } else {
              foundDep = node.arguments[0].value;
            }
          }
        } else if (types.isImportDeclaration(node)) {
          foundDep = node.source.value;
        } else if (
          types.isExportAllDeclaration(node) ||
          types.isExportNamedDeclaration(node)
        ) {
          if (node.source) foundDep = node.source.value;
        }
        if (foundDep != null) {
          gatheredDeps.add(foundDep);
        }
      },
    }
  );
  return gatheredDeps;
}
function addHREFToVisit(href, referrer) {
  console.log('%j contains ref to %j', referrer, href);
  let resolved = new URL(href);
  if (resolved.href !== href) {
    const target = outDir.getFilePathForHREF(resolved);
    scope.dependencies[href] = getAsyncPolicyRelative(target);
  }
  if (visited.has(href)) return;
  toVisit.add(href);
}
while (toVisit.size) {
  let [next] = toVisit;
  toVisit.delete(next);
  if (visited.has(next)) continue;
  visited.add(next);
  const nextURL = new URL(next);
  if (nextURL.protocol !== 'https:') {
    if (nextURL.protocol !== 'file:') {
      throw new Error(
        `GATHERING FROM ${nextURL.protocol} URLs NOT IMPLEMENTED`
      );
    }
    const deps = gatherDeps(await fs.readFile(nextURL, 'utf-8'), next);
    for (const specifier of deps) {
      try {
        const depURL = new URL(specifier);
        const depHREF = depURL.href;
        if (depURL.protocol === 'https:') {
          const depFile = outDir.getFilePathForHREF(depHREF);
          const key = getPolicyRelative(url.fileURLToPath(next));
          policy.resources[
            key
          ] ??= {
            "integrity": true,
            "cascade": true,
            "dependencies": {}
          };
          policy.resources[key].dependencies[specifier] = getAsyncPolicyRelative(depFile);
        }
        addHREFToVisit(depHREF, next);
      } catch (e) {
        if (path.isAbsolute(specifier) || /.?.?[\/\\]/.test(specifier)) {
          const fileURL = url.pathToFileURL(
            path.resolve(specifier, url.fileURLToPath(next))
          );
          addHREFToVisit(fileURL.href, next);
        }
      }
    }
    continue;
  }
  await fetch(next);
}
for (const pending of pendingPathResolutions) {
  await pending.then();
}
await fs.writeFile(policyFile, JSON.stringify(policy, null, 2), 'utf-8');

async function fetch(next) {
  let outFile = outDir.getFilePathForHREF(next);
  /**
   * @type {import('http').IncomingMessage}
   */
  let res = await new Promise((f, r) => {
    https.get(next, (res) => f(res)).on('abort', r).on('error', r).on('timeout', r);
  });
  if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
    const redirectLocation = new URL(res.headers['location'], next).href;
    console.log('%j redirected to %j', next, redirectLocation);
    try {
      await fs.unlink(outFile);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    const target = outDir.getFilePathForHREF(redirectLocation);
    await fs.symlink(target, outFile);
    scope.dependencies[next] = getAsyncPolicyRelative(target);
    return fetch(redirectLocation);
  }
  console.log('no redirect %j', next);
  let body = await new Promise((f, r) => {
    let buffers = [];
    res.on('error', r);
    res.on('data', (d) => buffers.push(d));
    res.on('end', () => {
      let src = Buffer.concat(buffers).toString('utf-8');
      f(src);
    });
  });
  if (!isJavaScriptMIME(res.headers['content-type'])) {
    throw new Error(
      format('%s, Unknown Content Type: %s', next, res.headers['content-type'])
    );
  }
  let integrity = `sha256-${crypto
    .createHash('sha256')
    .update(body)
    .digest()
    .toString('base64')}`;
  const key = getPolicyRelative(outFile);
  policy.resources[key] ??= {
    integrity,
    dependencies: {},
    cascade: true
  };
  const resource = policy.resources[key];
  scope.dependencies[next] = getAsyncPolicyRelative(outFile);
  for (const specifier of gatherDeps(body, next)) {
    let isAbsolute = false;
    try {
      new URL(specifier);
      isAbsolute = true;
    } catch {}
    const resolved = new URL(specifier, next);
    if (resolved.protocol !== 'https:' && resolved.protocol !== 'data:') {
      throw new Error(
        'https: modules cannot resolve ' +
          resolved +
          ' due to security concerns'
      );
    }
    let { href } = resolved;
    if (!isAbsolute) {
      resource.dependencies[
        specifier
      ] = getAsyncPolicyRelative(outDir.getFilePathForHREF(href));
    }
    // some things get messed with, like ' ' => '%20'
    // TODO: make local entry if munged
    if (isAbsolute) {
      addHREFToVisit(specifier, next);
    } else {
      addHREFToVisit(href, next);
    }
  }
  await fs.writeFile(outFile, body, 'utf-8');
}
