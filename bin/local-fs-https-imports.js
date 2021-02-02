#!/usr/bin/env node
import parser from '@babel/parser';
import traverse from '@babel/traverse';
import types from '@babel/types';
import https from 'https';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import url from 'url';

let entry = new URL(process.argv[2], url.pathToFileURL(process.cwd() + '/'));
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
      return path.join(this.cache, `${encodeURIComponent(href).replaceAll('_', '__').replaceAll('%', '_')}.mjs`);
    }
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
  cascade: true
};
let policy = {
  resources: {},
  scopes: {
    [url.pathToFileURL(outDir.policy).href + '/']: scope
  }
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
while (toVisit.size) {
  let [next] = toVisit;
  toVisit.delete(next);
  if (visited.has(next)) continue;
  visited.add(next);
  console.error('visiting', next);
  const nextURL = new URL(next);
  if (nextURL.protocol !== 'https:') {
    if (nextURL.protocol !== 'file:') {
      throw new Error(`GATHERING FROM ${nextURL.protocol} URLs NOT IMPLEMENTED`);
    }
    const deps = gatherDeps(await fs.readFile(nextURL, 'utf-8'), next);
    for (const specifier of deps) {
      try {
        toVisit.add(new URL(specifier).href);
      } catch (e) {
        if (path.isAbsolute(specifier) || /.?.?[\/\\]/.test(specifier)) {
          const fileURL = url.pathToFileURL(path.resolve(specifier, url.fileURLToPath(next)));
          toVisit.add(fileURL.href)
        }
      }
    }
    continue;
  }
  let body = await new Promise((f, r) => {
    https
      .get(next, (c) => {
        if (!isJavaScriptMIME(c.headers['content-type'])) {
          r(new Error('Unknown Content Type: ' + c.headers['content-type']));
        }
        let bufs = [];
        c.on('data', (d) => bufs.push(d));
        c.on('end', () => {
          let src = Buffer.concat(bufs).toString('utf-8');
          f(src);
        });
      })
      .on('abort', () => r(new Error('aborted')))
      .on('error', (err) => r(err))
      .on('timeout', () => r(new Error('timeout')));
  });
  let integrity = `sha256-${crypto.createHash('sha256').update(body).digest().toString('base64')}`;
  let outFile = outDir.getFilePathForHREF(next);
  policy.resources[outFile] = {
    integrity,
    dependencies: {}
  };
  scope.dependencies[next] = outFile;
  for (const specifier of gatherDeps(body, next)) {
    const resolved = new URL(specifier, next);
    if (resolved.protocol !== 'https:' && resolved.protocol !== 'data:') {
      throw new Error('https: modules cannot resolve ' + resolved + ' due to security concerns');
    }
    let {href} = resolved;
    policy.resources[outFile].dependencies[specifier] = outDir.getFilePathForHREF(href);
    toVisit.add(href)
  }
  await fs.writeFile(outFile, body, 'utf-8');
}
console.log(JSON.stringify(policy, null, 2))

