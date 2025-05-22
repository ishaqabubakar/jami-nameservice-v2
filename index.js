#!/usr/bin/env node
/*  GPL-3.0 – original copyright header kept intact                   */
'use strict';

require('dotenv').config();

const express    = require('express');
const bodyParser = require('body-parser');
const BigNumber  = require('bignumber.js');
const fs         = require('fs');
const http       = require('http');
const https      = require('https');
const path       = require('path');
const crypto     = require('crypto');
const argv       = require('minimist')(process.argv.slice(2));
const { Web3 }   = require('web3');

// ────────────────────────────────────────────────────────────────────────────
//  Web3 + RPC setup
// ────────────────────────────────────────────────────────────────────────────
const web3 = new Web3(process.env.RPC_URL || 'http://localhost:8545');

// ────────────────────────────────────────────────────────────────────────────
//  SQLite integration
// ────────────────────────────────────────────────────────────────────────────
const sqlite3 = require('sqlite3').verbose();
const dbPath  = path.join(__dirname, 'nameserver.db');
const db      = new sqlite3.Database(dbPath,
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  err => { if (err) console.error('DB open error:', err); }
);
db.run(`
  CREATE TABLE IF NOT EXISTS names (
    name       TEXT PRIMARY KEY,
    addr       TEXT,
    owner      TEXT,
    publickey  TEXT,
    signature  TEXT
  )
`);

// ────────────────────────────────────────────────────────────────────────────
//  DHT bootstrap (so your API can share the same node)
// ────────────────────────────────────────────────────────────────────────────
const [ dhtHost, dhtPort ] = (process.env.DHT_BOOT || '127.0.0.1:4222').split(':');
const dht = new DHT.Node({ port: Number(dhtPort) });
dht.bootstrap([ `${dhtHost}:${dhtPort}` ]);
console.log(`DHT client bootstrapped on ${dhtHost}:${dhtPort}`);

// ────────────────────────────────────────────────────────────────────────────
//  Constants & helpers
// ────────────────────────────────────────────────────────────────────────────
const REG_FILE       = path.join(__dirname, 'contract', 'registrar.out.json');
const REG_ADDR_FILE  = path.join(__dirname, 'contractAddress.txt');
const NAME_VALIDATOR = /^[a-z0-9-_]{3,32}$/;

const cache     = {};   // in-memory cache: name ⇒ record
const addrCache = {};   // in-memory cache: addr ⇒ record

function validateFile(f) {
  if (path.isAbsolute(f) && fs.existsSync(f))        return f;
  if (!path.isAbsolute(f) && fs.existsSync('./' + f)) return path.resolve(f);
  return false;
}

function loadCache(inputFile) {
  const list = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
  list.forEach(e => {
    cache[e.name]     = e;
    addrCache[e.addr] = e;
  });
  console.log(`Loaded ${list.length} entries into cache`);
}

function verifySignature(name, pub, sig) {
  const publicKey = Buffer.from(pub, 'base64').toString('ascii');
  const verifier  = crypto.createVerify('RSA-SHA512');
  verifier.update(name);
  return verifier.verify(publicKey, sig, 'base64');
}

const pad32   = hex => '0x' + hex.replace(/^0x/, '').padEnd(64, '0');
const unpad32 = hex => hex.replace(/^0x/, '').replace(/(00)+$/, '');

function formatName(n)  { return pad32(web3.utils.utf8ToHex(n)); }
function parseString(hex) {
  const raw = unpad32(hex);
  return raw ? web3.utils.hexToUtf8('0x' + raw) : '';
}
const isHashZero = h => !h || /^0x0*$/.test(h);

function formatAddress(a) {
  if (!a) return;
  let s = a.trim();
  if (s.startsWith('ring:')) s = s.slice(5);
  if (!s.startsWith('0x'))   s = '0x' + s;
  if (new BigNumber(s.slice(2), 16).isZero()) return;
  return s.toLowerCase();
}

// ────────────────────────────────────────────────────────────────────────────
//  Consensus helper (polling)
// ────────────────────────────────────────────────────────────────────────────
web3.eth.awaitConsensus = async (txHash, cb, tries = 12) => {
  const poll = async () => {
    try {
      const r = await web3.eth.getTransactionReceipt(txHash);
      if (r && r.blockNumber) return cb(null, r);
      if (--tries === 0)      return cb('Transaction timeout');
      setTimeout(poll, 5000);
    } catch (e) { cb(e); }
  };
  poll();
};

// ────────────────────────────────────────────────────────────────────────────
//  Registrar bootstrap
// ────────────────────────────────────────────────────────────────────────────
let coinbase, balance, regAddress = '0x0', regData, reg;

async function deployRegistrar(onReady) {
  let compiled;
  try {
    compiled = JSON.parse(fs.readFileSync(REG_FILE, 'utf8'));
  } catch (e) {
    console.error(`⛔ could not read/parse ${REG_FILE}:`, e);
    process.exit(1);
  }

  // Account for solcjs’s “contracts” wrapper:
  const find = obj =>
    obj && typeof obj === 'object'
      ? (obj.abi && obj.bin)
          ? {
              abi: JSON.parse(obj.abi),
              evm: { bytecode: { object: obj.bin }}
            }
          : Object.values(obj).reduce((acc, v) => acc || find(v), null)
      : null;

  const flat = compiled.contracts || compiled;
  regData = find(flat);
  if (!regData) {
    console.error(
      `\n⚠️  No contract ABI + bytecode found in ${REG_FILE}\n`+
      `   (re-compile your Solidity contract)\n`
    );
    process.exit(1);
  }

  const factory = new web3.eth.Contract(regData.abi);

  if (fs.existsSync(REG_ADDR_FILE)) {
    regAddress = fs.readFileSync(REG_ADDR_FILE, 'utf8').trim();
    const code = await web3.eth.getCode(regAddress);
    if (code && code !== '0x') {
      reg = factory;
      reg.options.address = regAddress;
      reg.options.from    = coinbase;
      console.log('Re-using registrar at', regAddress);
      return onReady();
    }
  }

  console.log('Deploying new registrar…');
  reg = await factory
    .deploy({ data: '0x' + regData.evm.bytecode.object })
    .send({ from: coinbase, gas: 5_000_000 });
  regAddress = reg.options.address;
  fs.writeFileSync(REG_ADDR_FILE, regAddress);
  console.log('Registrar deployed at', regAddress);
  onReady();
}

// ────────────────────────────────────────────────────────────────────────────
//  HTTP server + routes
// ────────────────────────────────────────────────────────────────────────────
function startServer() {
  console.log('Starting HTTP server …');
  const app = express();
  app.disable('x-powered-by');
  app.use(bodyParser.json());
  app.use((_, res, next) => { res.type('json'); next(); });

  // ——————————————————————————————————————————————————————————————
  //  1) Log every incoming request + its JSON body
  app.use((req, res, next) => {
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}` +
      `  body=${JSON.stringify(req.body)}`
    );
    next();
  });
  // ——————————————————————————————————————————————————————————————

  // GET /name/:name  →  try SQLite, then on-chain+cache
  app.get('/name/:name', (req, res) => {
    db.get(
      `SELECT name, addr, owner, publickey, signature
         FROM names WHERE name = ?`,
      [req.params.name],
      (err, row) => {
        if (err) console.error('DB lookup error:', err);
        if (row) return res.json(row);

        (async () => {
          try {
            const hex  = formatName(req.params.name);
            const addr = await reg.methods.addr(hex).call();
            if (isHashZero(addr)) {
              const c = cache[req.params.name];
              return c
                ? res.json(c)
                : res.status(404).json({ error: 'name not registered' });
            }
            const pub = await reg.methods.publickey(hex).call();
            const sig = await reg.methods.signature(hex).call();
            const obj = isHashZero(pub)
              ? { name: req.params.name, addr }
              : { name: req.params.name, addr, publickey: pub, signature: sig };
            cache[req.params.name] = obj;
            addrCache[addr]        = obj;
            res.json(obj);
          } catch (e) {
            console.error(e);
            res.status(500).json({ error: 'server error' });
          }
        })();
      }
    );
  });

  // … all your other GET routes unchanged …

  // POST /name/:name  →  on-chain + persist to SQLite
  app.post('/name/:name', async (req, res) => {
    try {
      const name  = req.params.name;
      const addr  = formatAddress(req.body.addr);
      const owner = formatAddress(req.body.owner);

      if (!addr || !owner)
        return res.status(400).json({ success: false, error: 'invalid addr/owner' });
      if (!NAME_VALIDATOR.test(name))
        return res.status(400).json({ success: false, error: 'invalid name' });
      if (cache[name])
        return res.status(400).json({ success: false, error: 'name already registered' });

      let publickey = '0x0', signature = '0x0';
      if (req.body.publickey || req.body.signature) {
        if (!req.body.publickey || !req.body.signature)
          return res.status(400).json({ success: false, error: 'missing publickey/signature' });
        if (!verifySignature(name, req.body.publickey, req.body.signature))
          return res.status(401).json({ success: false, error: 'signature invalid' });
        publickey = req.body.publickey;
        signature = req.body.signature;
      }

      const taken = !(await reg.methods.owner(formatName(name)).call()).match(/^0x0*$/);
      if (taken)
        return res.status(403).json({ success: false, error: 'name already owned' });

      console.log(`Registering ${name} → ${addr}`);
      const tx = await reg.methods.reserveFor(
        formatName(name), owner, addr, publickey, signature
      ).send({ from: coinbase, gas: 3_000_000 });

      const obj = { name, addr, publickey, signature };
      cache[name]     = obj;
      addrCache[addr] = obj;

      res.json({ success: true, tx: tx.transactionHash });

      // ——————————————————————————————————————————————————————————————
      //  2) Log SQLite insert results
      db.run(
        `INSERT OR REPLACE INTO names
           (name, addr, owner, publickey, signature)
         VALUES (?, ?, ?, ?, ?)`,
        [name, addr, owner, publickey, signature],
        (err) => {
          if (err) console.error('DB insert error:', err);
          else      console.log(`✔︎ persisted to SQLite: ${name} → ${addr}`);
        }
      );
      // ——————————————————————————————————————————————————————————————

    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'server error' });
    }
  });

  // start HTTP (and optional HTTPS)
  http.createServer(app).listen(process.env.PORT || 8080, () =>
    console.log(`HTTP  :${process.env.PORT||8080} ready`)
  );
  if (argv.https) {
    try {
      const opts = {
        key : fs.readFileSync('/etc/ssl/private/star_ring_cx.key'),
        cert: fs.readFileSync('/etc/ssl/certs/cert_star_ring_cx.pem'),
        ca  : fs.readFileSync('/etc/ssl/certs/chain_star_ring_cx.pem','utf8')
               .split('\n-----END CERTIFICATE-----')
               .filter(Boolean)
               .map(c => c + '\n-----END CERTIFICATE-----')
      };
      https.createServer(opts, app).listen(443, () =>
        console.log('HTTPS :443 ready')
      );
    } catch (e) {
      console.error('HTTPS error:', e);
    }
  }
}

// ────────────────────────────────────────────────────────────────────────────
//  Main (bootstrap + startServer)
// ────────────────────────────────────────────────────────────────────────────
(async () => {
  try {
    console.log('Loading…');
    const accounts = await web3.eth.getAccounts();
    coinbase = accounts[0];
    balance  = await web3.eth.getBalance(coinbase);
    console.log('Coinbase:', coinbase);
    console.log('Balance :', web3.utils.fromWei(balance, 'ether'), 'ETH');

    if (argv._.length) {
      const f = validateFile(String(argv._[0]));
      if (!f) throw new Error(`File ${argv._[0]} does not exist`);
      loadCache(f);
    }

    await deployRegistrar(startServer);
  } catch (err) {
    console.error('Fatal start-up error:', err);
    process.exit(1);
  }
})();
