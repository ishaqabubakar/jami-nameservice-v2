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
const { Web3 }   = require('web3');
const web3       = new Web3(process.env.RPC_URL || 'http://localhost:8545');
const argv       = require('minimist')(process.argv.slice(2));
const crypto     = require('crypto');
const path       = require('path');

/* ------------------------------------------------------------------ *
 *  CONSTANTS / HELPERS                                               *
 * ------------------------------------------------------------------ */

const REG_FILE       = path.join(__dirname, 'contract', 'registrar.out.json');
const REG_ADDR_FILE  = path.join(__dirname, 'contractAddress.txt');
const NAME_VALIDATOR = /^[a-z0-9-_]{3,32}$/;

const cache     = {};   // name  ⇒ { name, addr, … }
const addrCache = {};   // addr  ⇒ { name, addr, … }

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

/* ---------- name ⇄ bytes32 helpers (32-byte padding) ------------------ */
const pad32   = hex => '0x' + hex.replace(/^0x/, '').padEnd(64, '0');
const unpad32 = hex => hex.replace(/^0x/, '').replace(/(00)+$/, '');

function formatName(n) {                      // encode & right-pad
  return pad32(web3.utils.utf8ToHex(n));
}
function parseString(hex) {                   // decode & trim zeros
  const raw = unpad32(hex);
  return raw ? web3.utils.hexToUtf8('0x' + raw) : '';
}

const isHashZero = h => !h || /^0x0*$/.test(h);   // keep as-is


function formatAddress(a) {
  if (!a) return;
  let s = a.trim();
  if (s.startsWith('ring:')) s = s.slice(5);
  if (!s.startsWith('0x'))   s = '0x' + s;
  if (new BigNumber(s.slice(2), 16).isZero()) return;
  return s.toLowerCase();
}

/* ------------------------------------------------------------------ *
 *  AWAIT CONSENSUS helper (polling)                                   *
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ *
 *  REGISTRAR BOOTSTRAP                                               *
 * ------------------------------------------------------------------ */
let coinbase, balance, regAddress = '0x0', regData, reg;

async function deployRegistrar(onReady) {
  /* walk json & take the first object holding both abi + evm.bytecode */
  const compiled = JSON.parse(fs.readFileSync(REG_FILE, 'utf8'));
  const find = n =>
    n && typeof n === 'object'
      ? (n.abi && n.evm && n.evm.bytecode ? n
         : Object.values(n).reduce((r, v) => r || find(v), null))
      : null;

  regData = find(compiled);
  if (!regData) {
    console.error('\n⚠️  No contract ABI / byte-code found in', REG_FILE,
                  '\n   Re-compile your Solidity 0.6 contract.\n');
    process.exit(1);
  }

  const factory = new web3.eth.Contract(regData.abi);

  /* 1️⃣  reuse */
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

  /* 2️⃣  deploy */
  console.log('Deploying new registrar…');
  reg = await factory.deploy({ data: '0x' + regData.evm.bytecode.object })
                      .send({ from: coinbase, gas: 1_000_000 });
  regAddress = reg.options.address;
  fs.writeFileSync(REG_ADDR_FILE, regAddress);
  console.log('Registrar deployed at', regAddress);
  onReady();
}

/* ------------------------------------------------------------------ *
 *  EXPRESS SERVER – routes identical in spirit to original           *
 * ------------------------------------------------------------------ */
function startServer() {
  console.log('Starting HTTP server …');
  const app = express();
  app.disable('x-powered-by');
  app.use(bodyParser.json());
  app.use((_, res, next) => { res.type('json'); next(); });

  /* ---------- LOOK-UP ROUTES ---------- */

  app.get('/name/:name', async (req, res) => {
    try {
      const hex = formatName(req.params.name);
      const addr = await reg.methods.addr(hex).call();
      if (isHashZero(addr)) {
        const cached = cache[req.params.name];
        return cached
          ? res.json(cached)
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
    } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
  });

  app.get('/name/:name/publickey', async (req, res) => {
    try {
      const pub = await reg.methods.publickey(formatName(req.params.name)).call();
      if (isHashZero(pub))
        return res.status(404).json({ error: 'name not registered' });
      res.json({ name: req.params.name, publickey: pub });
    } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
  });

  app.get('/name/:name/signature', async (req, res) => {
    try {
      const sig = await reg.methods.signature(formatName(req.params.name)).call();
      if (isHashZero(sig))
        return res.status(404).json({ error: 'name not registered' });
      res.json({ name: req.params.name, signature: sig });
    } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
  });

  app.get('/name/:name/owner', async (req, res) => {
    try {
      const owner = await reg.methods.owner(req.params.name).call();
      if (isHashZero(owner))
        return res.status(404).json({ error: 'name not registered' });
      res.json({ name: req.params.name, owner });
    } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
  });

  app.get('/addr/:addr', async (req, res) => {
    try {
      const addr = formatAddress(req.params.addr);
      if (!addr) return res.status(400).json({ success: false });
      const nameHex = await reg.methods.name(addr).call();
      if (!isHashZero(nameHex))
        return res.json({ name: parseString(nameHex) });

      const cached = addrCache[addr];
      cached
        ? res.json(cached)
        : res.status(404).json({ error: 'address not registered' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
  });

  /* ---------- REGISTRATION ROUTE ---------- */

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

      /* optional pub-key / signature */
      let publickey = '0x0', signature = '0x0';
      if (req.body.publickey || req.body.signature) {
        if (!req.body.publickey || !req.body.signature)
          return res.status(400).json({ success: false, error: 'missing publickey/signature' });
        if (!verifySignature(name, req.body.publickey, req.body.signature))
          return res.status(401).json({ success: false, error: 'signature invalid' });
        publickey = req.body.publickey;
        signature = req.body.signature;
      }

      const taken = !(await reg.methods.owner(name).call()).match(/^0x0*$/);
      if (taken)
        return res.status(403).json({ success: false, error: 'name already owned' });

      console.log(`Registering ${name} → ${addr}`);

      const tx = await reg.methods.reserveFor(
        formatName(name),
        owner,
        addr,
        publickey,
        signature
      ).send({ from: coinbase, gas: 3_000_000 });

      const obj = { name, addr, publickey, signature };
      cache[name]    = obj;
      addrCache[addr]= obj;

      res.json({ success: true, tx: tx.transactionHash });
    } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
  });

  /* ---------- LISTENERS ---------- */

  http.createServer(app).listen(8080, () => console.log('HTTP  :8080 ready'));
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
      https.createServer(opts, app).listen(443, () => console.log('HTTPS :443  ready'));
    } catch (e) { console.error('HTTPS error:', e); }
  }
}

/* ------------------------------------------------------------------ *
 *  MAIN  (async bootstrap)                                            *
 * ------------------------------------------------------------------ */
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