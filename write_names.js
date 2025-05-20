#!/usr/bin/env nodejs
/*
 *  GNU GPL – Savoir-faire Linux (2016-2025) · Author Adrien Béraud
 */
'use strict';

/* ───────────── 0 . ENV / DEPENDENCIES ─────────────────────────────────── */
require('dotenv').config();

const async      = require('async');
const BigNumber  = require('bignumber.js');
const fs         = require('fs');
const path       = require('path');
const minimist   = require('minimist');const { Web3 } = require('web3');
const web3    = new Web3(process.env.RPC_URL || 'http://localhost:8545');

/* legacy helper kept, rewritten for Web3 v4 */
Object.getPrototypeOf(web3.eth).awaitConsensus = function (txHash, done) {
  const sub  = this.subscribe('newBlockHeaders');
  let   tries = 5;
  sub.on('data', async () => {
    const r = await this.getTransactionReceipt(txHash);
    if (r && r.transactionHash === txHash) { sub.unsubscribe(); done(); }
    else if (!--tries)                    { sub.unsubscribe(); done('timeout'); }
  });
};

/* ───────────── 2 . CLI ARG CHECKS ─────────────────────────────────────── */
const argv = minimist(process.argv.slice(2));
if (argv._.length < 1)
  throw `Specify Batch Input File as: node ${path.basename(__filename)} <file.json>`;

function validateFile(f) {
  if (path.isAbsolute(f) && fs.existsSync(f)) return f;
  const rel = path.resolve(f);
  return fs.existsSync(rel) ? rel : null;
}
const batchInputFile = validateFile(String(argv._[0]));
if (!batchInputFile) throw `File ${argv._[0]} does not exist`;

/* ───────────── 3 . CONSTANTS / REGISTRAR INFO ─────────────────────────── */
const REG_FILE        = path.join(__dirname, 'contract/registrar.out.json');
const REG_ADDR_FILE   = path.join(__dirname, 'contractAddress.txt');
const NAME_VALIDATOR  = /^[a-z0-9-_]{3,32}$/;
let   regAddress      = '0xe53cb2ace8707526a5050bec7bcf979c57f8b44f';
let   regData, regContract, reg;

/* ───────────── 4 . MAIN FLOW ──────────────────────────────────────────── */
(async () => {
  const coinbase = (await web3.eth.getCoinbase())?.toLowerCase();
  const balance  = await web3.eth.getBalance(coinbase);
  console.log('Coinbase:', coinbase);
  console.log('Balance :', balance.toString(10));

  /* unlockAccount helper unchanged */
  function unlockAccount() { web3.eth.personal.unlockAccount(coinbase, 'toto'); }

  /* ---------- FIXED: helper is now async so it can await ---------------- */
  async function getRemainingGaz() {
    const [bal, gasPrice] = await Promise.all([
      web3.eth.getBalance(coinbase),
      web3.eth.getGasPrice()
    ]);
    return BigInt(bal) / BigInt(gasPrice);
  }

  /* ---------- loadContract (unchanged logic, promise style) ------------ */
  function loadContract(onReady) {
    fs.readFile(REG_ADDR_FILE, (err, buf) => {
      if (!err) regAddress = buf.toString().trim();
      fs.readFile(REG_FILE, (e, data) => {
        if (e) throw e;
        regData     = JSON.parse(data).contracts.registrar.GlobalRegistrar;
        regContract = new web3.eth.Contract(regData.abi);
        console.log('Loading contract at', regAddress);

        web3.eth.getCode(regAddress).then(code => {
          if (!code || code === '0x') throw 'Contract not found – deploy it first';
          regContract.options.address = regAddress;
          reg = regContract;
          onReady();
        }).catch(console.error);
      });
    });
  }

  /* ---------- helpers unchanged ---------------------------------------- */
  function formatName(n)     { return '0x' + Buffer.from(n).toString('hex'); }
  function isHashZero(h)     { return !h || /^0x0+$/.test(h); }
  function parseString(s)    { return s ? web3.utils.hexToUtf8(s) : s; }
  function formatAddress(a) {
    if (!a) return undefined;
    let s = a.trim();
    if (s.startsWith('ring:')) s = s.slice(5);
    if (!s.startsWith('0x'))   s = '0x' + s;
    return new BigNumber(s.slice(2), 16).isZero() ? undefined : s.toLowerCase();
  }

  /* ---------- registerName (now async so we can await gas) -------------- */
  async function registerName(addrParam, nameParam, ownerParam, pk, sig, done) {
    try {
      const addr  = formatAddress(addrParam);
      const owner = formatAddress(ownerParam);
      if (!addr || !owner || !NAME_VALIDATOR.test(nameParam)) return done();

      console.log(`Reg request (${nameParam} → ${addr}) from ${owner}`);
      const ownerOnChain = await reg.methods.owner(formatName(nameParam)).call();
      if (!isHashZero(ownerOnChain)) { console.log('Already registered'); return done(); }

      console.log('Remaining gas:', await getRemainingGaz().then(n => n.toString()));
      unlockAccount();
      reg.methods.reserveFor(
        formatName(nameParam), owner, addr, pk || '0', sig || '0'
      ).send({ from: coinbase, gas: 3_000_000 })
        .then(tx => {
          console.log('Tx sent', tx.transactionHash);
          web3.eth.awaitConsensus(tx.transactionHash, err => {
            if (err) console.error(err);
            else     console.log('Registered', nameParam);
            done();
          });
        }).catch(e => { console.error(e); done(); });
    } catch (e) { console.error(e); done(); }
  }

  /* ---------- batching queue (unchanged) -------------------------------- */
  function startWrites() {
    const list = JSON.parse(fs.readFileSync(batchInputFile, 'utf8'));
    console.log(`${list.length} inserts queued`);
    const q = async.queue((task, cb) =>
      registerName(task.addr, task.name, task.owner,
                   task.publickey, task.signature, cb),
      256
    );
    q.push(list);
    q.drain(() => console.log('All done'));
  }

  /* ---------- ENTRY ----------------------------------------------------- */
  unlockAccount();
  loadContract(startWrites);
})();
