#!/usr/bin/env nodejs
/*
 *  Copyright (c) 2016-2020 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
'use strict';
require('dotenv').config();

const fs = require('fs');
const Web3 = require('web3');
const { RPC_URL = 'http://localhost:8545' } = process.env;

// ① Single Web3 instantiation
const web3 = new Web3(RPC_URL);

const REG_ADDR_FILE     = "contractAddress.txt";
const REG_ABI_reserveFor = ['bytes32','address','address','string','string'];
let REG_ADDR           = "0xe53cb2ace8707526a5050bec7bcf979c57f8b44f";

function readContractAddress() {
  fs.readFile(REG_ADDR_FILE, (err, content) => {
    if (err) {
      console.error("Can't read contract address:", err);
    } else {
      REG_ADDR = String(content).trim().toLowerCase();
    }
    web3.eth.getBlockNumber((error, total) => {
      if (error) {
        console.error("Error getting block number:", error);
      } else {
        getAllNames(total);
      }
    });
  });
}

function getAllNames(totalBlocks) {
  let nextBlock = 0;
  let rem       = totalBlocks;

  // Remove old output if present
  try { fs.unlinkSync('names.json'); } catch(e){}

  const fd = fs.openSync('names.json', 'a');
  fs.writeSync(fd, '[\n');

  const cb = (error, block) => {
    rem--;
    if (error) {
      console.error("Can't get block:", error);
    } else {
      for (const tr of block.transactions) {
        try {
          if (tr.to && tr.to.toLowerCase() === REG_ADDR) {
            const p = web3.eth.abi.decodeParameters(REG_ABI_reserveFor, tr.input.substr(10));
            const name = web3.utils.hexToUtf8(p[0]);
            console.log(`Entry: ${name} -> ${p[1]} ${p[2]}`);
            const entry = { name, addr: p[2], owner: p[1] };
            if (p[3]) entry.publickey = p[3];
            if (p[4]) entry.signature = p[4];
            fs.writeSync(fd, JSON.stringify(entry) + ',\n');
          }
        } catch (err) {
          console.error("Error reading transaction:", err);
        }
      }
    }

    if (nextBlock < totalBlocks) {
      web3.eth.getBlock(nextBlock++, true, cb);
    }
    if (rem === 0) {
      fs.writeSync(fd, ']');
      fs.closeSync(fd);
      console.log('Done dumping names.');
    }
  };

  console.log(`Starting... total blocks: ${totalBlocks}`);
  // Kick off up to 256 concurrent requests
  for (; nextBlock < totalBlocks && nextBlock < 256; nextBlock++) {
    web3.eth.getBlock(nextBlock, true, cb);
  }
}

readContractAddress();
