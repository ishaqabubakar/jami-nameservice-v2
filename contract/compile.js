// contract/compile.js
const fs   = require('fs');
const path = require('path');
const solc = require('solc');

// 1) load your source
const srcPath = path.join(__dirname, 'registrar.sol');
const source  = fs.readFileSync(srcPath, 'utf8');

// 2) prepare standard JSON input
const input = {
  language: 'Solidity',
  sources: {
    'registrar.sol': { content: source }
  },
  settings: {
    optimizer: { enabled: true },
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode.object']
      }
    }
  }
};

// 3) compile
const output = JSON.parse(solc.compile(JSON.stringify(input)));

// 4) check for errors
if (output.errors) {
  let fatal = false;
  output.errors.forEach(err => {
    console.error(err.formattedMessage);
    if (err.severity === 'error') fatal = true;
  });
  if (fatal) process.exit(1);
}

// 5) grab the first contract (should be your Registrar)
const contracts = output.contracts['registrar.sol'];
const name      = Object.keys(contracts)[0];
const { abi, evm } = contracts[name];

// 6) write out combined JSON
const combined = { abi, evm: { bytecode: { object: evm.bytecode.object } } };
fs.writeFileSync(
  path.join(__dirname, 'registrar.out.json'),
  JSON.stringify(combined, null, 2)
);
console.log(`→ registrar.out.json written (contract "${name}")`);
