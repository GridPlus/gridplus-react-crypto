'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

const Buffer = require('buffer/').Buffer;
const hash = require('hash.js');

class ReactCrypto {

  constructor(e) {
    // Hash whatever the entropy provided is and use that hash as the entropy for sjcl
    this.entropy = new Hash('sha256').update(e).digest();
    this.count = 0;
    this.hash = null;
  }

  get32RandomBytes() {
    const preImage = String(this.count * new Date().getTime());
    const r = this.createHash('sha256').update(preImage).digest();
    this.count += 1;
    return r;
  }

  // Return 32 bytes of entropy
  generateEntropy() {
    return this.get32RandomBytes();
  }

  // Return n bytes of entropy
  randomBytes(n) {
    const numHashes = Math.ceil(n / 32);
    let b = '';
    for (let i = 0; i < numHashes; i++) {
      b += this.get32RandomBytes();
    }
    return b.slice(0, n * 2);
  }

  createHash(type) {
    this.hash = new Hash(type);
    return this.hash;
  }
}

class Hash {
  constructor(type) {
    switch (type) {
      case 'sha256':
        this.hash = hash.sha256();
        break;
      case 'rmd160':
        this.hash = hash.ripemd160();
        break;
      default:
        throw new Error('Unsupported hash type');
        break;
    }
  }

  update(x) {
    this.hash.update(x);
    return this;
  }

  digest() {
    return Buffer.from(this.hash.digest('hex'), 'hex');
  }
}

exports.default = ReactCrypto;