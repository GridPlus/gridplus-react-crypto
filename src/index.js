const sha256 = require('./sha256.js');
const Buffer = require('buffer/').Buffer;
const hash = require('hash.js');

class ReactNativeCrypto {

  constructor(e) {
    // Hash whatever the entropy provided is and use that hash as the entropy for sjcl
    const shaObj = new sha256('SHA-256', 'TEXT');
    shaObj.update(e);
    this.entropy = shaObj.getHash('HEX');
    this.count = 0;
    this.hash = null;
  }

  get32RandomBytes() {
    const shaObj = new sha256('SHA-256', 'TEXT');
    const r = this.createHash('sha256').update(String(this.count * new Date().getTime())).digest().toString('hex');
    shaObj.update(`${this.entropy}${r}`);
    this.count += 1;
    return shaObj.getHash('HEX');
  }

  // Return 32 bytes of entropy
  generateEntropy () {
    return this.get32RandomBytes();
  }

  // Return n bytes of entropy
  randomBytes (n) {
    const numHashes = Math.ceil(n / 32);
    let b = '';
    for (let i = 0; i < numHashes; i++) {
      b += this.get32RandomBytes();
    }
    return b.slice(0, n*2);
  }

  createHash (type) {
    this.hash = new Hash(type);
    return this.hash;
  }
}

class Hash {
  constructor (type) {
    switch (type) {
      case 'sha256':
        this.hash = new hash.sha256;
        break;
      case 'rmd160':
        this.hash = new hash.ripemd160;
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

export default ReactNativeCrypto;
