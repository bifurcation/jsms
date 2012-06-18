// Basic JOSE library
// -- Encryption: AES-CCM (128-bit keys)
// -- Key encipherment: AES, RSA-OAEP
// -- Signing: RSA
// -- Hash: SHA256
// -- MAC: HMAC-SHA256
//
// Dependencies (from npm):
// -- execSync
// -- b64url
//
// XXX:
// -- Uses python/openssl for the crypto primitives
// -- Does not support detached JSMS; add content to object before verifying
// -- Does not support creation of multiple signatures
// -- Only supports keys specified by value
//

var execSync = require('exec-sync');
var b64url = require('b64url');

// This gets around the shortfalls of JS crypto by using a python shim
// But to change libraries, all you have to change is this layer
var _JOSE_Crypto = {
    algorithms: [
        // Signing
        "rsa",
        // Digest
        "sha256",
        // MAC
        "hs256",
        // Encryption
        "aes128-ccm",
        // Key Encipherment
        "aes",
        "rsaes-oaep"
        // Key Agreement
        // [none]
    ],

    supported: function(name) {
        return (this.algorithms.indexOf(name) > -1);
    },

    random: function(bytes) {
        return this.invoke(["random", bytes]);
    },
    sign_pkcs1_sha256: function(n, e, d, content) {
        return this.invoke(["sign_pkcs1_sha256", n, e, d, content]);
    },
    verify_pkcs1_sha256: function(n, e, content, sig) {
        return this.invoke(["verify_pkcs1_sha256", n, e, content, sig]);
    },
    aes_key_wrap: function(key, p) {
        return this.invoke(["aes_key_wrap", key, p]);
    },
    aes_key_unwrap: function(key, c) {
        return this.invoke(["aes_key_unwrap", key, c]);
    },
    rsa_oaep_key_wrap: function(n, e, p) {
        return this.invoke(["rsa_oaep_key_wrap", n, e, p]);
    },
    rsa_oaep_key_unwrap: function(n, e, d, c) {
        return this.invoke(["rsa_oaep_key_unwrap", n, e, d, c]);
    },
    hmac_sha256: function(key, content) {
        return this.invoke(["hmac_sha256", key, content]);
    },
    encrypt_gen_aead_AES128CBC_HMACSHA256: function(key, n, iv, content) {
        return this.invoke(["encrypt_gen_aead_AES128CBC_HMACSHA256", key, n, iv, content]);
    },
    decrypt_gen_aead_AES128CBC_HMACSHA256: function(key, n, iv, content) {
        return this.invoke(["decrypt_gen_aead_AES128CBC_HMACSHA256", key, n, iv, content]);
    },
    encrypt_AES128CCM: function(key, n, M, content, assoc) {
        return this.invoke(["encrypt_AES128CCM", key, n, M, content, assoc]);
    },
    decrypt_AES128CCM: function(key, n, M, content, assoc) {
        return this.invoke(["decrypt_AES128CCM", key, n, M, content, assoc]);
    },

    invoke: function(args) {
        var cmd = "./chelp.py '" + args.join("' '") + "'";
        //console.log("CRYPTO-HELPER: " + cmd);
        var result = execSync(cmd);
        //console.log("CRYPTO-HELPER-RESULT: " + result);
        if (result.substr(0,1) == "-") {
            throw reseult.substr(1);
        } else {
            return result.substr(1);
        }
    }
};

// Constants used in the JOSE syntax
var _JOSE_Const = {

    // Tokens
    version: 1,
    SignedData: "signed",
    AuthenticatedData: "authenticated",
    EncryptedData: "encrypted",

    // Top-level fields
    f: {
        version: "version",
        type: "type",
        content: "content"
    },

    // SignedData fields
    sdf: {
        digestAlgorithm: "digestAlgorithm",
        signatures: "signatures",
        certificates: "certificates",
        certificatesURI: "certificatesURI"
    },

    // AuthenticatedData fields
    adf: {
        algorithm: "algorithm",
        mac: "mac",
        keys: "keys",
        keyId: "keyId"
    },

    // EncryptedData fields
    edf: {
        algorithm: "algorithm",
        keys: "keys",
        mac: "mac"
    },

    // AlgorithmIdentifier fields
    aif: {
        name: "name",
        // AES-CCM parameters
        m: "m",
        n: "n"
    },

    sigdf: {
        signatureAlgorithm: "signatureAlgorithm",
        signature: "signature",
        key: "key",
    },

    // PublicKey fields
    pkf: {
        type: "type",
        id: "id",
        uri: "uri",
        // RSA parameters
        n: "n",
        e: "e"
    },

    // WrappedKey fields
    wkf: {
        type: "type",
        algorithm: "algorithm",
        encryptedKey: "encryptedKey",
        KEKIdentifier: "KEKIdentifier",
        originatorKey: "originatorKey",
        recipientKey: "recipientKey",
        userKeyMaterial: "userKeyMaterial",
        // Type values
        encryption: "encryption",
        transport: "transport",
        agreement: "agreement"
    }
};

// Class to verify that a JOSE object is one that we can process
// -- Format MUST be valid, in terms of fields present
// -- Algorithms MUST be supported
var _JOSE_Support = {
    notBase64: /[^a-zA-Z0-9_=-]/,
    c: _JOSE_Const,

    // Top-level objects
    isJOSEObject: function(x) {
        return (!(x instanceof Object)) &&
            (x[this.c.f.version] == this.c.version) &&
            (this.isSignedData(x) ||
             this.isAuthenticatedData(x) ||
             this.isEncryptedData(x));
    },
    isSignedData: function(x) {
        return (x instanceof Object) &&
            (x[this.c.f.type] == this.c.SignedData) && 
            (this.isAlgorithmIdentifier(x[this.c.sdf.digestAlgorithm])) &&
            (this.isSignatureList(x[this.c.sdf.signatures]));
        // Does not validate certificate information
    },
    isAuthenticatedData: function(x) {
        return (x instanceof Object) &&
            (x[this.c.f.type] == this.c.AuthenticatedData) &&
            (this.isAlgorithmIdentifier(x[this.c.adf.algorithm])) &&
            (this.isByteString(x[this.c.adf.mac])) &&
            (this.isWrappedKeyList(x[this.c.adf.keys]) ||
             this.isByteString(x[this.c.adf.keyId]) );
    },
    isEncryptedData: function(x) {
        return (x instanceof Object) &&
            (x[this.c.f.type] == this.c.EncryptedData) &&
            (this.isAlgorithmIdentifier(x[this.c.edf.algorithm])) &&
            (this.isWrappedKeyList(x[this.c.edf.keys]));
        // Does not check presence of MAC
    },
   

    // Supporting types
    isAlgorithmIdentifier: function(x) {
        // Only checks parameters for supported algorithms
        if ((typeof(x) == "string") && (_JOSE_Crypto.supported(x))) {
            return true;
        } else if ((typeof(x) == "object") && (_JOSE_Crypto.supported(x[this.c.aif.name]))) {
            if (x[this.c.aif.name] == "aes-ccm") {
                return (this.isByteString(x[this.c.aif.n])) &&
                    (this.isNumber(x[this.c.aif.m]));
            } else {
                return true;
            }
        } else return false;
    },
    isSignature: function(x) {
        return (x instanceof Object) && 
            (this.isAlgorithmIdentifier(x[this.c.sigdf.signatureAlgorithm])) &&
            (this.isPublicKey(x[this.c.sigdf.key])) &&
            (this.isByteString(x[this.c.sigdf.signature]));
    },
    isPublicKey: function(x) {
        // Only checks parameters for supported algorithms
        if (!(x instanceof Object)) { return false; }
        var type = x[this.c.pkf.type];
        if ((this.isString(type)) && _JOSE_Crypto.supported(type)) {
            if (type == "rsa") {
                return ((this.isByteString(x[this.c.pkf.n])) &&
                    (this.isByteString(x[this.c.pkf.e])))
            } else {
                return true;
            }
        } else {
            return (this.isByteString(x[this.c.pkf.id])) ||
                (this.isString(x[this.c.pkf.uri]));
        }
    },
    isWrappedKey: function(x) {
        if (!(x instanceof Object)) { return false; }
        var type = x[this.c.wkf.type]
        var algorithm = x[this.c.wkf.algorithm]
        var encryptedKey = x[this.c.wkf.encryptedKey]

        if ((!this.isAlgorithmIdentifier(algorithm)) || 
            (!this.isByteString(encryptedKey))) {
            return false;
        }

        if (type == this.c.wkf.encryption) {
            return (this.isByteString(x[this.c.wkf.KEKIdentifier]));
        } else if (type == this.c.wkf.transport) {
            return (this.isPublicKey(x[this.c.wkf.recipientKey]));
        } else if (type == this.c.wkf.agreement) {
            return (this.isPublicKey(x[this.c.wkf.recipientKey]))
                && (this.isPublicKey(x[this.c.wkf.originatorKey]));
        } else {
            return false;
        }
    },

    isWrappedKeyList: function(x) {
        if (x && !(x instanceof Array)) { return false; }
        for (i in x) {
            if (!this.isWrappedKey(x[i])) { return false; }
        }
        return true;
    },
    isSignatureList: function(x) {
        if (!(x instanceof Array)) {  return false; }
        for (i in x) {
            if (!this.isSignature(x[i])) { return false; }
        }
        return true;
    },

    // Basic Types
    isByteString: function(x) {
        return (typeof(x) == "string") && !this.notBase64.test(x);
    },
    isNumber: function(x) { return typeof(x) == "number" },
    isString: function(x) { return typeof(x) == "string" }
};


_JOSE_KeyStore = {};

_JOSE_DownMap = {
    "KEKIdentifier": "i",
    "agreement": "ag",
    "algorithm": "a",
    "authenticated": "au",
    "certificates": "ce",
    "certificatesURI": "cu",
    "content": "c",
    "digestAlgorithm": "da",
    "encrypted": "en",
    "encryptedKey": "ek",
    "encryption": "ec",
    "id": "i",
    "key": "k",
    "keyId": "ki",
    "keys": "ks",
    "mac": "mac",
    "name": "nm",
    "originatorKey": "o",
    "recipientKey": "r",
    "signature": "sg",
    "signatureAlgorithm": "sa",
    "signatures": "ss",
    "signed": "s",
    "transport": "tr",
    "type": "t",
    "uri": "u",
    "userKeyMaterial": "uk",
    "version": "v",
};
    
_JOSE_UpMap = {
    "i": "KEKIdentifier",
    "ag": "agreement",
    "a": "algorithm",
    "au": "authenticated",
    "ce": "certificates",
    "cu": "certificatesURI",
    "c": "content",
    "da": "digestAlgorithm",
    "en": "encrypted",
    "ek": "encryptedKey",
    "ec": "encryption",
    "i": "id",
    "k": "key",
    "ki": "keyId",
    "ks": "keys",
    "mac": "mac",
    "nm": "name",
    "o": "originatorKey",
    "r": "recipientKey",
    "sg": "signature",
    "sa": "signatureAlgorithm",
    "ss": "signatures",
    "s": "signed",
    "tr": "transport",
    "t": "type",
    "u": "uri",
    "uk": "userKeyMaterial",
    "v": "version",
};



JOSE = {
    // Key management functions
    generateSymmetricKey: function(bytes) {
        var key = _JOSE_Crypto.random(bytes);
        var id = this.addKey(key);
        return id;
    },
    addKey: function(key) {
        newID = _JOSE_Crypto.random(8);
        _JOSE_KeyStore[newID] = key;
        return newID;
    },    
    findKeyPair: function(key) {
        if (_JOSE_Support.isPublicKey(key)) {
            // Search by value, but only on public key
            for (id in _JOSE_KeyStore) {
                if ((key.n == _JOSE_KeyStore[id].n)&&
                    (key.e == _JOSE_KeyStore[id].e)) {
                    return _JOSE_KeyStore[id];
                }
            }
        } 
        // If it's not a public key or we didn't find one
        return false;
    },
    getKey: function(id) {  // NOT SAFE
        return _JOSE_KeyStore[id];
    },

    // Key wrap/unwrap functions
    wrapKey: function(cek, keyID) {
        var key = _JOSE_KeyStore[keyID];
        if (!key) {
            throw "Unkown key identifier";
        }

        var wcek = undefined;
        if (_JOSE_Support.isByteString(key)) {
            var wk = _JOSE_Crypto.aes_key_wrap(key, cek);
            wcek = {
                type: "encryption",
                algorithm: "aes",
                encryptedKey: wk,
                KEKIdentifier: keyID
            }
        } else if (_JOSE_Support.isPublicKey(key)) {
            var wk = _JOSE_Crypto.rsa_oaep_key_wrap(key.n, key.e, cek);
            var pubkey = { "type": key.type, "n": key.n, "e": key.e };
            wcek = {
                type: "transport",
                algorithm: "rsaes-oaep",
                encryptedKey: wk,
                recipientKey: key
            }
        } else {
            throw "Unknown key format"
        }
        return wcek;
    },

    unwrapKey: function(keys) {
        for (var i=0; i<keys.length; ++i) {
            if (keys[i].type == "encryption") {
                key = _JOSE_KeyStore[keys[i].KEKIdentifier];
                if (key && keys[i].algorithm == "aes") {
                    return _JOSE_Crypto.aes_key_unwrap(key, keys[i].encryptedKey)
                }
            } else if (keys[i].type == "transport") {
                key = JOSE.findKeyPair(keys[i].recipientKey);
                if (key && keys[i].algorithm == "rsaes-oaep") { 
                    return _JOSE_Crypto.rsa_oaep_key_unwrap(
                            key.n, key.e, key.d, keys[i].encryptedKey);
                }
            } else if (keys[i].type == "agreement") {
                // No support for key agreement right now
            }
        }
        return undefined;
    },



    // SignedData
    sign: function(content, keyID) {
        // Compute the signature
        var key = _JOSE_KeyStore[keyID];
        if (!_JOSE_Support.isPublicKey(key)) {
            throw "Unknown key identifier, or not a public key";
        } else if (!key.d) {
            throw "Private key required for signing";
        }
        var bcontent = b64url.encode(content);
        var sigval = _JOSE_Crypto.sign_pkcs1_sha256(key.n, key.e, key.d, bcontent);
        var tempd = key.d;
        delete key.d;
        var sig = {
            signatureAlgorithm: "rsa",
            key: key,
            signature: sigval
        };
        key.d = tempd;

        // Encode the JSMS
        var jsms = {
            version: 1,
            type: "signed",
            digestAlgorithm: "sha256",
            content: bcontent,
            signatures: [sig]
        };
        return JSON.stringify(jsms);  
    },
    verify: function(object) {
        var jsms = JSON.parse(object);
        if (!_JOSE_Support.isSignedData(jsms)) {
            throw "Invalid SignedData object";
        }

        // Figure out which signatures are valid
        var validPublicKeys = [];
        var sigs = jsms.signatures;
        for (var i=0; i<sigs.length; ++i) {
            if (!_JOSE_Support.isPublicKey(sigs[i].key)) {
                continue;
            }
            var result = _JOSE_Crypto.verify_pkcs1_sha256(
                sigs[i].key.n, sigs[i].key.e, jsms.content, sigs[i].signature)
            if (result = "True") {
                validPublicKeys.push(sigs[i].key);
            }
        }

        return validPublicKeys;
    },

    // AuthenticatedData
    auth_mac: function(content, keyID) {
        // Generate a random CEK and encrypt it
        var cek = _JOSE_Crypto.random(64);
        var wcek = JOSE.wrapKey(cek, keyID);

        // MAC the content
        var bcontent = b64url.encode(content);
        var mac = _JOSE_Crypto.hmac_sha256(cek, bcontent);

        // Generate the JSMS
        var jsms = {
            version: 1,
            type: "authenticated",
            algorithm: "hs256",
            content: bcontent,
            mac: mac,
            keys: [wcek]
        }
        return JSON.stringify(jsms);    
    },
    auth_mac_direct: function(content, keyID) {
        // Generate a random CEK and encrypt it
        var cek = _JOSE_KeyStore[keyID];
        if (!_JOSE_Support.isByteString(cek)) {
            throw "Unknown key identifier";
        }

        // MAC the content
        var bcontent = b64url.encode(content);
        var mac = _JOSE_Crypto.hmac_sha256(cek, bcontent);

        // Generate the JSMS
        var jsms = {
            version: 1,
            type: "authenticated",
            algorithm: "hs256",
            content: bcontent,
            mac: mac,
            keyId: keyID
        }
        return JSON.stringify(jsms);    
    },
    auth_verify: function(object) {
        // Fixed algorithm parameters
        var jsms = JSON.parse(object);
        if (!_JOSE_Support.isAuthenticatedData(jsms)) {
            throw "Invalid AuthenticatedData object";
        }

        // Find a keyId or a WrappedKey we can unwrap, then unwrap the key
        var cek = undefined;
        if (jsms.keyId && _JOSE_KeyStore[jsms.keyId]) {
            cek = _JOSE_KeyStore[jsms.keyId];
        } else {
            cek = JOSE.unwrapKey(jsms.keys);
        }
        if (!cek) {
            throw "No usable wrapped key found";
        }

        // Decrypt the content 
        // Throws on integrity check failure
        if (jsms.algorithm != "hs256") {
            throw "Unkown MAC algorithm";
        }
        var macResult = _JOSE_Crypto.hmac_sha256(cek, jsms.content);

        if (macResult == jsms.mac) {
            return true;
        } else {
            return false;
        }
    },

    // EncryptedData
    // Only supports AES-CCM for the encryption algorithm
    encrypt: function(content, keyID) {
        // Fixed algorithm parameters (for simplicity)
        M = 8;
        n = _JOSE_Crypto.random(10);
        assoc = "";

        // Generate a random CEK and encrypt it
        var cek = _JOSE_Crypto.random(16);
        var wcek = JOSE.wrapKey(cek,keyID);

        // Encrypt the content
        var bcontent = b64url.encode(content);
        var econtent = _JOSE_Crypto.encrypt_AES128CCM(cek, n, M, bcontent, assoc);

        // Generate the JSMS
        var jsms = {
            version: 1,
            type: "encrypted",
            algorithm: {
                name: "aes128-ccm", 
                n: n, 
                m: M
            },
            content: econtent,
            keys: [wcek]
        }
        return JSON.stringify(jsms);
    },
    decrypt: function(object) {
        // Fixed AES-CCM parameters
        assoc = "";

        var jsms = JSON.parse(object);
        if (!_JOSE_Support.isEncryptedData(jsms)) {
            throw "Invalid EncryptedData object";
        }

        // TODO Perform some validation

        // Find a WrappedKey we can unwrap, then unwrap the key
        var cek = JOSE.unwrapKey(jsms.keys);
        if (!cek) {
            throw "No usable wrapped key found";
        }

        // Decrypt the content 
        // Throws on integrity check failure
        if (jsms.algorithm.name != "aes128-ccm") {
            throw "Unkown encryption algorithm";
        }
        var bcontent = _JOSE_Crypto.decrypt_AES128CCM(
            cek, jsms.algorithm.n, jsms.algorithm.m, jsms.content, assoc
        );
        var content = b64url.decode(bcontent);

        return content;
    },

    // Functions for handling compact form
    // NB: The above functions only handle/generate non-compact form
    compact_j: function(xj) {
        var x = JSON.parse(xj);
        x = JOSE.compact(x);
        return JSON.stringify(x);
    },
    compact: function(x) {
        if ((typeof(x) == "string")&&(x in _JOSE_DownMap)) {
            return _JOSE_DownMap[x];
        } else if (!(x instanceof Object) && !(x instanceof Array)) {
            return x;
        }

        // Arrays are objects, but not vice versa
        var y;
        if (x instanceof Object) { y = {}; }
        if (x instanceof Array) { y = []; }
        for (i in x) { 
            if (i in _JOSE_DownMap) {
                y[_JOSE_DownMap[i]] = JOSE.compact(x[i]);
            } else {
                y[i] = JOSE.compact(x[i]);
            };
        }
        return y;
    },
   
    uncompact_j: function(xj) {
        var x = JSON.parse(xj);
        x = JOSE.uncompact(x);
        return JSON.stringify(x);
    },
    uncompact: function(x) {
        if ((typeof(x) == "string")&&(x in _JOSE_UpMap)) {
            return _JOSE_UpMap[x];
        } else if (!(x instanceof Object) && !(x instanceof Array)) {
            return x;
        }

        // Arrays are objects, but not vice versa
        var y;
        if (x instanceof Object) { y = {}; }
        if (x instanceof Array) { y = []; }
        for (i in x) { 
            if (i in _JOSE_UpMap) {
                y[_JOSE_UpMap[i]] = JOSE.uncompact(x[i]);
            } else {
                y[i] = JOSE.uncompact(x[i]);
            };
        }
        return y;
    }
};

module.exports = JOSE;
