var http = require('http');
var jose = require('./jose');
var execSync = require('exec-sync');

// Symmetric key 
var keyID = jose.generateSymmetricKey(16);
var key = jose.getKey(keyID);

// Asymmetric key pair
var keyPair = {
    type: "rsa",
    n: "AfWGinFrdktMCi4LkD_vcIsqc0m4JSS0rNDk_5Zdi8fwja_qH0M7d3U4tPUw7L0gP1iSMakdTKX0S7uTV_v9FeY8_WrxDgbphrH9Zaz0PvTLOuiKfRkMWK5A6nzl_PdP7_ujDWkvHKhWcJtM7irdn9K059X21EDtuqGJyq7_v_c_",
    e: "AQAB",
    d: "EMwfyOqzfJQgZyhl_W40k8SpNdfgDpmqjBiPYubhLqIk7LZns6XDO37ZuLiZxT_WP04uMZ7UmV5URwUJVlxEpmfozhtLooCTP1oWtRQQjhTaPz1f5nRKoHsO8e3PZY7O44ut2prRWNNxYxDk52rH9GTECqGAmDNb1fhe6zX4KJk="
};
var keyPairID = jose.addKey(keyPair);

// The content we'll be protecting
var content = "Attack at dawn!";

function signTest() {
    // Signing with an asymmetric key pair
    var sdata = jose.sign(content, keyPairID);
    var svalid = jose.verify(sdata);
    if (svalid.length > 0) { console.log("At least one valid signature found"); }
    else                   { console.log("No valid signatures found"); }
}

function authTest() {
    // Authentication with direct key
    var adata1 = jose.auth_mac_direct(content, keyID);
    var avalid1 = jose.auth_verify(adata1);
    if (avalid1) { console.log("Valid MAC with direct key"); }
    else         { console.log("INVALID MAC with direct key"); }
    
    // Authentication with symmetric key wrapping
    var adata1 = jose.auth_mac(content, keyID);
    var avalid1 = jose.auth_verify(adata1);
    if (avalid1) { console.log("Valid MAC with symmetric-key wrapping"); }
    else         { console.log("INVALID MAC with symmetric-key wrapping"); }
    
    // Authentication with asymmetric key wrapping
    var adata1 = jose.auth_mac(content, keyPairID);
    var avalid1 = jose.auth_verify(adata1);
    if (avalid1) { console.log("Valid MAC with asymmetric-key wrapping"); }
    else         { console.log("INVALID MAC with asymmetric-key wrapping"); }
}

function encryptTest() {
    // Encryption with symmetric key wrapping
    var edata1 = jose.encrypt(content, keyID);
    var decrypt1 = jose.decrypt(edata1);
    console.log("[symm-wrap]  Decrypted content: ", decrypt1);
    
    // Encryption with asymmetric key wrapping 
    var edata2 = jose.encrypt(content, keyPairID);
    var decrypt2 = jose.decrypt(edata2);
    console.log("[asymm-wrap] Decrypted content: ", decrypt2);
}

function compactTest() {
    // Generate a SignedData object
    var edata = jose.encrypt(content, keyPairID);
    // ... compact it
    var cedata = jose.compact_j(edata);
    console.log(cedata);
    // ... then uncompact
    var ucedata = jose.uncompact_j(cedata);
    console.log(ucedata);
    // ... and see if it validates
    var decrypt = jose.decrypt(ucedata);
    console.log("[compact] Decrypted content: ", decrypt);

}

function generateExamples() {
    sdata = jose.sign(content, keyPairID);
    adata = jose.auth_mac(content, keyID);
    adata2 = jose.auth_mac_direct(content, keyID);
    adata2c = jose.compact_j(adata2);
    edata = jose.encrypt(content, keyPairID);

    console.log(key);
    console.log(keyPair);
    console.log(keyID);
    console.log("==========");
    console.log(sdata)
    console.log("==========");
    console.log(adata)
    console.log("==========");
    console.log(adata2c)
    console.log("==========");
    console.log(edata)
}

//signTest();
//authTest();
//encryptTest();
//compactTest();
generateExamples();
