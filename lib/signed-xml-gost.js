var select = require('xpath.js')
  , Dom = require('xmldom').DOMParser
  , utils = require('./utils')
  , ExclusiveCanonicalization = require('./exclusive-canonicalization').ExclusiveCanonicalization
  , ExclusiveCanonicalizationWithComments = require('./exclusive-canonicalization').ExclusiveCanonicalizationWithComments
  , EnvelopedSignature = require('./enveloped-signature').EnvelopedSignature
  , crypto = require('crypto')
  , fs = require('fs');

var GostSignedXml = require('./signed-xml.js').SignedXml;
var GostFileKeyInfo = require('./signed-xml.js').FileKeyInfo;
//exports.GostSignedXml = GostSignedXml;
exports.SignedXml = GostSignedXml;
exports.FileKeyInfo = GostFileKeyInfo
/**
 * A key info provider implementation
 *
 */

/**
 * Hash algorithm implementation
 *
 */
function GOST3411_94() {

  this.getHash = function(xml) {
    var gostHash = crypto.createHash('md_gost94')
    gostHash.update(xml, 'utf8')
    var res = gostHash.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#gostr3411"
  }
}

function GOST3411_12_256() {

  this.getHash = function(xml) {
    var gostHash = crypto.createHash('md_gost12_256')
    gostHash.update(xml, 'utf8')
    var res = gostHash.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#gostr34112012-256"
  }
}

function GOST3411_12_512() {

  this.getHash = function(xml) {
    var gostHash = crypto.createHash('md_gost12_512')
    gostHash.update(xml, 'utf8')
    var res = gostHash.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#gostr34112012-512"
  }
}


/**
 * Signature algorithm implementation
 *
 */
function GOST3410_01() {

  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {
    var signer = crypto.createSign("GOST R 34.11-94")
    signer.update(signedInfo)
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("GOST R 34.11-94")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"
  }

}


/**
 * Signature algorithm implementation
 *
 */
function GOST3410_12_256() {

  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {
    var signer = crypto.createSign("GOST R 34.11-2012 256-bit length")
    signer.update(signedInfo)
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("GOST R 34.11-2012 256-bit length")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#gostr34102012-gostr3411-256"
  }

}

/**
 * Signature algorithm implementation
 *
 */
function GOST3410_12_512() {

  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {
    var signer = crypto.createSign("GOST R 34.11-2012 512-bit length")
    signer.update(signedInfo)
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("GOST R 34.11-2012 512-bit length")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#gostr34102012-gostr3411-512"
  }
}
/*
function HMACSHA1() {
    this.verifySignature = function(str, key, signatureValue) {
        var verifier = crypto.createHmac("SHA1", key);
        verifier.update(str);
        var res = verifier.digest('base64');
        return res === signatureValue;
    };

    this.getAlgorithmName = function() {
        return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    };

    this.getSignature = function(signedInfo, signingKey) {
        var verifier = crypto.createHmac("SHA1", signingKey);
        verifier.update(signedInfo);
        var res = verifier.digest('base64');
        return res;
    };
}
*/

/**
* Xml signature implementation
*
* @param {string} idMode. Value of "wssecurity" will create/validate id's with the ws-security namespace
*/
/*
function SignedXml(idMode, options) {
  this.options = options || {};
  this.idMode = idMode
  this.references = []
  this.id = 0
  this.signingKey = null
  this.signatureAlgorithm = this.options.signatureAlgorithm || "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  this.keyInfoProvider = null
  this.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
  this.signedXml = ""
  this.signatureXml = ""
  this.signatureNode = null
  this.signatureValue = ""
  this.originalXmlWithIds = ""
  this.validationErrors = []
  this.keyInfo = null
  this.idAttributes = [ 'Id', 'ID' ];
  if (this.options.idAttribute) this.idAttributes.splice(0, 0, this.options.idAttribute);
}

SignedXml.CanonicalizationAlgorithms = {
  'http://www.w3.org/2001/10/xml-exc-c14n#': ExclusiveCanonicalization,
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments': ExclusiveCanonicalizationWithComments,
  'http://www.w3.org/2000/09/xmldsig#enveloped-signature': EnvelopedSignature
}
*/
GostSignedXml.HashAlgorithms['http://www.w3.org/2001/04/xmldsig-more#gostr3411'] = GOST3411_94;
GostSignedXml.SignatureAlgorithms['http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411'] = GOST3410_01;
/*
SignedXml.HashAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#sha1': SHA1,
  'http://www.w3.org/2001/04/xmlenc#sha256': SHA256,
  'http://www.w3.org/2001/04/xmlenc#sha512': SHA512
}

SignedXml.SignatureAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': RSASHA1,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': RSASHA256,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': RSASHA512,
  'http://www.w3.org/2000/09/xmldsig#hmac-sha1': HMACSHA1
}
*/

