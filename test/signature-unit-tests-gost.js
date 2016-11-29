var select = require('xpath.js'),
  DomParser = require('xmldom').DOMParser,
  GostSignedXml = require('../lib/signed-xml-gost.js').GostSignedXml,
  GostFileKeyInfo = require('../lib/signed-xml-gost.js').GostFileKeyInfo,
  xml_assert = require('./xml-assert.js'),
  fs = require('fs');

module.exports = {
  
  "signer creates correct signature value with GOST 2001": function(test) {
    var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>";
    var sig = new GostSignedXml();
    sig.signingKey = fs.readFileSync("./test/gost/private.pem");
    sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411';
    sig.keyInfoProvider = null;

    sig.addReference("//*[local-name(.)='x']", ["http://www.w3.org/2001/10/xml-exc-c14n#"], 'http://www.w3.org/2001/04/xmldsig-more#gostr3411');
    sig.addReference("//*[local-name(.)='y']", ["http://www.w3.org/2001/10/xml-exc-c14n#"], 'http://www.w3.org/2001/04/xmldsig-more#gostr3411');
    sig.addReference("//*[local-name(.)='w']", ["http://www.w3.org/2001/10/xml-exc-c14n#"], 'http://www.w3.org/2001/04/xmldsig-more#gostr3411');

    sig.computeSignature(xml);
    var signedXml = sig.getSignedXml();
    var expected =  "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
                    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                    "<SignedInfo>" +
                    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411\"/>" +
                    "<Reference URI=\"#_0\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/>" +
                    "<DigestValue>IL0BMorWqUsTIUOpcTKrf2dNYUbzgcO0X/pXr9jMQ9U=</DigestValue>" +
                    "</Reference>" +
                    "<Reference URI=\"#_1\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/>" +
                    "<DigestValue>L1MIC6+kkEnGKgtBGQPu4JpctCAmuJZ3aKSudVAsyuU=</DigestValue>" +
                    "</Reference>" +
                    "<Reference URI=\"#_2\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/>" +
                    "<DigestValue>hdvKiumKZUiDTEFrQBBogGQJjdTkYNCLvSlF9kVsDSM=</DigestValue>" +
                    "</Reference>" +
                    "</SignedInfo>" +
                    "<SignatureValue></SignatureValue>" +
                    "</Signature>" +
                    "</root>";

    var doc = new DomParser().parseFromString(signedXml);
    // remove signature from SignatureValue element for checking
    var signatureValueNode = doc.getElementsByTagName('SignatureValue')[0].childNodes[0];
    var signetureValueBase64 = signatureValueNode.data;
    signatureValueNode.data = "";
    // check format without signature
    test.equal(expected, doc.toString(), "wrong signature format");

    // check SignatureValue
    var signedXml = sig.getSignedXml();
    var doc = new DomParser().parseFromString(signedXml);
    var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new GostSignedXml();
    sig.keyInfoProvider = new GostFileKeyInfo('./test/gost/public.pem');
    sig.loadSignature(signature.toString());
    test.ok(sig.checkSignature(xml));

    test.done();
  },

   "signer creates correct signature value with RSA": function(test) {

    var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>"
    var sig = new GostSignedXml()
    sig.signingKey = fs.readFileSync("./test/static/client.pem")
    sig.keyInfoProvider = null

    sig.addReference("//*[local-name(.)='x']")
    sig.addReference("//*[local-name(.)='y']")
    sig.addReference("//*[local-name(.)='w']")

    sig.computeSignature(xml)
    var signedXml = sig.getSignedXml()
    var expected =  "<root><x xmlns=\"ns\" Id=\"_0\"/><y attr=\"value\" Id=\"_1\"/><z><w Id=\"_2\"/></z>" +
                    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                    "<SignedInfo>" +
                    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
                    "<Reference URI=\"#_0\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
                    "</Reference>" +
                    "<Reference URI=\"#_1\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
                    "</Reference>" +
                    "<Reference URI=\"#_2\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                    "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
                    "</Reference>" +
                    "</SignedInfo>" +
                    "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
                    "</Signature>" +
                    "</root>"

    test.equal(expected, signedXml, "wrong signature format")

    test.done();
  }
}
