var select = require('xpath.js')
  , dom = require('xmldom').DOMParser
  , SignedXml = require('../lib/signed-xml.js').SignedXml
  , FileKeyInfo = require('../lib/signed-xml.js').FileKeyInfo
  , xml_assert = require('./xml-assert.js')
  , fs = require('fs')

module.exports = {

  "signer creates correct signature values": function(test) {

    var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>"
    var sig = new SignedXml()
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
