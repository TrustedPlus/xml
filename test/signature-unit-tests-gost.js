var select = require('xpath.js')
  , DomParser = require('xmldom').DOMParser
  , SignedXml = require('../lib/signed-xml.js').SignedXml
  , FileKeyInfo = require('../lib/signed-xml.js').FileKeyInfo
  , xml_assert = require('./xml-assert.js')
  , fs = require('fs');

module.exports = {
  
  "signer creates correct signature values": function(test) {
    debugger;
    var xml = "<root><x xmlns=\"ns\" Id=\"_0\"></x><y attr=\"value\" Id=\"_1\"></y><z><w Id=\"_2\"></w></z></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/gost/private.pem");
    sig.keyInfoProvider = null;

    sig.addReference("//*[local-name(.)='x']", "http://www.w3.org/2001/10/xml-exc-c14n#", 'http://www.w3.org/2001/04/xmldsig-more#gostr3411');
    sig.addReference("//*[local-name(.)='y']", "http://www.w3.org/2001/10/xml-exc-c14n#", 'http://www.w3.org/2001/04/xmldsig-more#gostr3411');
    sig.addReference("//*[local-name(.)='w']", "http://www.w3.org/2001/10/xml-exc-c14n#", 'http://www.w3.org/2001/04/xmldsig-more#gostr3411');

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
    // remove signature from SignatureValue element
    doc.getElementsByTagName('SignatureValue')[0].childNodex[0].data = "";

    test.equal(expected, doc.toString(), "wrong signature format");

    test.done();
  }
}
