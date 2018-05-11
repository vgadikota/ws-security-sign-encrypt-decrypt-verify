package demo.wssec.common;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

public class Test {

	public static void main(String[] args) {
		
		/*String msgContent="<soap:Envelope xmlns:ns1=\"http://mybank.com/20180223/Customer\" xmlns:ns2=\"http://mybank.com/20180223/common\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">  <soap:Body>  <ns1:AccountCheck>  <ns1:AccountCheckRequest>  <ns2:CorrelationId>test</ns2:CorrelationId> <ns2:Channel>Internet</ns2:Channel> <ns2:ClientUserId>test_user</ns2:ClientUserId> <ns2:ApplicationId>InternetBanking</ns2:ApplicationId> <ns2:RequestDateTime>2008-11-15T09:52:58</ns2:RequestDateTime> <ns1:Tin>111111111</ns1:Tin> </ns1:AccountCheckRequest> </ns1:AccountCheck>  </soap:Body></soap:Envelope>";
		SignatureEncryptionTest signatureEncryptionTest = new SignatureEncryptionTest();
		try {
			signatureEncryptionTest.testSignatureEncryptionOutbound(msgContent);
			//signatureEncryptionTest.testSignatureEncryptionSymmetricOutbound(msgContent);
			//signatureEncryptionTest.testEncryptedDataTokenSecurityHeaderWithoutReferenceInbound(msgContent);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
		
		String encryptedContent = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns2=\"http://mybank.com/20180223/common\" xmlns:ns1=\"http://mybank.com/20180223/Customer\">\n" + 
				"  <soap:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" soap:mustUnderstand=\"1\"><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"G0bfaef31-ae85-469f-a193-33f8c8ade5a4\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/><dsig:KeyInfo xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><wsse:SecurityTokenReference xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"G3d2c0ece-4f82-4840-aa67-c4ad31320a0c\"><dsig:X509Data><dsig:X509IssuerSerial><dsig:X509IssuerName>CN=Mayank Mishra,OU=Dev,O=Apache,L=INDORE,ST=MP,C=IN</dsig:X509IssuerName><dsig:X509SerialNumber>1245003015</dsig:X509SerialNumber></dsig:X509IssuerSerial></dsig:X509Data></wsse:SecurityTokenReference></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>tGsEWgjKC1RMzl4xqIxmWSUmw+1frVFwUOzmrBo8sTh1kN+JkvIa3dMIE169f69MqNZrhkofQJVi&#xD;\n" + 
				"lWD0TO0HKh2UTdmXayw3YatTNdUgqRb/Tw3F0lw8Moy6uZ7WOshLpUQrv5QOrzRDunlDQFs9ojZw&#xD;\n" + 
				"ujz2bEkSIiPJ6+XGOI8=</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#G9cfc66c9-e5a0-44f1-b3df-2695bdf2b011\"/></xenc:ReferenceList></xenc:EncryptedKey><wsse:BinarySecurityToken xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"G79b70921-aded-4a40-8dc8-529550500a4d\">MIICNjCCAZ8CBEo1POgwDQYJKoZIhvcNAQEEBQAwYjELMAkGA1UEBhMCSU4xCzAJBgNVBAgTAk1Q&#xD;\n" + 
				"MQ8wDQYDVQQHEwZJTkRPUkUxDzANBgNVBAoTBkFwYWNoZTEMMAoGA1UECxMDRGV2MRYwFAYDVQQD&#xD;\n" + 
				"Ew1NYXlhbmsgTWlzaHJhMB4XDTA5MDYxNDE4MDk0NFoXDTE5MDYxMjE4MDk0NFowYjELMAkGA1UE&#xD;\n" + 
				"BhMCSU4xCzAJBgNVBAgTAk1QMQ8wDQYDVQQHEwZJTkRPUkUxDzANBgNVBAoTBkFwYWNoZTEMMAoG&#xD;\n" + 
				"A1UECxMDRGV2MRYwFAYDVQQDEw1NYXlhbmsgTWlzaHJhMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB&#xD;\n" + 
				"iQKBgQCdPhcimx7/CFX4H8isKEKCbRK6Kr+qeCMCby9I/Q/NY1bNqy6nsD+Y5BxSc2yCUnyLsRdm&#xD;\n" + 
				"AHIxUwRQ9X5s8FP9+T1nwuoPzBvjcoZqWgDhe9RvydkijuzsFan/PY4oemd5EIoQu80ZpcFqb00x&#xD;\n" + 
				"yDY3DkPgymXNsZ2uAM1ccsx90QIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAGXIE7pFNInlyjHnq89z&#xD;\n" + 
				"gvHJfZNE44El6Cd5V55JvL+LZUnynU2Y8WaUwD2Qvc1QTr9R7u6nhZ8abyB7TSx3idiN6KUSNtBH&#xD;\n" + 
				"OeWUTmfGbAJqO/J6R2A9J20KCvss28D05rRI3z52VQHnMBzgirL6M5ClWBZfl2Q3bNKnOImjoNhK</wsse:BinarySecurityToken><dsig:Signature xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"G5fd48fe5-4361-42f9-9c03-d19bf1e0e417\"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><c14nEx:InclusiveNamespaces xmlns:c14nEx=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ns2 ns1 soap\"/></dsig:CanonicalizationMethod><dsig:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><dsig:Reference URI=\"#G4741dfb3-c259-4e32-86bd-979fa76db126\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><c14nEx:InclusiveNamespaces xmlns:c14nEx=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ns2 ns1\"/></dsig:Transform></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><dsig:DigestValue>D082RJaYT5AD94po4CaPg/2Cx1M=</dsig:DigestValue></dsig:Reference><dsig:Reference URI=\"#Ga0116b2c-e5d3-4a50-b895-7bad0078bb34\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><c14nEx:InclusiveNamespaces xmlns:c14nEx=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"\"/></dsig:Transform></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><dsig:DigestValue>hoVmJvVccyq0G21UhBcxZ0bfeko=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EMvsKiUT8UpJq3zdkNgug4nLD4TiNNOKEqnPlimlNeCVe03OcgOD9zqpCMlB8A4hOxS7zVF+5Wab&#xD;\n" + 
				"46BGKoPm5Z0AQPmaf/CsOs4crApwzRIgAN4pr1jm5FurzHJw6Rec9Pc2wJC/RsSFqWezySKjwEND&#xD;\n" + 
				"/ORXGIm+b0xU56ZM2oU=</dsig:SignatureValue><dsig:KeyInfo Id=\"Gee4fb831-ddb8-41ea-b161-a8c981ddf8b2\"><wsse:SecurityTokenReference xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"G686f6c8c-40d9-43e0-b7ab-2fed727c4933\"><wsse:Reference URI=\"#G79b70921-aded-4a40-8dc8-529550500a4d\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wsse:SecurityTokenReference></dsig:KeyInfo></dsig:Signature><wsu:Timestamp xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"G4741dfb3-c259-4e32-86bd-979fa76db126\"><wsu:Created>2018-05-04T11:54:47.491Z</wsu:Created><wsu:Expires>2018-05-04T11:59:47.491Z</wsu:Expires></wsu:Timestamp></wsse:Security></soap:Header><soap:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"Ga0116b2c-e5d3-4a50-b895-7bad0078bb34\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"G9cfc66c9-e5a0-44f1-b3df-2695bdf2b011\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/><dsig:KeyInfo xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" wsse11:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\" wsu:Id=\"Gc359962a-2f72-4a5e-879e-4b0133f5fcc8\"><wsse:Reference URI=\"#G0bfaef31-ae85-469f-a193-33f8c8ade5a4\" ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\"/></wsse:SecurityTokenReference></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>KI4bJ1Vs1HpEMpzN5L1rvEb7VtN0ACctj0Y3sOQHjXDuNw08khdCaXjoaGBpx//DJdsCUuj4zAeP&#xD;\n" + 
				"/GCHBMpXpaF+d7YfZ3RqbBjnrNz2tQHz+Ld6SJHh8sCLxW1OiSMwqYHVYnHoeoOh8QTTeC8ssICB&#xD;\n" + 
				"ZJ7nv5OqRX+vcEB7sBK2k9aPLmYFOzD+bRuAMbQ/Tf32hhkPx35lrg5DjnbyDkNIBa13pml2cFUN&#xD;\n" + 
				"in16rMJiAp261EPCsqOM4yMBPLe28OoMR3CuWP3At4xWqAuUFJRt91yoy3VcPBSqahOwkLFh14et&#xD;\n" + 
				"XwvmpQR+FdMou9yUneK4TSclxZZ9rHtEJBR04aH0973rjq4vAkP3FTWmqjr3hZ0Uw2+iu8xvUf+M&#xD;\n" + 
				"RPAkKXwqu8sVH8c5Z4EFH5j96p8PkgTEU+gPsHCfz33KVC0g1RAtERz4U/Kg0BCIEl62Vi/6EpUv&#xD;\n" + 
				"CrfFfP0bGaYXH6F03oA0fP/ebEeJoJgqlvg4sIVCjIc9gsq19WNSUuxJRThi/Iub4COOStZfZf8g&#xD;\n" + 
				"ZpG2WBO094IGe+vTsNh3u3W7b1rqjgVQmx0EUq7ikEvZya/EWMCQYFxyTlBRl639zEJvgloSPeq9&#xD;\n" + 
				"43T56H8huJQ=&#xD;\n" + 
				"</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></soap:Body>\n" + 
				"</soap:Envelope>";
		
		
		SignatureDecryptionTest decryptionTest = new SignatureDecryptionTest();
		try {
			decryptionTest.testDecrypt(encryptedContent);
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			System.out.println(e.getCause().toString());
		}
		

	}

}
