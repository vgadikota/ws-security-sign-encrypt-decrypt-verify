package demo.wssec.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class SignatureDecryptionTest extends AbstractTestBase {
	
	public Document testDecrypt(String content) throws SAXException, ParserConfigurationException, Exception {
	 //done encryption; now test decryption:
		
		InputStream sourceDocument = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
		
	 ByteArrayOutputStream baos = new ByteArrayOutputStream();
	 baos.write(content.getBytes());
    
        String action = /*WSSConstants.USERNAMETOKEN + " " + */WSSConstants.TIMESTAMP + " " + WSSConstants.SIGNATURE+ " "+WSSConstants.ENCRYPT;
        Document decryptedDoc =  doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
      //  System.out.println(XmlUtil.toString(decryptedDoc));
    
	return decryptedDoc;

}
}
