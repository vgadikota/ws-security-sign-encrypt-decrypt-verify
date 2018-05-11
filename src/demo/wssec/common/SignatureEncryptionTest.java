package demo.wssec.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;
//import org.junit.Assert;
//import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SignatureEncryptionTest extends AbstractTestBase {

    
    public  Document testSignatureEncryptionOutbound(String content) throws Exception {

        ByteArrayOutputStream baos;
        
            /*WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("serverx509v1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("clientx509v1");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );*/
        	
        	String client_Encrypt_path = new File(this.getClass().getResource("Client_Encrypt.properties").getFile()).getPath();
        	String client_Sign_path = new File(this.getClass().getResource("Client_Sign.properties").getFile()).getPath();
        	
        	 Properties encCryptoProperties =
                     CryptoFactory.getProperties(client_Encrypt_path,SignatureEncryptionTest.class.getClassLoader());
                 Properties sigCryptoProperties =
                     CryptoFactory.getProperties(client_Sign_path, SignatureEncryptionTest.class.getClassLoader());

                 WSSSecurityProperties properties = new WSSSecurityProperties();
                 //properties.addAction(WSSConstants.USERNAMETOKEN);
                 properties.addAction(WSSConstants.TIMESTAMP);
                 properties.addAction(WSSConstants.SIGNATURE);
                 properties.addAction(WSSConstants.ENCRYPT);

                 properties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                 properties.setTokenUser("abcd");
                 properties.setSignatureUser("clientx509v1");
                 properties.setEncryptionUser("serverx509v1");

                 //properties.setEncryptionCryptoProperties(encCryptoProperties);
                 properties.loadEncryptionKeystore(this.getClass().getResource("client-truststore.jks"), "storepassword".toCharArray());
                 
                 properties.setEncryptionKeyIdentifier(
                     WSSecurityTokenConstants.KeyIdentifier_IssuerSerial
                 );
                 properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
                 
                 //properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
                 //properties.addEncryptionPart(new SecurePart(new QName(WSSConstants.NS_WSSE10,"UsernameToken"), SecurePart.Modifier.Element));
                 properties.addEncryptionPart(new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Content));

                 //properties.setSignatureCryptoProperties(sigCryptoProperties);
                 properties.loadSignatureKeyStore(this.getClass().getResource("client-keystore.jks"), "storepassword".toCharArray());
                 properties.setSignatureKeyIdentifier(
                     WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE
                 );
                 properties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
                 properties.addSignaturePart(
                     new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
                 );
                 properties.addSignaturePart(
                     new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
                 );
                 /*properties.addSignaturePart(
                     new SecurePart(new QName("http://www.w3.org/2005/08/addressing", "ReplyTo"),
                         SecurePart.Modifier.Element)
                 );*/
                 properties.setCallbackHandler(new UTPasswordCallback());

                 InputStream sourceDocument = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
                 
            //InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("plain-soap-1.1.xml");
            baos = doOutboundSecurity(properties, sourceDocument);

            Document encryptedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            
            System.out.println(XmlUtil.toString(encryptedDoc));
        

        //done encryption; now test decryption:
       /* {
            String action = WSSConstants.USERNAMETOKEN + " " + WSSConstants.TIMESTAMP + " " + WSSConstants.SIGNATURE+ " "+WSSConstants.ENCRYPT;
            Document decryptedDoc =  doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
            System.out.println(XmlUtil.toString(decryptedDoc));
        }*/
        return encryptedDoc;
    }

    
    /*public  void testEncryptionSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

            // Symmetric Key
            String keyAlgorithm =
                JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES128);
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES128);
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken =
                new GenericOutboundSecurityToken(ekId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);

            final SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public    OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                    return encryptedKeySecurityToken;
                }

                @Override
                public    String getId() {
                    return ekId;
                }
            };

            final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
            outboundSecurityContext.putList(SecurityEvent.class, new ArrayList<SecurityEvent>());

            // Save Token on the security context
            outboundSecurityContext.registerSecurityTokenProvider(encryptedKeySecurityTokenProvider.getId(), encryptedKeySecurityTokenProvider);
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, encryptedKeySecurityTokenProvider.getId());

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = new ByteArrayOutputStream();
            XMLStreamWriter xmlStreamWriter =
                wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }*/

    
   /* public  void testSignatureEncryptionSymmetricOutbound(String content) throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getResource("client-truststore.jks"), "storepassword".toCharArray());
            securityProperties.setEncryptionUser("serverx509v1");

            securityProperties.loadSignatureKeyStore(this.getClass().getResource("client-keystore.jks"), "storepassword".toCharArray());
            securityProperties.setSignatureUser("clientx509v1");
            securityProperties.setCallbackHandler(new UTPasswordCallback());

           // securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
            securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_RSASHA1);
            securityProperties.setSignatureKeyIdentifier(
                WSSecurityTokenConstants.KeyIdentifier_EncryptedKey
            );

            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

            // Symmetric Key
            String keyAlgorithm = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES128);//JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES256);
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES128);//JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES256);
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken =
                new GenericOutboundSecurityToken(ekId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);

            final SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                    return encryptedKeySecurityToken;
                }

                @Override
                public String getId() {
                    return ekId;
                }
            };

            final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
            outboundSecurityContext.putList(SecurityEvent.class, new ArrayList<SecurityEvent>());

            // Save Token on the security context
            outboundSecurityContext.registerSecurityTokenProvider(encryptedKeySecurityTokenProvider.getId(), encryptedKeySecurityTokenProvider);
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, encryptedKeySecurityTokenProvider.getId());
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, encryptedKeySecurityTokenProvider.getId());

            //InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            
            InputStream sourceDocument = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
            

            baos = new ByteArrayOutputStream();
            XMLStreamWriter xmlStreamWriter =
                wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document encryptedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            System.out.println(XmlUtil.toString(encryptedDocument));

           
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.TIMESTAMP;
            Document decryptedDocument = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
            System.out.println(XmlUtil.toString(decryptedDocument));
        }
    }*/

    /*
    public  void testEncryptionSignatureSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
            securityProperties.setSignatureKeyIdentifier(
                    WSSecurityTokenConstants.KeyIdentifier_EncryptedKey
            );

            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

            // Symmetric Key
            String keyAlgorithm =
                    JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES128);
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES128);
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken =
                    new GenericOutboundSecurityToken(ekId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);

            final SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                        @Override
                        public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                            return encryptedKeySecurityToken;
                        }

                        @Override
                        public String getId() {
                            return ekId;
                        }
                    };

            final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
            outboundSecurityContext.putList(SecurityEvent.class, new ArrayList<SecurityEvent>());

            // Save Token on the security context
            outboundSecurityContext.registerSecurityTokenProvider(encryptedKeySecurityTokenProvider.getId(), encryptedKeySecurityTokenProvider);
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, encryptedKeySecurityTokenProvider.getId());
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, encryptedKeySecurityTokenProvider.getId());

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = new ByteArrayOutputStream();
            XMLStreamWriter xmlStreamWriter =
                    wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            //Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

          
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }*/

    
   /* public  void testEncryptedDataTokenSecurityHeaderWithoutReferenceInbound(String content) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));//this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSignature sign = new WSSecSignature(secHeader);
            sign.setUserInfo("clientx509v1", "storepassword");
            sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
            String client_Sign_path = new File(this.getClass().getResource("Client_Sign.properties").getFile()).getPath();
            Crypto crypto = CryptoFactory.getInstance(client_Sign_path);

            sign.build( crypto);

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            builder.setUserInfo("clientx509v1", "storepassword");
            builder.setSymmetricEncAlgorithm(WSConstants.AES_256);
            builder.prepare(crypto);

            WSEncryptionPart bst = new WSEncryptionPart("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Element");
            WSEncryptionPart def = new WSEncryptionPart("definitions", "http://schemas.xmlsoap.org/wsdl/", "Element");
            List<WSEncryptionPart> encryptionParts = new ArrayList<>();
            encryptionParts.add(bst);
            encryptionParts.add(def);
            Element ref = builder.encryptForRef(null, encryptionParts);
            ref.removeChild(ref.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "DataReference").item(0));
            builder.addExternalRefElement(ref);
            builder.prependToHeader();
            
            

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getResource("server-keystore.jks"), "storepassword".toCharArray());
            securityProperties.setCallbackHandler(new UTPasswordCallback());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

          
        }
    }*/
}
