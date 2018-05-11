package demo.wssec.common;

import java.util.Map;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.w3c.dom.Document;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;


public class DecryptAndVerify extends WsSecCalloutBase implements Execution {
	
	public DecryptAndVerify(Map properties) {
        super(properties);
    }
	
	@Override
    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext execCtxt) {

        try {
            Message msg = msgCtxt.getMessage();
            String msgContent = msg.getContent();
            SignatureDecryptionTest signatureDecryptionTest = new SignatureDecryptionTest();
            Document decryptedDoc = signatureDecryptionTest.testDecrypt(msgContent);
            String verifiedMessage = XmlUtil.toString(decryptedDoc);
           msgCtxt.setVariable("message.content", verifiedMessage);
        }
        catch (Exception e) {
           // System.out.println(ExceptionUtils.getStackTrace(e));
            
        	String error = e.getCause().toString();
            msgCtxt.setVariable("wssec_exception", error);
            int ch = error.lastIndexOf(':');
            if (ch >= 0) {
                msgCtxt.setVariable("wssec_exception", error.substring(ch+2).trim());
            }
            else {
                msgCtxt.setVariable("wssec_exception", error);
            }
            msgCtxt.setVariable("wssec_stacktrace", ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }

        return ExecutionResult.SUCCESS;
    }

}
