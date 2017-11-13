package org.picketlink.identity.federation.web.handlers.saml2;

import java.security.Principal;

import javax.servlet.http.HttpSession;

import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.SerializablePrincipal;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.federation.web.core.HTTPContext;

/**
 * Created by pellegatta on 13/06/16.
 */
public class StatusHandler extends BaseSAML2Handler {

	@Override
	public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		checkResponseStatus(request,response);
	}
	
	@Override
	public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response)
			throws ProcessingException {
	}
	
	private void checkResponseStatus(SAML2HandlerRequest request, SAML2HandlerResponse response) {
		HTTPContext httpContext = (HTTPContext) request.getContext();
        ResponseType responseType = (ResponseType) request.getSAML2Object();
        StatusType statusType = responseType.getStatus();
        if (statusType!=null && statusType.getStatusCode()!=null && statusType.getStatusCode().getStatusCode()!=null){
        	if (!statusType.getStatusCode().getValue().toString().equals(JBossSAMLURIConstants.STATUS_SUCCESS.get())){
        		HttpSession session = httpContext.getRequest().getSession(false);
        		StringBuffer statusDetail = new StringBuffer();
        		session.setAttribute("picketlink.error", "true");
        		session.setAttribute("picketlink.statusCode", statusType.getStatusCode().getStatusCode().getValue().toString());
        		session.setAttribute("picketlink.statusMessage", statusType.getStatusMessage());
        		if (statusType.getStatusDetail()!=null && statusType.getStatusDetail().getAny()!=null){
        			for (Object errorDetail : statusType.getStatusDetail().getAny()) {
    					statusDetail.append(errorDetail.toString()+".");
    				}
        		}
        		session.setAttribute("picketlink.statusDetail", statusDetail.toString());
        		httpContext.getResponse().setStatus(403);
   			 	response.setError(403, "");
   			 	Principal principal = new SerializablePrincipal(session.getId());
   			 	session.setAttribute(GeneralConstants.PRINCIPAL_ID, principal);
        	}
        }
	}
	
}
