package org.picketlink.identity.federation.web.handlers.saml2;

import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.SerializablePrincipal;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

/**
 * Created by crawley on 05/02/16.
 */
public class UserIdHandler extends BaseSAML2Handler {

	public static final String USERID_ASSERTION_ATTRIBUTE = "USERID_ASSERTION_ATTRIBUTE";

	@Override
	public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		setUserPrincipal(request, response);
	}

	private void setUserPrincipal(SAML2HandlerRequest request, SAML2HandlerResponse response) {
		HttpSession session = getHttpSession(request);
		Principal userPrincipal = (Principal)session.getAttribute(GeneralConstants.PRINCIPAL_ID);
		String userId = userPrincipal.getName();

		if (handlerConfig.getParameter(USERID_ASSERTION_ATTRIBUTE) != null) {
			Object userIdKey = handlerConfig.getParameter(USERID_ASSERTION_ATTRIBUTE);
			if (userIdKey instanceof String) {
				Map<String, List<Object>> sessionMap = (Map<String, List<Object>>) session .getAttribute(GeneralConstants.SESSION_ATTRIBUTE_MAP);
				if ((sessionMap != null) && sessionMap.containsKey(userIdKey)) {
					List<Object> values = sessionMap.get(userIdKey);
					if (values.size() > 0) {
						userId = (String)values.get(0);
					}
				}
			}
		}
		Principal principal = new SerializablePrincipal(userId);
		session.setAttribute(GeneralConstants.PRINCIPAL_ID, principal);
	}

	@Override
	public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		setUserPrincipal(request, response);
		super.handleStatusResponseType(request, response);
	}
}
