package org.picketlink.identity.federation.web.handlers.saml2;

import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by crawley on 05/02/16.
 */
public class RoleSeparatorHandler extends BaseSAML2Handler {

	public static final String ROLE_SEPARATOR = "ROLE_SEPARATOR";
	private String separator = ",";

	@Override
	public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		separateRoles(response);
	}

	private void separateRoles(SAML2HandlerResponse response) {
		List<String> rolesList = response.getRoles();
		if (handlerConfig.getParameter(ROLE_SEPARATOR) != null) {
			Object fottiObject = handlerConfig.getParameter(ROLE_SEPARATOR);
			if (fottiObject instanceof String) {
				separator = (String)fottiObject;
			}
		}
		List<String> newRoles = new ArrayList<String>();
		for (String role : rolesList) {
			if (role.contains(separator)) {
				String [] roles = role.split(separator);
				for (String newRole : roles) {
					newRoles.add(newRole);
				}
			} else {
				newRoles.add(role);
			}
		}
		response.setRoles(newRoles);
	}

	@Override
	public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
		separateRoles(response);
		super.handleStatusResponseType(request, response);
	}


}
