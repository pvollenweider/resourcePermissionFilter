package org.jahia.support.module.filters;
import java.io.IOException;
import java.net.URLDecoder;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jahia.api.Constants;
import org.jahia.registries.ServicesRegistry;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link CheckResourcePermissionFilter} is used to redirect to a login page for restricted content.
 */
public class CheckResourcePermissionFilter implements javax.servlet.Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(CheckResourcePermissionFilter.class);


    /** {@inheritDoc} */
    @Override
    public void destroy() {
        // do nothing
    }

    /** {@inheritDoc} */
    // CHECKSTYLE:OFF Accept cyclomatic complexity
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        // CHECKSTYLE:ON

        final HttpServletRequest hsRequest = (HttpServletRequest) request;
        HttpServletResponse hsResponse = (HttpServletResponse) response;

        // check for status request
        String uri = hsRequest.getRequestURI();

        LOGGER.debug("Handling resource {}", uri);

        String encodedNodePath = "";
        if (uri.indexOf("/sites/") > -1) {
            encodedNodePath = uri.substring(uri.indexOf("/sites/"));
        }
        else if (uri.indexOf("/files/default/") > -1) {
            encodedNodePath = uri.substring(uri.indexOf("/default/") + 8);
        }
        else if (uri.indexOf("/files/live/") > -1) {
            encodedNodePath = uri.substring(uri.indexOf("/live/") + 5);
        }
        else if (uri.indexOf("/files/preview/") > -1) {
            encodedNodePath = uri.substring(uri.indexOf("/preview/") + 8);
        }
        else if (uri.indexOf("/files/") > -1) {
            encodedNodePath = uri.substring(uri.indexOf("/files/") + 6);
        }

        String nodePath = URLDecoder.decode(encodedNodePath, "UTF-8");

        // REFACTOR: Do not distinguish between 403 and 404; Simply check if file is not restricted
        // and redirect in all other cases to login page

        //check if files servlet is used
        if (nodePath != null && nodePath.length() > 0) {
            if (!JahiaUserManagerService.isGuest(JCRSessionFactory.getInstance().getCurrentUser())) {

                //authenticated user
                //You could add checks if it is needed and you could send an error if it is needed

            }
            else {
                //guest user
                //do a check if resource exists if yes send 403 error if not continue and a 404 error will be send
                try {
                    boolean fileExists = false;
                    //important guest user needs to a "live" session
                    //JCRSessionFactory.getInstance().setCurrentUser(
                    //        ServicesRegistry.getInstance().getJahiaUserManagerService().lookupUser("guest").getJahiaUser());
                    JCRSessionWrapper jcrSession = JCRSessionFactory.getInstance().getCurrentUserSession(Constants.LIVE_WORKSPACE);

                    try {
                        if (jcrSession.getItem(nodePath) == null) {
                            fileExists = checkPathInRestrictedArea(nodePath);
                        }
                        else {
                            //file is visible for the current user (guest)
                            //continue with filters
                            chain.doFilter(request, response);
                            return;
                        }
                    }
                    catch (PathNotFoundException ex) {

                        //Path not found, to check if it exists in restricted area
                        fileExists = checkPathInRestrictedArea(nodePath);
                    }

                    if (fileExists) {
                        LOGGER.debug("Node " + nodePath + " is not readable for current user. Send error 403");
                        //set a path for a redirect url
                        hsRequest.getSession().setAttribute("resourceUri", uri);
                        hsResponse.sendError(403);
                        //don't forget the return, otherwise the filters will continue and it will lead into an error
                        return;
                    }

                }
                catch (RepositoryException ex) {
                    LOGGER.error("Repository Exception", ex);
                }
            }
        }

        //continue with filters
        chain.doFilter(request, response);
    }


    private boolean checkPathInRestrictedArea(String path) throws RepositoryException {
        JahiaUser currentUser = JCRSessionFactory.getInstance().getCurrentUser();
        try {
            JCRSessionFactory.getInstance().setCurrentUser(
                    ServicesRegistry.getInstance().getJahiaUserManagerService().lookupUser("root").getJahiaUser());
            JCRSessionWrapper session = JCRSessionFactory.getInstance().getCurrentUserSession(Constants.LIVE_WORKSPACE);
            JCRNodeWrapper node = session.getNode(path);
            if (node != null) {
                JCRSessionFactory.getInstance().setCurrentUser(currentUser);
                return true;
            }
        }
        catch (PathNotFoundException ex) {

            JCRSessionFactory.getInstance().setCurrentUser(currentUser);
            return false;
        }
        // CHECKSTYLE:OFF catch all exceptions in order to log them
        catch (Exception uex) {
            // CHECKSTYLE:ON
            LOGGER.error("Unexpected exception: ", uex);
        }
        finally {
            JCRSessionFactory.getInstance().setCurrentUser(currentUser);
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override
    public void init(FilterConfig cfg) throws ServletException {
        // do nothing
    }

}
