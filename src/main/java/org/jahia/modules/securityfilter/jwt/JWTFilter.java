/*
 * ==========================================================================================
 * =                   JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION                       =
 * ==========================================================================================
 *
 *                                 http://www.jahia.com
 *
 *     Copyright (C) 2002-2025 Jahia Solutions Group SA. All rights reserved.
 *
 *     THIS FILE IS AVAILABLE UNDER TWO DIFFERENT LICENSES:
 *     1/Apache2 OR 2/JSEL
 *
 *     1/ Apache2
 *     ==================================================================================
 *
 *     Copyright (C) 2002-2025 Jahia Solutions Group SA. All rights reserved.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 *
 *     2/ JSEL - Commercial and Supported Versions of the program
 *     ===================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE JSEL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     Alternatively, commercial and supported versions of the program - also known as
 *     Enterprise Distributions - must be used in accordance with the terms and conditions
 *     contained in a separate written agreement between you and Jahia Solutions Group SA.
 *
 *     If you are unsure which license is appropriate for your use,
 *     please contact the sales department at sales@jahia.com.
 */
package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang.StringUtils;
import org.jahia.bin.Jahia;
import org.jahia.bin.filters.AbstractServletFilter;
import org.jahia.bundles.securityfilter.JWTService;
import org.jahia.services.securityfilter.PermissionService;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

@Component(
        service = AbstractServletFilter.class,
        immediate = true,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Security filter: servlet filter used for JWT token verification",
                Constants.SERVICE_VENDOR + "=" + Jahia.VENDOR_NAME
        }
)
public class JWTFilter extends AbstractServletFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTFilter.class);

    private static final String BEARER = "Bearer";
    private static final ThreadLocal<TokenVerificationResult> THREAD_LOCAL = new ThreadLocal<TokenVerificationResult>();
    private JWTService jwtService;

    public static TokenVerificationResult getJWTTokenVerificationStatus() {
        return THREAD_LOCAL.get();
    }

    private PermissionService permissionService;

    @Activate
    public void activate() {
        this.setUrlPatterns(new String[]{"/*"});
    }

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    public void setPermissionService(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    public void setJwtConfig(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        //Do nothing for now
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        String authorization = httpRequest.getHeader("Authorization");

        TokenVerificationResult tvr = new TokenVerificationResult();

        THREAD_LOCAL.set(tvr);

        if (authorization != null && authorization.contains(BEARER)) {
            String token = StringUtils.substringAfter(authorization, BEARER).trim();
            if (!StringUtils.isEmpty(token)) {
                try {
                    DecodedJWT decodedToken = jwtService.verifyToken(token);

                    verifyToken(httpRequest, tvr, decodedToken);

                    if (tvr.getVerificationStatusCode() == TokenVerificationResult.VerificationStatus.VERIFIED) {
                        List<String> scopes = decodedToken.getClaim("scopes").asList(String.class);
                        if (scopes != null) {
                            permissionService.addScopes(scopes, httpRequest);
                        }
                    }
                } catch (Exception e) {
                    tvr.setVerificationStatusCode(TokenVerificationResult.VerificationStatus.REJECTED);
                    tvr.setMessage("Failed to verify token");
                    logger.debug("Failed to verify JWT token: {}", e.getMessage());
                }
            }
        }

        filterChain.doFilter(httpRequest, servletResponse);

        THREAD_LOCAL.set(null);
    }

    void verifyToken(HttpServletRequest httpRequest, TokenVerificationResult tvr, DecodedJWT decodedToken) {
        String referer = httpRequest.getHeader("referer");
        List<String> claimReferers = decodedToken.getClaim("referer").asList(String.class);
        String ip = httpRequest.getRemoteAddr();
        List<String> ips = decodedToken.getClaim("ips").asList(String.class);

        if (claimReferers != null && !claimReferers.isEmpty() && !checkReferer(claimReferers, referer)) {
            //Check referers
            tvr.setVerificationStatusCode(TokenVerificationResult.VerificationStatus.REJECTED);
            tvr.setMessage("Incorrect referer in token");
        } else if (ips != null && !ips.isEmpty() && !ips.contains(ip)) {
            //Check IP
            tvr.setVerificationStatusCode(TokenVerificationResult.VerificationStatus.REJECTED);
            tvr.setMessage("Your IP did not match any of the permitted IPs");
        } else {
            tvr.setToken(decodedToken);
            tvr.setVerificationStatusCode(TokenVerificationResult.VerificationStatus.VERIFIED);
            tvr.setMessage("Token verified");
        }
    }

    private boolean checkReferer(List<String> claimReferers, String referer) {
        RefererParts actual = RefererParts.parse(referer);
        if (actual == null) {
            return false;
        }
        for (String claimReferer : claimReferers) {
            RefererParts claimed = RefererParts.parse(claimReferer);
            if (claimed != null && claimed.covers(actual)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The parts of an absolute http(s) URL that a token's {@code referer} claim is matched on.
     * Parsing goes through {@link URL} and not {@link java.net.URI}, because a URI rejects characters a
     * browser sends unencoded in a query and reports no host for an authority such as
     * {@code intra_net.example.com}.
     */
    private static final class RefererParts {

        private final String scheme;
        private final String host;
        private final int port;
        /** Percent-decoded, with {@code .} and {@code ..} segments resolved. Empty for the root. */
        private final String path;

        private RefererParts(String scheme, String host, int port, String path) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.path = path;
        }

        static RefererParts parse(String value) {
            if (StringUtils.isEmpty(value)) {
                return null;
            }
            URL url;
            try {
                url = new URL(value);
            } catch (MalformedURLException e) {
                logger.debug("Referer value is not an absolute URL: {}", value);
                return null;
            }
            String scheme = url.getProtocol();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                logger.debug("Referer value carries no http(s) scheme: {}", value);
                return null;
            }
            if (StringUtils.isEmpty(url.getHost())) {
                logger.debug("Referer value carries no host: {}", value);
                return null;
            }
            String path = resolvePath(url.getPath());
            if (path == null) {
                logger.debug("Referer path cannot be decoded: {}", value);
                return null;
            }
            int port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
            return new RefererParts(scheme, url.getHost(), port, path);
        }

        /**
         * Resolves a raw path to the form the server addresses: decoded first, so that an encoded
         * {@code ..} segment resolves instead of travelling on as a name.
         */
        private static String resolvePath(String rawPath) {
            String decoded;
            try {
                // '+' stands for itself in a path, and URLDecoder would read it as a space.
                decoded = URLDecoder.decode(rawPath.replace("+", "%2B"), StandardCharsets.UTF_8.name());
            } catch (IllegalArgumentException | UnsupportedEncodingException e) {
                return null;
            }
            Deque<String> segments = new ArrayDeque<>();
            for (String segment : decoded.split("/")) {
                if (segment.isEmpty() || ".".equals(segment)) {
                    continue;
                }
                if ("..".equals(segment)) {
                    segments.pollLast();
                } else {
                    segments.addLast(segment);
                }
            }
            return segments.isEmpty() ? "" : "/" + String.join("/", segments);
        }

        boolean covers(RefererParts actual) {
            return scheme.equalsIgnoreCase(actual.scheme)
                    && host.equalsIgnoreCase(actual.host)
                    && port == actual.port
                    && (actual.path.equals(path) || actual.path.startsWith(path + "/"));
        }
    }

    @Override
    public void destroy() {
        //Do nothing for now
    }
}
