package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.jahia.bundles.securityfilter.JWTService;
import org.jahia.services.securityfilter.PermissionService;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.jahia.modules.securityfilter.jwt.TokenVerificationResult.VerificationStatus.REJECTED;
import static org.jahia.modules.securityfilter.jwt.TokenVerificationResult.VerificationStatus.VERIFIED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What {@link JWTFilter#doFilter} does with the token's {@code scopes} claim, and whether the
 * request receives the scopes that claim grants.
 * <p>
 * Every claim is built into a local before it is stubbed, because Mockito refuses a mock created
 * inside a {@code thenReturn} argument.
 */
public class JWTFilterDoFilterTest {

    private static final String CONNECTION_ADDRESS = "198.51.100.9";
    private static final String OTHER_ADDRESS = "203.0.113.7";

    private JWTFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private PermissionService permissionService;
    private DecodedJWT decodedToken;

    @Before
    public void setUp() throws Exception {
        filter = new JWTFilter();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        permissionService = mock(PermissionService.class);
        JWTService jwtService = mock(JWTService.class);
        decodedToken = mock(DecodedJWT.class);

        filter.setPermissionService(permissionService);
        filter.setJwtConfig(jwtService);

        when(request.getHeader("Authorization")).thenReturn("Bearer a.b.c");
        when(request.getRemoteAddr()).thenReturn(CONNECTION_ADDRESS);
        when(jwtService.verifyToken(anyString())).thenReturn(decodedToken);

        // No referer and no ips restriction, so the scopes claim is the only variable.
        Claim noReferer = absentClaim();
        Claim noIps = absentClaim();
        when(decodedToken.getClaim("referer")).thenReturn(noReferer);
        when(decodedToken.getClaim("ips")).thenReturn(noIps);
    }

    @Test
    public void aScopesListGrantsItsScopesToTheRequest() throws Exception {
        stubScopes(listClaim(Collections.singletonList("graphql")));
        TokenVerificationResult tvr = runFilter();
        assertEquals("status", VERIFIED, tvr.getVerificationStatusCode());
        verify(permissionService).addScopes(Collections.singletonList("graphql"), request);
    }

    @Test
    public void aScalarScopesClaimGrantsNothingAndRejects() throws Exception {
        stubScopes(scalarClaim());
        TokenVerificationResult tvr = runFilter();
        assertEquals("status", REJECTED, tvr.getVerificationStatusCode());
        assertEquals("message", "Unreadable scopes in token", tvr.getMessage());
        assertNull("a rejected result carries no token", tvr.getToken());
        verify(permissionService, never()).addScopes(anyList(), any());
    }

    @Test
    public void aScopesListHoldingANullEntryGrantsNothingAndRejects() throws Exception {
        stubScopes(listClaim(Arrays.asList("graphql", null)));
        TokenVerificationResult tvr = runFilter();
        assertEquals("status", REJECTED, tvr.getVerificationStatusCode());
        verify(permissionService, never()).addScopes(anyList(), any());
    }

    @Test
    public void anAbsentScopesClaimGrantsNothingAndVerifies() throws Exception {
        stubScopes(absentClaim());
        TokenVerificationResult tvr = runFilter();
        assertEquals("status", VERIFIED, tvr.getVerificationStatusCode());
        verify(permissionService, never()).addScopes(anyList(), any());
    }

    @Test
    public void anEmptyScopesListGrantsNothingAndVerifies() throws Exception {
        stubScopes(listClaim(Collections.<String>emptyList()));
        TokenVerificationResult tvr = runFilter();
        assertEquals("status", VERIFIED, tvr.getVerificationStatusCode());
        verify(permissionService, never()).addScopes(anyList(), any());
    }

    @Test
    public void aRefusedAddressRestrictionGrantsNothingWhateverTheScopesClaimHolds() throws Exception {
        Claim restricted = listClaim(Collections.singletonList(OTHER_ADDRESS));
        when(decodedToken.getClaim("ips")).thenReturn(restricted);
        stubScopes(listClaim(Collections.singletonList("graphql")));
        TokenVerificationResult tvr = runFilter();
        assertEquals("status", REJECTED, tvr.getVerificationStatusCode());
        verify(permissionService, never()).addScopes(anyList(), any());
    }

    @Test
    public void theChainRunsWhateverTheDecision() throws Exception {
        stubScopes(scalarClaim());
        runFilter();
        verify(chain).doFilter(request, response);
    }

    private void stubScopes(Claim scopes) {
        when(decodedToken.getClaim("scopes")).thenReturn(scopes);
    }

    /**
     * Runs the filter and answers the result it published. The filter clears its ThreadLocal after
     * the chain, so the chain is the one place the result can be read.
     */
    private TokenVerificationResult runFilter() throws Exception {
        final TokenVerificationResult[] seen = new TokenVerificationResult[1];
        doAnswer(invocation -> {
            seen[0] = JWTFilter.getJWTTokenVerificationStatus();
            return null;
        }).when(chain).doFilter(any(), any());
        filter.doFilter(request, response, chain);
        return seen[0];
    }

    private static Claim listClaim(List<String> values) {
        Claim claim = mock(Claim.class);
        when(claim.asList(String.class)).thenReturn(values);
        when(claim.isNull()).thenReturn(false);
        return claim;
    }

    private static Claim absentClaim() {
        Claim claim = mock(Claim.class);
        when(claim.asList(String.class)).thenReturn(null);
        when(claim.isNull()).thenReturn(true);
        return claim;
    }

    private static Claim scalarClaim() {
        Claim claim = mock(Claim.class);
        when(claim.asList(String.class)).thenReturn(null);
        when(claim.isNull()).thenReturn(false);
        return claim;
    }
}
