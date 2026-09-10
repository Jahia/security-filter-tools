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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The scope decision {@link JWTConfig#tokenMatches} takes on the token the filter published.
 * <p>
 * Each case drives the real {@link JWTFilter} and asks the question from inside the filter chain,
 * which is where a downstream caller asks it. So the ThreadLocal the two classes share is
 * populated the way a request populates it, and no test reaches into it. Every claim is built into
 * a local before it is stubbed, because Mockito refuses a mock created inside a {@code thenReturn}
 * argument.
 */
public class JWTConfigTokenMatchesTest {

    private final JWTConfig config = new JWTConfig();

    private JWTFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private DecodedJWT decodedToken;

    @Before
    public void setUp() throws Exception {
        filter = new JWTFilter();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        JWTService jwtService = mock(JWTService.class);
        decodedToken = mock(DecodedJWT.class);

        filter.setPermissionService(mock(PermissionService.class));
        filter.setJwtConfig(jwtService);

        when(request.getHeader("Authorization")).thenReturn("Bearer a.b.c");
        when(request.getRemoteAddr()).thenReturn("198.51.100.9");
        when(jwtService.verifyToken(anyString())).thenReturn(decodedToken);

        Claim noReferer = absentClaim();
        Claim noIps = absentClaim();
        when(decodedToken.getClaim("referer")).thenReturn(noReferer);
        when(decodedToken.getClaim("ips")).thenReturn(noIps);
    }

    @Test
    public void noRequiredScopeMatchesWhateverTheTokenCarries() throws Exception {
        assertEquals(Boolean.TRUE, askWith(scalarClaim(), Collections.<String>emptySet()));
    }

    @Test
    public void aScopesListCarryingTheRequiredScopeMatches() throws Exception {
        assertEquals(Boolean.TRUE,
                askWith(listClaim(Arrays.asList("graphql", "contentManager")), required("graphql")));
    }

    @Test
    public void aScopesListWithoutTheRequiredScopeDoesNotMatch() throws Exception {
        assertEquals(Boolean.FALSE,
                askWith(listClaim(Collections.singletonList("contentManager")), required("graphql")));
    }

    @Test
    public void aScalarScopesClaimMatchesNothingAndRaisesNothing() throws Exception {
        // Reading this claim as a list answers null, so the comparison must not run on it.
        assertEquals(Boolean.FALSE, askWith(scalarClaim(), required("graphql")));
    }

    @Test
    public void anAbsentScopesClaimMatchesNothingAndRaisesNothing() throws Exception {
        assertEquals(Boolean.FALSE, askWith(absentClaim(), required("graphql")));
    }

    @Test
    public void anEmptyScopesListMatchesNothing() throws Exception {
        assertEquals(Boolean.FALSE, askWith(listClaim(Collections.<String>emptyList()), required("graphql")));
    }

    @Test
    public void aScopesListHoldingANullEntryMatchesNothing() throws Exception {
        assertEquals(Boolean.FALSE,
                askWith(listClaim(Arrays.asList("graphql", null)), required("graphql")));
    }

    /** Runs the filter with this scopes claim, and asks tokenMatches from inside the chain. */
    private Boolean askWith(Claim scopesClaim, final Set<String> requiredScopes) throws Exception {
        when(decodedToken.getClaim("scopes")).thenReturn(scopesClaim);
        final Boolean[] answer = new Boolean[1];
        doAnswer(invocation -> {
            answer[0] = config.tokenMatches(requiredScopes);
            return null;
        }).when(chain).doFilter(any(), any());
        filter.doFilter(request, response, chain);
        return answer[0];
    }

    private static Set<String> required(String scope) {
        return new HashSet<>(Collections.singletonList(scope));
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
