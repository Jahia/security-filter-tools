package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.jahia.modules.securityfilter.jwt.TokenVerificationResult.VerificationStatus.REJECTED;
import static org.jahia.modules.securityfilter.jwt.TokenVerificationResult.VerificationStatus.VERIFIED;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The decision {@link JWTFilter#verifyToken} takes on a token's optional {@code ips} and
 * {@code referer} claims.
 */
public class JWTFilterVerificationTest {

    private static final String CONNECTION_ADDRESS = "198.51.100.9";
    private static final String CLAIMED_ADDRESS = "203.0.113.7";
    private static final String CLAIMED_ORIGIN = "https://intranet.example.com";

    private final Map<String, String> headers = new HashMap<>();

    private JWTFilter filter;
    private HttpServletRequest request;

    @Before
    public void setUp() {
        filter = new JWTFilter();
        request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(CONNECTION_ADDRESS);
        // A servlet container resolves a header name without regard to case, and a mock matches the
        // argument it was given. Stubbing one spelling would let a read of another spelling pass.
        when(request.getHeader(anyString())).thenAnswer(
                invocation -> headers.get(invocation.<String>getArgument(0).toLowerCase(Locale.ROOT)));
    }

    private void header(String name, String value) {
        headers.put(name.toLowerCase(Locale.ROOT), value);
    }

    // ---------- the ips claim ----------

    @Test
    public void addressClaimMatchingTheConnectionAddressVerifies() {
        assertStatus(VERIFIED, verify(token(null, Collections.singletonList(CONNECTION_ADDRESS))));
    }

    @Test
    public void addressClaimNotMatchingTheConnectionAddressRejects() {
        assertStatus(REJECTED, verify(token(null, Collections.singletonList(CLAIMED_ADDRESS))));
    }

    @Test
    public void aForwardedHeaderDoesNotSatisfyTheAddressClaim() {
        header("X-Forwarded-For", CLAIMED_ADDRESS);
        assertStatus(REJECTED, verify(token(null, Collections.singletonList(CLAIMED_ADDRESS))));
    }

    @Test
    public void aForwardedChainDoesNotSatisfyTheAddressClaim() {
        header("X-Forwarded-For", CLAIMED_ADDRESS + ", 192.0.2.1");
        assertStatus(REJECTED, verify(token(null, Collections.singletonList(CLAIMED_ADDRESS))));
    }

    @Test
    public void absentAddressClaimVerifies() {
        assertStatus(VERIFIED, verify(token(null, null)));
    }

    @Test
    public void emptyAddressClaimVerifies() {
        assertStatus(VERIFIED, verify(token(null, Collections.<String>emptyList())));
    }

    @Test
    public void addressClaimListingSeveralAddressesVerifiesOnAMatch() {
        assertStatus(VERIFIED, verify(token(null, Arrays.asList(CLAIMED_ADDRESS, CONNECTION_ADDRESS))));
    }

    // ---------- the referer claim ----------

    @Test
    public void refererOnTheClaimedOriginVerifies() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/", CLAIMED_ORIGIN));
    }

    @Test
    public void refererDeeperInTheClaimedPathVerifies() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/app/page?q=1", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererEqualToTheClaimedPathVerifies() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/app", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererOnAHostExtendingTheClaimedHostRejects() {
        assertStatus(REJECTED, verifyReferer("https://intranet.example.com.other.test/app", CLAIMED_ORIGIN));
    }

    @Test
    public void refererOnAPathSharingTheClaimedPrefixRejects() {
        assertStatus(REJECTED, verifyReferer(CLAIMED_ORIGIN + "/application", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererClimbingOutOfTheClaimedPathRejects() {
        assertStatus(REJECTED, verifyReferer(CLAIMED_ORIGIN + "/app/../admin", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererOnAnotherSchemeRejects() {
        assertStatus(REJECTED, verifyReferer("http://intranet.example.com/app", CLAIMED_ORIGIN));
    }

    @Test
    public void refererOnAnotherPortRejects() {
        assertStatus(REJECTED, verifyReferer("https://intranet.example.com:8443/app", CLAIMED_ORIGIN));
    }

    @Test
    public void refererOnAnotherHostRejects() {
        assertStatus(REJECTED, verifyReferer("https://other.example.com/app", CLAIMED_ORIGIN));
    }

    @Test
    public void claimedDefaultPortMatchesARefererWithoutOne() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/app", "https://intranet.example.com:443"));
    }

    @Test
    public void refererClimbingOutOfTheClaimedPathWithAnEncodedSegmentRejects() {
        assertStatus(REJECTED, verifyReferer(CLAIMED_ORIGIN + "/app/%2e%2e/admin", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererClimbingOutOfTheClaimedPathWithAnEncodedSeparatorRejects() {
        assertStatus(REJECTED, verifyReferer(CLAIMED_ORIGIN + "/app%2f..%2fadmin", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void aTrailingSlashOnTheRefererPathIsIgnored() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/app/", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void aTrailingSlashOnTheClaimedPathIsIgnored() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/app", CLAIMED_ORIGIN + "/app/"));
    }

    @Test
    public void claimedHttpDefaultPortMatchesARefererCarryingItExplicitly() {
        assertStatus(VERIFIED, verifyReferer("http://intranet.example.com:80/app", "http://intranet.example.com"));
    }

    @Test
    public void refererCarryingAPipeInItsQueryVerifies() {
        assertStatus(VERIFIED, verifyReferer(CLAIMED_ORIGIN + "/app?ids=1|2", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererOnAHostCarryingAnUnderscoreVerifies() {
        assertStatus(VERIFIED, verifyReferer("https://intra_net.example.com/app", "https://intra_net.example.com"));
    }

    @Test
    public void refererOnANonHttpSchemeRejects() {
        assertStatus(REJECTED, verifyReferer("ftp://intranet.example.com/app", CLAIMED_ORIGIN));
    }

    @Test
    public void absentRefererWithARefererClaimRejects() {
        assertStatus(REJECTED, verifyReferer(null, CLAIMED_ORIGIN));
    }

    @Test
    public void refererClaimListingSeveralOriginsVerifiesOnAMatch() {
        DecodedJWT token = token(Arrays.asList("https://other.example.com", CLAIMED_ORIGIN), null);
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertStatus(VERIFIED, verify(token));
    }

    // ---------- both claims ----------

    @Test
    public void bothClaimsSatisfiedVerifies() {
        DecodedJWT token = token(Collections.singletonList(CLAIMED_ORIGIN), Collections.singletonList(CONNECTION_ADDRESS));
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertStatus(VERIFIED, verify(token));
    }

    @Test
    public void refererSatisfiedWhileTheAddressClaimIsNotRejects() {
        DecodedJWT token = token(Collections.singletonList(CLAIMED_ORIGIN), Collections.singletonList(CLAIMED_ADDRESS));
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertStatus(REJECTED, verify(token));
    }

    // ---------- helpers ----------

    private TokenVerificationResult verifyReferer(String refererHeader, String claimedReferer) {
        header("Referer", refererHeader);
        return verify(token(Collections.singletonList(claimedReferer), null));
    }

    private TokenVerificationResult verify(DecodedJWT decodedToken) {
        TokenVerificationResult tvr = new TokenVerificationResult();
        filter.verifyToken(request, tvr, decodedToken);
        return tvr;
    }

    private static void assertStatus(TokenVerificationResult.VerificationStatus expected, TokenVerificationResult tvr) {
        assertEquals(tvr.getMessage(), expected, tvr.getVerificationStatusCode());
    }

    private static DecodedJWT token(List<String> claimReferers, List<String> ips) {
        Claim refererClaim = claim(claimReferers);
        Claim ipsClaim = claim(ips);
        DecodedJWT decodedToken = mock(DecodedJWT.class);
        when(decodedToken.getClaim("referer")).thenReturn(refererClaim);
        when(decodedToken.getClaim("ips")).thenReturn(ipsClaim);
        return decodedToken;
    }

    private static Claim claim(List<String> values) {
        Claim claim = mock(Claim.class);
        when(claim.asList(String.class)).thenReturn(values);
        return claim;
    }
}
