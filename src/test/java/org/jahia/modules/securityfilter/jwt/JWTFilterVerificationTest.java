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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
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
    private static final String VERIFIED_MESSAGE = "Token verified";
    private static final String REFERER_REJECTION = "Incorrect referer in token";
    private static final String ADDRESS_REJECTION = "Your IP did not match any of the permitted IPs";
    private static final String SCALAR_REFERER_REJECTION = "Unreadable referer in token";
    private static final String SCALAR_ADDRESS_REJECTION = "Unreadable IPs in token";

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
        assertVerified(verify(token(null, Collections.singletonList(CONNECTION_ADDRESS))));
    }

    @Test
    public void addressClaimNotMatchingTheConnectionAddressRejects() {
        assertRejected(ADDRESS_REJECTION, verify(token(null, Collections.singletonList(CLAIMED_ADDRESS))));
    }

    @Test
    public void theAddressClaimIsMatchedOnTheConnectionAddressAndNotOnARequestHeader() {
        header("X-Forwarded-For", CLAIMED_ADDRESS);
        assertRejected(ADDRESS_REJECTION, verify(token(null, Collections.singletonList(CLAIMED_ADDRESS))));
    }

    @Test
    public void theAddressClaimIsMatchedOnTheConnectionAddressAndNotOnAHeaderChain() {
        header("X-Forwarded-For", CLAIMED_ADDRESS + ", 192.0.2.1");
        assertRejected(ADDRESS_REJECTION, verify(token(null, Collections.singletonList(CLAIMED_ADDRESS))));
    }

    @Test
    public void absentAddressClaimVerifies() {
        assertVerified(verify(token(null, null)));
    }

    @Test
    public void emptyAddressClaimVerifies() {
        assertVerified(verify(token(null, Collections.<String>emptyList())));
    }

    @Test
    public void addressClaimListingSeveralAddressesVerifiesOnAMatch() {
        assertVerified(verify(token(null, Arrays.asList(CLAIMED_ADDRESS, CONNECTION_ADDRESS))));
    }

    // ---------- the referer claim ----------

    @Test
    public void refererOnTheClaimedOriginVerifies() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/", CLAIMED_ORIGIN));
    }

    @Test
    public void refererDeeperInTheClaimedPathVerifies() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/app/page?q=1", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererEqualToTheClaimedPathVerifies() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/app", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererOnAHostExtendingTheClaimedHostRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer("https://intranet.example.com.other.test/app", CLAIMED_ORIGIN));
    }

    @Test
    public void refererOnAPathSharingTheClaimedPrefixRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/application", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererClimbingOutOfTheClaimedPathRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/app/../admin", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererOnAnotherSchemeRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer("http://intranet.example.com/app", CLAIMED_ORIGIN));
    }

    @Test
    public void refererOnAnotherPortRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer("https://intranet.example.com:8443/app", CLAIMED_ORIGIN));
    }

    @Test
    public void refererOnAnotherHostRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer("https://other.example.com/app", CLAIMED_ORIGIN));
    }

    @Test
    public void claimedDefaultPortMatchesARefererWithoutOne() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/app", "https://intranet.example.com:443"));
    }

    @Test
    public void refererClimbingOutOfTheClaimedPathWithAnEncodedSegmentRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/app/%2e%2e/admin", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererClimbingOutOfTheClaimedPathWithAnEncodedSeparatorRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/app%2f..%2fadmin", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void aTrailingSlashOnTheRefererPathIsIgnored() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/app/", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void aTrailingSlashOnTheClaimedPathIsIgnored() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/app", CLAIMED_ORIGIN + "/app/"));
    }

    @Test
    public void claimedHttpDefaultPortMatchesARefererCarryingItExplicitly() {
        assertVerified(verifyReferer("http://intranet.example.com:80/app", "http://intranet.example.com"));
    }

    @Test
    public void refererCarryingAPipeInItsQueryVerifies() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/app?ids=1|2", CLAIMED_ORIGIN + "/app"));
    }

    @Test
    public void refererOnAHostCarryingAnUnderscoreVerifies() {
        assertVerified(verifyReferer("https://intra_net.example.com/app", "https://intra_net.example.com"));
    }

    @Test
    public void refererOnANonHttpSchemeRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer("ftp://intranet.example.com/app", CLAIMED_ORIGIN));
    }

    @Test
    public void aPlusInThePathStandsForItself() {
        assertVerified(verifyReferer(CLAIMED_ORIGIN + "/a+b/page", CLAIMED_ORIGIN + "/a+b"));
    }

    @Test
    public void anEncodedSpaceInThePathIsNotAPlus() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/a%20b/page", CLAIMED_ORIGIN + "/a+b"));
    }

    @Test
    public void absentRefererWithARefererClaimRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer(null, CLAIMED_ORIGIN));
    }

    @Test
    public void emptyRefererWithARefererClaimRejects() {
        assertRejected(REFERER_REJECTION, verifyReferer("", CLAIMED_ORIGIN));
    }

    @Test
    public void emptyRefererClaimVerifies() {
        assertVerified(verify(token(Collections.<String>emptyList(), null)));
    }

    @Test
    public void absentRefererClaimVerifiesWhateverTheRefererHeaderCarries() {
        header("Referer", "https://other.example.com/app");
        assertVerified(verify(token(null, null)));
    }

    @Test
    public void refererClaimListingSeveralOriginsVerifiesOnAMatch() {
        DecodedJWT token = token(Arrays.asList("https://other.example.com", CLAIMED_ORIGIN), null);
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertVerified(verify(token));
    }

    // ---------- a referer claim its issuer wrote wrong ----------

    @Test
    public void aRefererClaimThatIsNotAnAbsoluteUrlSatisfiesNothing() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/app", "intranet.example.com"));
    }

    @Test
    public void aRefererClaimThatIsAPathAloneSatisfiesNothing() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/app", "/app"));
    }

    @Test
    public void aRefererClaimOnANonHttpSchemeSatisfiesNothing() {
        assertRejected(REFERER_REJECTION, verifyReferer(CLAIMED_ORIGIN + "/app", "ftp://intranet.example.com"));
    }

    @Test
    public void aRefererClaimAndARefererAgreeingOnANonHttpSchemeSatisfyNothing() {
        // The scheme comparison alone would pass this pair, so only the http(s) guard refuses it.
        assertRejected(REFERER_REJECTION,
                verifyReferer("ftp://intranet.example.com/app/page", "ftp://intranet.example.com/app"));
    }

    @Test
    public void aRefererClaimCarryingAQuerySatisfiesNothing() {
        assertRejected(REFERER_REJECTION,
                verifyReferer(CLAIMED_ORIGIN + "/app?tenant=a", CLAIMED_ORIGIN + "/app?tenant=a"));
    }

    @Test
    public void anUnusableRefererClaimDoesNotStopAUsableOneFromMatching() {
        DecodedJWT token = token(Arrays.asList("intranet.example.com", CLAIMED_ORIGIN), null);
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertVerified(verify(token));
    }

    // ---------- a claim the issuer wrote as a scalar ----------

    @Test
    public void aScalarAddressClaimRejects() {
        assertRejected(SCALAR_ADDRESS_REJECTION, verify(tokenWithClaims(claim(null), scalarClaim())));
    }

    @Test
    public void aScalarRefererClaimRejects() {
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertRejected(SCALAR_REFERER_REJECTION, verify(tokenWithClaims(scalarClaim(), claim(null))));
    }

    @Test
    public void aScalarAddressClaimRejectsEvenFromTheConnectionAddress() {
        // The connection address cannot satisfy a claim that is never read, so the arm that would
        // pass on the array form must still refuse here.
        assertRejected(SCALAR_ADDRESS_REJECTION, verify(tokenWithClaims(claim(null), scalarClaim())));
    }

    @Test
    public void aScalarRefererClaimIsReportedBeforeAScalarAddressClaim() {
        assertRejected(SCALAR_REFERER_REJECTION, verify(tokenWithClaims(scalarClaim(), scalarClaim())));
    }

    @Test
    public void aScalarAddressClaimRejectsWhileTheRefererClaimIsSatisfied() {
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertRejected(SCALAR_ADDRESS_REJECTION,
                verify(tokenWithClaims(claim(Collections.singletonList(CLAIMED_ORIGIN)), scalarClaim())));
    }

    // ---------- both claims ----------

    @Test
    public void bothClaimsSatisfiedVerifies() {
        DecodedJWT token = token(Collections.singletonList(CLAIMED_ORIGIN), Collections.singletonList(CONNECTION_ADDRESS));
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertVerified(verify(token));
    }

    @Test
    public void refererSatisfiedWhileTheAddressClaimIsNotRejects() {
        DecodedJWT token = token(Collections.singletonList(CLAIMED_ORIGIN), Collections.singletonList(CLAIMED_ADDRESS));
        header("Referer", CLAIMED_ORIGIN + "/app");
        assertRejected(ADDRESS_REJECTION, verify(token));
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

    private static void assertVerified(TokenVerificationResult tvr) {
        assertEquals("status", VERIFIED, tvr.getVerificationStatusCode());
        assertEquals("message", VERIFIED_MESSAGE, tvr.getMessage());
        // The decoded token is what carries the scopes on to JWTConfig.tokenMatches, so a verified
        // result without it grants nothing.
        assertNotNull("the decoded token a verified result carries", tvr.getToken());
    }

    private static void assertRejected(String expectedMessage, TokenVerificationResult tvr) {
        assertEquals("status", REJECTED, tvr.getVerificationStatusCode());
        assertEquals("message", expectedMessage, tvr.getMessage());
        assertNull("the decoded token a rejected result carries", tvr.getToken());
    }

    private static DecodedJWT token(List<String> claimReferers, List<String> ips) {
        return tokenWithClaims(claim(claimReferers), claim(ips));
    }

    private static DecodedJWT tokenWithClaims(Claim refererClaim, Claim ipsClaim) {
        Claim scopesClaim = claim(Collections.singletonList("graphql"));
        DecodedJWT decodedToken = mock(DecodedJWT.class);
        when(decodedToken.getClaim("referer")).thenReturn(refererClaim);
        when(decodedToken.getClaim("ips")).thenReturn(ipsClaim);
        when(decodedToken.getClaim("scopes")).thenReturn(scopesClaim);
        return decodedToken;
    }

    /** A claim carrying a list, or an absent claim when {@code values} is null. */
    private static Claim claim(List<String> values) {
        Claim claim = mock(Claim.class);
        when(claim.asList(String.class)).thenReturn(values);
        // java-jwt answers a NullClaim for an absent claim, and isNull() is true only there.
        when(claim.isNull()).thenReturn(values == null);
        return claim;
    }

    /**
     * A claim the issuer wrote as a scalar. java-jwt reports it exactly as it reports an absent
     * claim through {@code asList}, and {@code isNull()} is what separates the two.
     */
    private static Claim scalarClaim() {
        Claim claim = mock(Claim.class);
        when(claim.asList(String.class)).thenReturn(null);
        when(claim.isNull()).thenReturn(false);
        return claim;
    }
}
