package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What {@link ListClaim} reads out of a real token, decoded by java-jwt itself.
 * <p>
 * The other three classes in this package drive the decision through Mockito doubles, which state
 * what java-jwt answers rather than measure it. A double that models the library wrongly is the
 * defect this whole change is about, so this class decodes real payloads and pins the doubles to
 * the library. A java-jwt upgrade that moves any of these answers fails here.
 */
public class ListClaimContractTest {

    private static final String CLAIM = "ips";
    private static final String ADDRESS = "203.0.113.7";

    // ---------- the library answers the doubles model ----------

    @Test
    public void javaJwtOmitsAnAbsentClaimFromThePayloadKeySet() {
        DecodedJWT token = decode("{\"iss\":\"t\"}");
        assertFalse("an absent claim is in the key set", token.getClaims().containsKey(CLAIM));
        assertTrue("isNull for an absent claim", token.getClaim(CLAIM).isNull());
    }

    @Test
    public void javaJwtHoldsAJsonNullClaimInThePayloadKeySet() {
        // This is the pair that the key set separates and isNull() does not, on java-jwt 3.4.0.
        DecodedJWT token = decode("{\"ips\":null}");
        assertTrue("a JSON-null claim is in the key set", token.getClaims().containsKey(CLAIM));
        assertTrue("isNull for a JSON-null claim", token.getClaim(CLAIM).isNull());
    }

    @Test
    public void javaJwtReadsAScalarClaimAsNoList() {
        // The defect this change fixes: asList answers null for a scalar exactly as for an absent
        // claim, so asList alone cannot tell a restriction from no restriction.
        DecodedJWT token = decode("{\"ips\":\"" + ADDRESS + "\"}");
        assertTrue("a scalar claim is in the key set", token.getClaims().containsKey(CLAIM));
        assertFalse("isNull for a scalar claim", token.getClaim(CLAIM).isNull());
        assertNull("asList for a scalar claim", token.getClaim(CLAIM).asList(String.class));
    }

    // ---------- what ListClaim makes of each shape ----------

    @Test
    public void anAbsentClaimIsReadableAndConstrainsNothing() {
        assertNoRestriction(read("{\"iss\":\"t\"}"));
    }

    @Test
    public void aJsonNullClaimIsReadableAndConstrainsNothing() {
        assertNoRestriction(read("{\"ips\":null}"));
    }

    @Test
    public void anEmptyListIsReadableAndConstrainsNothing() {
        assertNoRestriction(read("{\"ips\":[]}"));
    }

    @Test
    public void aListOfValuesConstrains() {
        ListClaim claim = read("{\"ips\":[\"" + ADDRESS + "\"]}");
        assertFalse("unreadable", claim.isUnreadable());
        assertTrue("constraining", claim.isConstraining());
        assertEquals("values", Collections.singletonList(ADDRESS), claim.values());
    }

    @Test
    public void aScalarIsUnreadable() {
        assertUnreadable(read("{\"ips\":\"" + ADDRESS + "\"}"));
    }

    @Test
    public void aNumberIsUnreadable() {
        assertUnreadable(read("{\"ips\":42}"));
    }

    @Test
    public void aListHoldingANullEntryIsUnreadable() {
        assertUnreadable(read("{\"ips\":[\"" + ADDRESS + "\",null]}"));
    }

    @Test
    public void aListHoldingAnEmptyStringConstrainsAndIsNotUnreadable() {
        // The guard tests for a null entry, and an empty string is not one. Such a list is a
        // restriction that matches no address, so the token is refused wherever it is presented.
        ListClaim claim = read("{\"ips\":[\"\"]}");
        assertFalse("unreadable", claim.isUnreadable());
        assertTrue("constraining", claim.isConstraining());
        assertEquals("values", Collections.singletonList(""), claim.values());
    }

    // ---------- the contract java-jwt 4.x would present ----------

    /**
     * java-jwt 4.x narrows {@code isNull()} to a JSON-null claim, and moves "absent" to its own
     * {@code isMissing()}. No 4.x jar is on this classpath, so this case states that contract as a
     * double: an absent claim the payload key set omits and whose {@code isNull()} answers false.
     * Reading absence from the key set is what keeps the decision right under it. The read this
     * change replaces called such a claim unreadable, and refused every token carrying none.
     */
    @Test
    public void anAbsentClaimUnderTheJavaJwt4ContractStillConstrainsNothing() {
        Claim absent = mock(Claim.class);
        when(absent.asList(String.class)).thenReturn(null);
        when(absent.isNull()).thenReturn(false);
        DecodedJWT token = mock(DecodedJWT.class);
        when(token.getClaims()).thenReturn(Collections.emptyMap());
        when(token.getClaim(CLAIM)).thenReturn(absent);
        assertNoRestriction(ListClaim.of(token, CLAIM));
    }

    // ---------- helpers ----------

    private static void assertNoRestriction(ListClaim claim) {
        assertFalse("unreadable", claim.isUnreadable());
        assertFalse("constraining", claim.isConstraining());
    }

    private static void assertUnreadable(ListClaim claim) {
        assertTrue("unreadable", claim.isUnreadable());
        assertFalse("constraining", claim.isConstraining());
        assertNull("values", claim.values());
    }

    private static ListClaim read(String payloadJson) {
        return ListClaim.of(decode(payloadJson), CLAIM);
    }

    /**
     * Decodes a token carrying the payload given. {@link JWT#decode} reads the parts and checks no
     * signature, so the third part can be any text.
     */
    private static DecodedJWT decode(String payloadJson) {
        return JWT.decode(base64("{\"alg\":\"HS256\"}") + "." + base64(payloadJson) + ".unchecked");
    }

    private static String base64(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
