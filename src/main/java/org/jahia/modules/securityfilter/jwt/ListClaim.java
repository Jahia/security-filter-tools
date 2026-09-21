package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.List;

/**
 * A token claim that carries a list of strings, read as the token's issuer wrote it.
 * <p>
 * {@link Claim#asList} answers {@code null} both for a claim that is not set and for a claim
 * holding a scalar, so a caller that tests only for {@code null} cannot tell the two apart. This
 * class keeps them apart on {@link DecodedJWT#getClaims()}, whose key set is the claims the payload
 * carries. A name that key set does not hold is a claim the issuer never wrote, and a name it holds
 * whose {@code asList} answers {@code null} is a claim the issuer wrote as something other than a
 * list.
 * <p>
 * A claim written as JSON {@code null} counts as no list given, the same as an absent claim, which
 * is what {@link Claim#isNull()} adds to the key-set test.
 * <p>
 * Both tests hold across java-jwt majors. On 3.4.0 {@code isNull()} is {@code true} for an absent
 * claim as well as for a JSON {@code null} one, and 4.x narrows it to JSON {@code null} alone and
 * moves "absent" to its own {@code isMissing()}. Reading absence from the key set instead of from
 * {@code isNull()} is what makes this class independent of that change, so {@code pom.xml} pins no
 * version range on the package.
 */
final class ListClaim {

    private final List<String> values;
    private final boolean unreadable;

    private ListClaim(List<String> values, boolean unreadable) {
        this.values = values;
        this.unreadable = unreadable;
    }

    static ListClaim of(DecodedJWT token, String name) {
        Claim claim = token.getClaim(name);
        List<String> values = claim.asList(String.class);
        boolean given = token.getClaims().containsKey(name) && !claim.isNull();
        // A list holding a null entry is a list this code cannot act on, so it counts as unreadable
        // alongside a claim that is given and is no list at all.
        boolean unreadable = (values == null && given) || (values != null && values.contains(null));
        return new ListClaim(unreadable ? null : values, unreadable);
    }

    List<String> values() {
        return values;
    }

    boolean isUnreadable() {
        return unreadable;
    }

    boolean isConstraining() {
        return values != null && !values.isEmpty();
    }
}
