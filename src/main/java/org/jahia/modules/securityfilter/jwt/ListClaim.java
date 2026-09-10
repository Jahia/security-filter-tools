package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.List;

/**
 * A token claim that carries a list of strings, read as the token's issuer wrote it.
 * <p>
 * {@link Claim#asList} answers {@code null} both for a claim that is not set and for a claim
 * holding a scalar, so a caller that tests only for {@code null} cannot tell the two apart. This
 * class keeps them apart on {@link Claim#isNull()}, which java-jwt 3.4.0 answers {@code true} for a
 * claim that is absent <em>or</em> written as JSON {@code null}, and {@code false} for every other
 * claim. {@code JsonNodeClaim.claimFromNode} maps both of the first two to one {@code NullClaim},
 * so this class cannot separate them either, and it treats both as "no list given".
 * <p>
 * The read is pinned to that contract. java-jwt 4.x moves "absent" to its own {@code isMissing()}
 * and leaves {@code isNull()} for a JSON {@code null} alone, which would invert this class, so
 * {@code pom.xml} imports the package at {@code [3.4,4)}.
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
        // A list holding a null entry is a list this code cannot act on, so it counts as unreadable
        // alongside a claim that is no list at all.
        boolean unreadable = (values == null && !claim.isNull()) || (values != null && values.contains(null));
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
