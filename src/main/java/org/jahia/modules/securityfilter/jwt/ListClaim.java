package org.jahia.modules.securityfilter.jwt;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.List;

/**
 * A token claim that carries a list of strings, read as the token's issuer wrote it.
 * <p>
 * {@link Claim#asList} answers {@code null} both for an absent claim and for a claim holding a
 * scalar, so a caller that tests only for {@code null} cannot tell the two apart. This class keeps
 * them apart: {@link Claim#isNull()} is true only for an absent claim, because
 * {@code JsonNodeClaim.claimFromNode} answers a {@code NullClaim} for a missing or JSON-null node
 * and a {@code JsonNodeClaim} for every other node.
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
        return new ListClaim(values, values == null && !claim.isNull());
    }

    /** The values the claim carries, or null when the claim is absent or unreadable. */
    List<String> values() {
        return values;
    }

    /** True when the claim is present and carries something other than a list. */
    boolean isUnreadable() {
        return unreadable;
    }

    /** True when the claim carries at least one value, so it constrains the token. */
    boolean isConstraining() {
        return values != null && !values.isEmpty();
    }
}
