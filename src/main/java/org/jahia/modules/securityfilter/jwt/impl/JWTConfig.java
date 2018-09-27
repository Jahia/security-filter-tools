package org.jahia.modules.securityfilter.jwt.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.securityfilter.JWTService;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedServiceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.apache.jackrabbit.util.ISO8601;
import javax.jcr.RepositoryException;
import java.util.*;

public class JWTConfig implements JWTService, ManagedServiceFactory, InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(JWTConfig.class);

    //Configuration as defined by the config file. Includes secret, algorithm etc.
    private Map<String, String> tokenConfig = new HashMap<>();

    public JWTConfig() {
        super();
    }

    @Override
    public String createToken(final Map<String, Object> claims) throws RepositoryException {
        JWTCreator.Builder builder = JWT.create();
        //Generate random uuid for jti claim field
        builder.withJWTId(UUID.randomUUID().toString());
        Date now = new Date();
        builder.withIssuedAt(now);

        //Add public claims to token builder
        addConfigToToken(builder, now);
        //Add private claims to token builder
        addPrivateClaimsToToken(claims, builder);
        return signToken(builder);
    }

    @Override
    public DecodedJWT verifyToken(String token) throws JWTVerificationException, RepositoryException {
        Verification verification = signedVerification();
        addConfigToVerification(verification);
        JWTVerifier verifier = verification.build(); //Reusable verifier instance
        return verifier.verify(token);
    }

    @Override
    public String getName() {
        return "JWT token configuration";
    }

    @Override
    public void updated(String pid, Dictionary<String, ?> properties) throws ConfigurationException {
        if (properties != null) {
            Enumeration<String> keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = keys.nextElement();
                if (StringUtils.startsWith(key, "jwt.")) {
                    String subKey = StringUtils.substringAfter(key, "jwt.");
                    String name = StringUtils.substringBefore(subKey, ".");
                    if (!tokenConfig.containsKey(name)) {
                        tokenConfig.put(name, (String) properties.get(key));
                    }
                }
            }
            logger.info("JWT configuration reloaded");
        }
    }

    @Override
    public void deleted(String pid) {

    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }

    private void addConfigToToken(JWTCreator.Builder builder, Date now) {
        Set<String> keys = tokenConfig.keySet();
        for (String key : keys) {
            switch (key) {
                case "issuer" :
                case "iss" : builder.withIssuer(tokenConfig.get(key));
                break;
                case "subject" :
                case "sub" : builder.withSubject(tokenConfig.get(key));
                break;
                case "audience" :
                case "aud" : builder.withAudience(tokenConfig.get(key));
                break;
                case "expirationTime" :
                case "exp" : builder.withExpiresAt(ISO8601.parse(tokenConfig.get(key)).getTime());
                break;
                case "notBefore" :
                case "nbf" : builder.withNotBefore(ISO8601.parse(tokenConfig.get(key)).getTime());
                break;
            }
        }
    }

    private void addConfigToVerification(Verification verification) {
        Set<String> keys = tokenConfig.keySet();
        for (String key : keys) {
            switch (key) {
                case "audience" :
                case "aud" : verification.withAudience(tokenConfig.get(key));
                    break;
            }
        }
    }

    private void addPrivateClaimsToToken(Map<String, Object> claims, JWTCreator.Builder builder) {
        Set<Map.Entry<String, Object>> entries = claims.entrySet();
        for (Map.Entry<String, Object> entry : entries) {
            Object value = entry.getValue();
            String key = entry.getKey();
            if (value instanceof List) {
                List listValue = (List) value;
                Object firstElement = listValue.get(0);
                if (firstElement instanceof String) {
                    builder.withArrayClaim(key, (String[]) ((List) value).toArray(new String[((ArrayList) value).size()]));
                }
                else if (firstElement instanceof Integer) {
                    builder.withArrayClaim(key, (Integer[]) ((List) value).toArray(new Integer[((ArrayList) value).size()]));
                }
            }
            else if (value instanceof String) {
                builder.withClaim(key, (String) value);
            }
            else if (value instanceof Integer) {
                builder.withClaim(key, (Integer) value);
            }
            else if (value instanceof Long) {
                builder.withClaim(key, (Long) value);
            }
            else if (value instanceof Double) {
                builder.withClaim(key, (Double) value);
            }
            else if (value instanceof Date) {
                builder.withClaim(key, (Date) value);
            }
            else if (value instanceof Boolean) {
                builder.withClaim(key, (Boolean) value);
            }
        }
    }

    private String signToken(JWTCreator.Builder builder) {
        String algorithm = tokenConfig.get("algorithm");
        switch(algorithm) {
            case "HMAC256" : return builder.sign(Algorithm.HMAC256(tokenConfig.get("secret")));
            case "HMAC384" : return builder.sign(Algorithm.HMAC384(tokenConfig.get("secret")));
            case "HMAC512" : return builder.sign(Algorithm.HMAC512(tokenConfig.get("secret")));
        }
        return null;
    }

    private Verification signedVerification() {
        String algorithm = tokenConfig.get("algorithm");
        switch(algorithm) {
            case "HMAC256" : return JWT.require(Algorithm.HMAC256(tokenConfig.get("secret")));
            case "HMAC384" : return JWT.require(Algorithm.HMAC384(tokenConfig.get("secret")));
            case "HMAC512" : return JWT.require(Algorithm.HMAC512(tokenConfig.get("secret")));
        }
        return null;
    }
}
