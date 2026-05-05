# JWT tokens

## Scope and tokens

A request can be granted a scope through the usage of tokens, passed in the `Authentication: Bearer` header. 

Security filter currently only support signed JWT token. Tokens contain a verified list of scopes, along with restriction on its usage. 
It's possible to restrict the usage of a token based on the client IP or referer header.

### Configuration

Tokens can be generated via the tools section "jwtConfiguration" - the user can specify the list of scopes that will be owned by the token, and fill in the optional restrictions. 
You must customize org.jahia.modules.jwt.token.cfg configuration file before generating any token. 
The file contains the following properties :

- `jwt.issuer` : Name of your organization, that will be included in tokens, only for informational purpose
- `jwt.audience` : The target audience is an identifier for you DX installation - audience is included in the token at generation, and only tokens with the same audience will be accepted.
- `jwt.algorithm` : Algorithm used to sign the token. Only HMAC supported.
- `jwt.secret` : Secret key used to be used with HMAC. It will be used to sign and validate tokens. You must change the secret and keep it safe - any token signed with the same secret can be accepted and will grant the associated scopes.

### JWT example

The getaway app is an example of SPA, accessing specific data through GraphQL. The code can be found on github: [getaway-dx-module](https://github.com/Jahia/getaway-dx-module) and [getaway-reactjs-app](https://github.com/Jahia/getaway-reactjs-app). 

The module first defines different types, that need to be accessible by the react SPA. The [CND file](https://github.com/Jahia/getaway-dx-module/blob/master/src/main/resources/META-INF/definitions.cnd) contains definitions for `gant:destination` , `gant:highlightedLandmarks`

A [configuration file](https://github.com/Jahia/getaway-dx-module/blob/master/src/main/resources/META-INF/configurations/org.jahia.modules.api.permissions-getaway.cfg) will give access
for nodes with these types and `jmix:image`, when they are in `/sites/getaway/contents` and `/sites/getaway/files`. They will be accessible by the `jcr.nodesByQuery` graphql endpoint 
for bearers of the scope `getaway` :

```
permission.getaway.api=graphql.Query.jcr,graphql.JCRQuery.nodesByQuery
permission.getaway.scope=getaway
permission.getaway.nodeType=gant:destination, gant:highlightedLandmarks, jmix:image
permission.getaway.pathPattern=/sites/[^/]+/contents/.*, /sites/[^/]+/files/.*
```

In order for the rule to apply and grant these access, the client will have to provide a valid token containing the corresponding `scope` claim.

The `jwtConfiguration` tool will be used to generate the token. Scope is `getaway`, and we will add more restrictions on the referer field, so that the token can only be used when being used from a site on `http://localhost` or `http://127.0.0.1` .

Generated token will look like that :
`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwOi8vamFoaWEuY29tIiwic3ViIjoiYXBpIHZlcmlmaWNhdGlvbiIsInJlZmVyZXIiOlsiaHR0cDovLzEyNy4wLjAuMSIsImh0dHA6Ly9sb2NhbGhvc3QiXSwiaXNzIjoiZHgiLCJzY29wZXMiOlsiZ2V0YXdheSJdLCJpYXQiOjE1Mzg0NjU3NjQsImp0aSI6ImJiNjUyYmI2LTVlOGUtNGRmZC1hYjI3LWRlYzY4NWQxZmVmYiJ9.YolJyuSXGlvIN9_hL4eH6D9_oFHKwt005y3vfCuR2ZU`

The content of the token can be verified on [jwt.io](https://jwt.io/) :

```json
{
  "aud": "http://jahia.com",
  "sub": "api verification",
  "referer": [
    "http://127.0.0.1",
    "http://localhost"
  ],
  "iss": "dx",
  "scopes": [
    "getaway"
  ],
  "iat": 1538465764,
  "jti": "bb652bb6-5e8e-4dfd-ab27-dec685d1fefb"
}
```

The claims `aud` and `iss` are coming from the configuration file. You can also check the signature on [jwt.io](https://jwt.io/) - here the token is signed with the default key `my super secret secret`. It must match the secret in the configuration file.
`iat` is the date of issue, and `jti` is a unique token identifier. They could be used to set an expiration time or manually revoke a specific token, although the current implementation does not support it yet.

Finally, the application will add the token to its `Authentication: Bearer` header, as in [index.js](https://github.com/Jahia/getaway-reactjs-app/blob/master/src/index.js) .
