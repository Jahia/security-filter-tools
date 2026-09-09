# security-filter-tools Changelog

## 0.1.0

### New Features

* Changed how Jahia checks the IP address and referer restrictions that a token carries. (#93)

  Jahia compares the token's IP list against the network address that a request arrives from. Jahia refuses a token that does not list that address. A refused token grants no access, so a call that used it now receives the response of a caller with no token.

  You are affected if you issue tokens with an IP restriction, and Jahia runs behind a reverse proxy or a load balancer. To check, compare the address in the token with the address of the machine that connects to Jahia. On such a deployment, configure Tomcat's RemoteIpValve so that Jahia sees the visitor's address. Then reissue the affected tokens with that address.

  Jahia also matches a referer restriction on the scheme, host and port of the referring page, and then on the path. A referer restriction must be an absolute URL, and it must carry no query string. Jahia writes a warning to the log for an entry it cannot use.

* Clean up webpack federation implementation, expose @apollo/react-hooks for backward compatibility (#71)

### Bug Fixes

* **JWT Refactoring**: Relocated the JWT implementation within the security filter tools for better organization. (#67)

* Set minimum jahia supported version to 8.1.9.2. The module is compatible only with Jahia versions 8.1.9.2 to 8.2 (excluded), 8.2.2.2 to 8.2.3.0 (excluded), and 8.2.3.1 or higher — it will not start outside these ranges. (#76)
