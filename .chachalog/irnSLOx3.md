---
# Allowed version bumps: patch, minor, major
security-filter-tools: minor
---

Changed how Jahia checks the IP address and referer restrictions that a token carries. (#93)

Jahia compares the token's IP list against the network address that a request arrives from. Jahia refuses a token that does not list that address. A refused token grants no access, so a call that used it now receives the response of a caller with no token.

You are affected if you issue tokens with an IP restriction, and Jahia runs behind a reverse proxy or a load balancer. To check, compare the address in the token with the address of the machine that connects to Jahia. On such a deployment, configure Tomcat's RemoteIpValve so that Jahia sees the visitor's address. Then reissue the affected tokens with that address.

Jahia also matches a referer restriction on the scheme, host and port of the referring page, and then on the path. A referer restriction must be an absolute URL, and it must carry no query string. Jahia writes a warning to the log for an entry it cannot use.
