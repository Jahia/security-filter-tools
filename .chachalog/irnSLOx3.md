---
# Allowed version bumps: patch, minor, major
security-filter-tools: minor
---

Changed how Jahia checks the IP address and referer restrictions that a token carries.

Jahia compares the token's IP list against the network address that a request arrives from. Jahia refuses a token that does not list that address, so the request loses the access the token grants. You are affected if you issue tokens with an IP restriction and Jahia runs behind a reverse proxy or a load balancer. Configure Tomcat's RemoteIpValve on such a deployment, so that Jahia sees the visitor's address and not the proxy's. Jahia also matches a referer restriction on the scheme, host and port of the referring page, and then on the path.
