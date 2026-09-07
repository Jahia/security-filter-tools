---
security-filter-tools: patch
---

Changed how Jahia checks the IP address and referer restrictions that a token carries.

Jahia compares the token's IP list against the network address that a request arrives from. Jahia matches a referer restriction on the scheme, host and port of the referring page, and then on the path. If Jahia runs behind a reverse proxy or a load balancer, configure Tomcat's RemoteIpValve so that Jahia sees the visitor's address. You can also list the proxy's own addresses in the token.
