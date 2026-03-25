import dns.resolver
import sys
from collections import defaultdict

MAX_DOMAINS = 100        
DNS_TIMEOUT = 2
MAX_DEPTH = 5
TLD_LIST = {'.com', '.fr', '.net', '.org', '.io', '.de', '.uk', '.us', '.ca', '.au', '.co'}          

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "imap", "pop3", "ftp", "sftp", "vpn",
    "api", "dev", "test", "staging", "prod", "production",
    "shop", "store", "news", "blog", "community", "forum",
    "admin", "panel", "dashboard", "console", "control",
    "webmail", "roundcube", "squirrelmail",
    "cpanel", "whm", "plesk",
    "git", "gitlab", "github", "bitbucket", "jenkins",
    "mysql", "db", "database", "redis", "mongo",
    "app", "application", "web", "mobile", "m",
    "cdn", "static", "media", "images", "assets",
    "docs", "documentation", "wiki", "help", "support",
    "download", "downloads", "files", "upload",
    "status", "monitoring", "metrics", "health",
    "auth", "login", "signin", "signup", "register",
    "secure", "ssl", "tls", "certificate",
    "intranet", "extranet", "employees", "staff",
    "crm", "erp", "hr", "finance", "accounting",
    "mail2", "mail3", "mx", "mx1", "mx2",
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "old", "new", "legacy", "beta", "alpha", "demo",
    "remote", "cloud", "backup", "archive",
    "autoconfig", "autodiscover", "cpcontacts", "cpcalendars"
]

SRV_RECORDS = [
    "_sip._tcp", "_sip._udp", "_sip._tls",
    "_xmpp-server._tcp", "_xmpp-client._tcp",
    "_ldap._tcp", "_kerberos._tcp",
    "_http._tcp", "_https._tcp",
    "_imap._tcp", "_imaps._tcp",
    "_smtp._tcp", "_smtps._tcp",
    "_pop3._tcp", "_pop3s._tcp"
]


class DNSMapper:
    def __init__(self):
        self.seen_domains = set()
        self.graph = defaultdict(set)
        self.count = 0

    def query(self, domain, rtype):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            return resolver.resolve(domain, rtype)
        except Exception:
            return []


    def add_edge(self, src, dst, label):
        self.graph[src].add((dst, label))


    def explore_domain(self, domain, depth=0):
        if domain in self.seen_domains:
            return

        if self.count >= MAX_DOMAINS:
            return

        if depth > MAX_DEPTH:
            return

        self.seen_domains.add(domain)
        self.count += 1

        # A / AAAA
        for rtype in ["A", "AAAA"]:
            for r in self.query(domain, rtype):
                self.add_edge(domain, r.address, rtype)

        # CNAME
        for r in self.query(domain, "CNAME"):
            cname = str(r.target).rstrip(".")
            self.add_edge(domain, cname, "CNAME")
            self.explore_domain(cname, depth + 1)

        # MX
        for r in self.query(domain, "MX"):
            mx = str(r.exchange).rstrip(".")
            self.add_edge(domain, mx, "MX")
            self.explore_domain(mx, depth + 1)

        # NS
        for r in self.query(domain, "NS"):
            ns = str(r.target).rstrip(".")
            self.add_edge(domain, ns, "NS")
            self.explore_domain(ns, depth + 1)

        # SOA
        for r in self.query(domain, "SOA"):
            soa = str(r.mname).rstrip(".")
            self.add_edge(domain, soa, "SOA")
            self.explore_domain(soa, depth + 1)

        # SRV
        for srv in SRV_RECORDS:
            fqdn = f"{srv}.{domain}"
            for r in self.query(fqdn, "SRV"):
                target = str(r.target).rstrip(".")
                self.add_edge(domain, target, f"SRV {srv}")
                self.explore_domain(target, depth + 1)

        
        parts = domain.split(".")
        if len(parts) > 2 and depth < MAX_DEPTH - 1:
            parent = ".".join(parts[1:])
            self.add_edge(domain, parent, "PARENT")
            # Ne pas explorer les domaines génériques (TLD)
            if not any(parent.endswith(tld) for tld in TLD_LIST):
                self.explore_domain(parent, depth + 1)

        is_base_domain = len(parts) == 2 or (len(parts) == 3)
        if is_base_domain and depth <= 1:
            for sub in COMMON_SUBDOMAINS:
                subdomain = f"{sub}.{domain}"
                # Vérifier l'existence avec A, AAAA ou CNAME
                exists = False
                for rtype in ["A", "AAAA", "CNAME"]:
                    if self.query(subdomain, rtype):
                        exists = True
                        break

                if exists:
                    self.add_edge(domain, subdomain, "SUBDOMAIN")
                    self.explore_domain(subdomain, depth + 1)


    def print_report(self):
        for src, edges in self.graph.items():
            print(f"\n{src}")
            for dst, label in sorted(edges):
                print(f"  └─[{label}]→ {dst}")



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Utilisation: python dns_mapper.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    mapper = DNSMapper()
    mapper.explore_domain(domain)
    mapper.print_report()