from re import match, sub
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import ipaddress
import sys
from collections import defaultdict
import os

MAX_WORKERS = 20 
MAX_DOMAINS = 300  # Augmenté pour plus de découvertes
DNS_TIMEOUT = 2
MAX_DEPTH = 6  # Augmenté pour scan plus profond
MAX_SUBDOMAINS = 100  # Limite le nombre de sous-domaines à tester
TLD_LIST = {'.com', '.fr', '.net', '.org', '.io', '.de', '.uk', '.us', '.ca', '.au', '.co'} # TLD communs 

SRV_RECORDS = [
    "_sip._tcp", "_sip._udp", "_sip._tls",
    "_xmpp-server._tcp", "_xmpp-client._tcp",
    "_ldap._tcp", "_kerberos._tcp",
    "_http._tcp", "_https._tcp",
    "_imap._tcp", "_imaps._tcp",
    "_smtp._tcp", "_smtps._tcp",
    "_pop3._tcp", "_pop3s._tcp"
]



def load_subdomain_wordlist(filename="directory-list-2.3-small.txt", max_entries=MAX_SUBDOMAINS):
    subdomains = []
    wordlist_path = os.path.join(os.path.dirname(__file__), filename)

    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f: # Ouvrir le fichier, le lire ligne par ligne, et ajouter les sous-domaines à la liste subdomains[]
        for line in f:
            line = line.strip() # Enlève les espaces et les retours à la ligne
            if line and not line.startswith('#'): # Lire uniquement les lignes sans # 
                if line.replace('-', '').replace('_', '').isalnum(): # Remplace - et _ par rien et vérifie si le string est alphanumérique
                    subdomains.append(line.lower()) # Ajouter le sous-domaine à la liste en minuscules
                    if len(subdomains) >= max_entries:
                        break
    return subdomains # Liste finale de nos sous domaines à tester


COMMON_SUBDOMAINS = load_subdomain_wordlist() 

REGEX_IP = r"^(?:\d{1,3}\.){3}\d{1,3}$" 

def reverse_dns_lookup(ip):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        result = resolver.resolve_address(ip)
        return [str(r.target).rstrip(".") for r in result]
    except Exception:
        return []
    

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

        # IP Neighbors en range IP +3 -3 juste un revserse dns pour les IPs trouvées
       

        
        # Remonter vers le domaine parent pour découvrir la hiérarchie complète
        # Exemple : ns.octopuce.fr -> octopuce.fr -> fr
        parts = domain.split(".")
        if len(parts) > 2 and depth < MAX_DEPTH - 1:
            parent = ".".join(parts[1:])
            self.add_edge(domain, parent, "PARENT")
            # Ne pas explorer les TLDs purs (juste "fr", "com", etc.)
            # Mais explorer les domaines comme "octopuce.fr"
            is_pure_tld = len(parent.split(".")) == 1 or parent in TLD_LIST
            if not is_pure_tld:
                self.explore_domain(parent, depth + 1)

        parts = domain.split(".")
        is_base_domain = len(parts) == 2 or (len(parts) == 3 and (parts[-2] in ('co', 'gouv')))

        if is_base_domain:
            def check_subdomain(sub):
                subdomain = f"{sub}.{domain}"
                if any(self.query(subdomain, rtype) for rtype in ["A", "AAAA", "CNAME"]):
                    print(f"[+] Trouvé: {subdomain}")
                    self.add_edge(domain, subdomain, "SUBDOMAIN")
                    self.explore_domain(subdomain, depth + 1)

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                executor.map(check_subdomain, COMMON_SUBDOMAINS)


        for r in self.query(domain, "A"):
            ip = ipaddress.IPv4Address(r.address)
            for offset in range(-2, 3, 1):
                neighbor = ip + offset
                for rev_domain in reverse_dns_lookup(str(neighbor)):
                    self.add_edge(domain, rev_domain, f"IP Neighbor {neighbor}")

    def print_report(self):
        for src, edges in self.graph.items():
            print(f"\n{src}")
            for dst, label in sorted(edges):
                print(f"  └─[{label}]→ {dst}")






if __name__ == "__main__":
    if len(sys.argv) != 2 :
        print("Utilisation: python dns_mapper.py <domain> or python dns_mapper.py <IP>")
        sys.exit(1)
    elif sys.argv[1] and match(REGEX_IP, sys.argv[1].strip()):
        ip = sys.argv[1].strip()
        domains = reverse_dns_lookup(ip)
        if domains:
            print(f"Résultats de la recherche inversée pour {ip}:")
            for d in domains:
                print(f"  - {d}")
        else:
            print(f"Aucun résultat trouvé pour l'IP: {ip}")
        sys.exit(0)
    

    domain = sys.argv[1].strip().lower()

    mapper = DNSMapper()

    mapper.explore_domain(domain)
    mapper.print_report()
