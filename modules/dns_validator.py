import dns.resolver
import re

def is_valid_domain(domain):
    pattern = r'^(?!-)[A-Za-z0-9.-]+(?<!-)$'
    return bool(re.match(pattern, domain))

def resolve_dns_records(domain):
    """
    Look up standard DNS record types.
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    
    results = {}
    print(f"[*] Querying DNS records for {domain}...")
    for rt in record_types:
        try:
            answers = resolver.resolve(domain, rt)
            results[rt] = [rdata.to_text() for rdata in answers]
        except Exception:
            results[rt] = []
    return results
