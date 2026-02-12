#!/usr/bin/env python3
"""
shared/cymru_resolver.py

Centralized Team Cymru DNS enrichment for ASN and IP lookups.
Replaces duplicated logic across asn_intel.py, tor_intel.py, and vpn_intel.py.

Usage:
    from shared.cymru_resolver import CymruResolver
    
    resolver = CymruResolver()
    info = resolver.enrich_asn("3333")
    # Returns: {"asn": "AS3333", "name": "RIPE-NCC-AS", "country": "NL", "registry": "ripe", "date": "1993-02-23"}
    
    info = resolver.enrich_ip("8.8.8.8")
    # Returns: {"ip": "8.8.8.8", "asn": "AS15169", "name": "GOOGLE", "country": "US", ...}
"""

import re
import logging
import dns.resolver
from typing import Dict, Optional

from shared.retry import retry

logger = logging.getLogger(__name__)

# Regex to extract numeric ASN from various formats (AS3333, as3333, 3333)
ASN_REGEX = re.compile(r'(?:AS|as)?(\d+)')

# DNS query templates
ASN_QUERY_TEMPLATE = "AS{asn}.asn.cymru.com"
IP_ORIGIN_TEMPLATE = "{reversed_ip}.origin.asn.cymru.com"
PEER_QUERY_TEMPLATE = "{reversed_ip}.peer.asn.cymru.com"


class CymruResolver:
    """
    Enriches ASN numbers and IP addresses via Team Cymru DNS TXT lookups.
    
    Team Cymru provides free DNS-based lookups for ASN metadata:
    - AS{N}.asn.cymru.com → TXT record with "ASN | CC | Registry | Date | Name"
    - {reversed_ip}.origin.asn.cymru.com → TXT record with originating ASN info
    """
    
    def __init__(
        self,
        nameservers: list = None,
        timeout: float = 3.0,
        lifetime: float = 3.0,
        max_retries: int = 2
    ):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = nameservers or ['8.8.8.8', '1.1.1.1']
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
        self._max_retries = max_retries
    
    @staticmethod
    def clean_asn(raw_text: str) -> Optional[str]:
        """Extracts numeric ASN string from text like 'AS3333', 'as3333', or '3333'."""
        match = ASN_REGEX.search(raw_text)
        return match.group(1) if match else None
    
    def _parse_cymru_txt(self, txt_record: str) -> Dict[str, str]:
        """
        Parses a Team Cymru TXT response.
        Format: "ASN | CC | Registry | Date | Name"
        Example: "3333 | NL | ripe | 1993-02-23 | RIPE-NCC-AS"
        """
        parts = [p.strip() for p in txt_record.strip('"').split('|')]
        result = {}
        
        if len(parts) >= 1:
            result['asn_raw'] = parts[0]
        if len(parts) >= 2:
            result['country'] = parts[1]
        if len(parts) >= 3:
            result['registry'] = parts[2]
        if len(parts) >= 4:
            result['date'] = parts[3]
        if len(parts) >= 5:
            result['name'] = parts[4]
        
        return result
    
    @retry(
        max_attempts=2,
        backoff_base=1.0,
        exceptions=(dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout)
    )
    def _dns_lookup(self, query: str) -> Optional[str]:
        """Perform a DNS TXT lookup with retry."""
        answers = self.resolver.resolve(query, 'TXT')
        for r in answers:
            return r.to_text().strip('"')
        return None
    
    def enrich_asn(self, asn: str) -> Dict[str, str]:
        """
        Queries Team Cymru for ASN metadata.
        
        Args:
            asn: Numeric ASN string (e.g., "3333", not "AS3333")
        
        Returns:
            Dict with keys: asn, name, country, registry, date.
            Missing fields default to empty string.
        """
        result = {
            "asn": f"AS{asn}",
            "name": "",
            "country": "",
            "registry": "",
            "date": ""
        }
        
        try:
            query = ASN_QUERY_TEMPLATE.format(asn=asn)
            txt = self._dns_lookup(query)
            if txt:
                parsed = self._parse_cymru_txt(txt)
                result.update({
                    "name": parsed.get("name", ""),
                    "country": parsed.get("country", ""),
                    "registry": parsed.get("registry", ""),
                    "date": parsed.get("date", "")
                })
        except Exception as e:
            logger.debug(f"Cymru ASN lookup failed for AS{asn}: {e}")
        
        return result
    
    def enrich_ip(self, ip: str) -> Dict[str, str]:
        """
        Queries Team Cymru for IP origin ASN metadata.
        
        Args:
            ip: IPv4 address string
        
        Returns:
            Dict with keys: ip, asn, name, country, prefix.
        """
        result = {
            "ip": ip,
            "asn": "",
            "name": "",
            "country": "",
            "prefix": ""
        }
        
        try:
            # Reverse the IP octets for the DNS query
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = IP_ORIGIN_TEMPLATE.format(reversed_ip=reversed_ip)
            txt = self._dns_lookup(query)
            
            if txt:
                # Origin format: "ASN | IP Prefix | CC | Registry | Date"
                parts = [p.strip() for p in txt.split('|')]
                if len(parts) >= 1:
                    result['asn'] = f"AS{parts[0].strip()}"
                if len(parts) >= 2:
                    result['prefix'] = parts[1]
                if len(parts) >= 3:
                    result['country'] = parts[2]
                    
                # Now get the ASN name
                asn_num = parts[0].strip() if parts else ""
                if asn_num:
                    asn_info = self.enrich_asn(asn_num)
                    result['name'] = asn_info.get('name', '')
                    
        except Exception as e:
            logger.debug(f"Cymru IP lookup failed for {ip}: {e}")
        
        return result
