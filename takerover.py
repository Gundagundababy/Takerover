#!/usr/bin/env python3
import asyncio
import argparse
import csv
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import aiohttp
import dns.resolver
import dns.exception

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("subdomain_takeover.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("subdomain-takeover")

# Signatures for different cloud providers
TAKEOVER_SIGNATURES = {
    "CloudFront": "The request could not be satisfied",
    "GitHub": "There isn't a GitHub Pages site here",
    "Heroku": "No such app",
    "S3": "NoSuchBucket",
    "Fastly": "Fastly error: unknown domain",
    "Azure": "404 Not Found",
    "Zendesk": "Help Center Closed",
    "Shopify": "Sorry, this shop is currently unavailable",
    "AWS/S3": "The specified bucket does not exist",
    "Bitbucket": "Repository not found",
    "Ghost": "The thing you were looking for is no longer here, or never was",
    "Pantheon": "The gods are wise, but do not know of the site which you seek",
    "Tumblr": "Whatever you were looking for doesn't currently exist at this address",
    "WordPress": "Do you want to register",
    "TeamWork": "Oops - We didn't find your site",
    "Desk": "Please try again or try Desk.com",
    "Tilda": "Please renew your subscription",
    "Smartling": "Domain is not configured",
    "Acquia": "Site not found",
    "UserVoice": "This UserVoice subdomain is currently available!",
    "Canny": "Company Not Found",
    "Webflow": "The page you are looking for doesn't exist or has been moved",
    "JetBrains": "is not a registered InCloud YouTrack",
    "Aftership": "Oops.",
    "Strikingly": "page not found",
    "Uptimerobot": "page not found",
    "Surge": "project not found",
    "Intercom": "This page is reserved for",
    "Webnode": "This website has been successfully established",
    "Kajabi": "The page you were looking for doesn't exist",
    "Thinkific": "You may have mistyped the address or the page may have moved",
    "Tave": "Domain not found",
    "Wishpond": "https://www.wishpond.com/404?campaign=true",
    "Aftermarket": "Aftermarket.pl - This domain is for sale",
    "Unbounce": "The requested URL was not found on this server",
    "Readthedocs": "unknown to Read the Docs",
    "Teamwork": "Oops - We didn't find your site",
    "Helpjuice": "We could not find what you're looking for",
    "Network Solutions": "should be here but isn't",
    "Agile CRM": "Sorry, this page is no longer available",
    "Anima": "Missing website",
    "Readme.io": "Project doesnt exist... yet!",
    "Pingdom": "Sorry, couldn't find the status page",
    "Kiln": "No such domain",
    "Tictail": "Building a brand of your own?",
    "Campaign Monitor": "Trying to access your account?",
    "Digital Ocean": "Domain uses DO name servers with no records"
}

class SubdomainTakeoverTool:
    def __init__(self, target_domain, output_dir="output", concurrency=20, dns_resolver_ips=None):
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.concurrency = concurrency
        self.subdomains_file = os.path.join(output_dir, f"{target_domain}_subdomains.txt")
        self.vulnerable_file = os.path.join(output_dir, f"{target_domain}_vulnerable.csv")
        self.dns_resolver_ips = dns_resolver_ips or ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Load existing subdomains if file exists
        self.known_subdomains = set()
        if os.path.exists(self.subdomains_file):
            with open(self.subdomains_file, 'r') as f:
                self.known_subdomains = set(line.strip() for line in f)
        
        # Setup CSV file for vulnerable subdomains
        if not os.path.exists(self.vulnerable_file):
            with open(self.vulnerable_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Subdomain", "Type", "Provider", "Timestamp", "Details"])

    async def enumerate_subdomains(self):
        """
        Continuous loop to enumerate subdomains using multiple tools and sources.
        This is the first independent loop mentioned in the text.
        """
        while True:
            try:
                logger.info(f"Starting subdomain enumeration for {self.target_domain}")
                new_subdomains = set()
                
                # Simulate using multiple subdomain enumeration tools
                # In a real implementation, you would call actual tools or APIs
                
                # Example: Use Subfinder
                subfinder_results = await self._run_subfinder()
                new_subdomains.update(subfinder_results)
                
                # Example: Use Amass
                amass_results = await self._run_amass()
                new_subdomains.update(amass_results)
                
                # Example: Use Certificate Transparency logs
                ct_results = await self._check_certificate_transparency()
                new_subdomains.update(ct_results)
                
                # Filter out already known subdomains
                truly_new = new_subdomains - self.known_subdomains
                
                if truly_new:
                    logger.info(f"Found {len(truly_new)} new subdomains")
                    
                    # Append new subdomains to file
                    with open(self.subdomains_file, 'a') as f:
                        for subdomain in truly_new:
                            f.write(f"{subdomain}\n")
                    
                    # Update known subdomains set
                    self.known_subdomains.update(truly_new)
                else:
                    logger.info("No new subdomains found in this iteration")
                
                # Sleep before next enumeration cycle (e.g., 12 hours)
                await asyncio.sleep(43200)  # 12 hours
                
            except Exception as e:
                logger.error(f"Error in subdomain enumeration: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying
    
    async def verify_takeovers(self):
        """
        Continuous loop to verify potential subdomain takeovers.
        This is the second independent loop mentioned in the text.
        """
        while True:
            try:
                if not self.known_subdomains:
                    logger.info("No subdomains to check yet. Waiting...")
                    await asyncio.sleep(300)  # 5 minutes
                    continue
                
                logger.info(f"Starting takeover verification for {len(self.known_subdomains)} subdomains")
                
                # Process in chunks to avoid overwhelming resources
                subdomains_list = list(self.known_subdomains)
                chunk_size = 100
                
                for i in range(0, len(subdomains_list), chunk_size):
                    chunk = subdomains_list[i:i+chunk_size]
                    
                    # First, check DNS status for all subdomains in parallel
                    dns_results = await self._check_dns_status_bulk(chunk)
                    
                    # Then check HTTP responses for domains with potential issues
                    http_check_domains = [domain for domain, status in dns_results.items() 
                                         if status['vulnerable_dns']]
                    
                    if http_check_domains:
                        http_results = await self._check_http_status_bulk(http_check_domains)
                        
                        # Process and record results
                        await self._process_vulnerability_results(dns_results, http_results)
                    
                    # Small delay between chunks
                    await asyncio.sleep(5)
                
                logger.info("Completed takeover verification cycle")
                
                # Sleep before next verification cycle (e.g., 1 hour)
                await asyncio.sleep(3600)  # 1 hour
                
            except Exception as e:
                logger.error(f"Error in takeover verification: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying
    
    async def run(self):
        """Run both loops concurrently"""
        enum_task = asyncio.create_task(self.enumerate_subdomains())
        verify_task = asyncio.create_task(self.verify_takeovers())
        
        # Run both loops indefinitely
        await asyncio.gather(enum_task, verify_task)
    
    # Helper methods for subdomain enumeration
    
    async def _run_subfinder(self):
        """Simulate running subfinder tool"""
        # In a real implementation, you would execute the actual tool and parse results
        await asyncio.sleep(2)  # Simulate processing time
        
        # Return simulated results
        # In real implementation this would be actual data from subfinder
        return {f"sub{i}.{self.target_domain}" for i in range(1, 5)}
    
    async def _run_amass(self):
        """Simulate running amass tool"""
        await asyncio.sleep(3)  # Simulate processing time
        
        # Return simulated results
        return {f"service{i}.{self.target_domain}" for i in range(1, 4)}
    
    async def _check_certificate_transparency(self):
        """Simulate checking certificate transparency logs"""
        await asyncio.sleep(1)  # Simulate processing time
        
        # Return simulated results
        return {f"api{i}.{self.target_domain}" for i in range(1, 3)}
    
    # Helper methods for takeover verification
    
    async def _check_dns_status_bulk(self, domains):
        """
        Check DNS status for multiple domains in parallel.
        This handles both CNAME and NS/MX record checking as mentioned in the text.
        """
        results = {}
        
        async def check_dns(domain):
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.dns_resolver_ips
                
                dns_result = {
                    'domain': domain,
                    'cname': None,
                    'ns': None,
                    'mx': None,
                    'error': None,
                    'vulnerable_dns': False
                }
                
                # Check for CNAME records
                try:
                    cname_records = resolver.resolve(domain, 'CNAME')
                    cname_targets = [str(record.target).rstrip('.') for record in cname_records]
                    dns_result['cname'] = cname_targets
                    
                    # Check if CNAME points to a potentially vulnerable service
                    for cname in cname_targets:
                        for provider in ['s3.amazonaws.com', 'cloudfront.net', 'github.io', 
                                         'azure-api.net', 'herokuapp.com', 'zendesk.com']:
                            if provider in cname:
                                dns_result['vulnerable_dns'] = True
                                break
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    # NXDOMAIN with CNAME could indicate a potential takeover
                    dns_result['error'] = 'NXDOMAIN'
                    dns_result['vulnerable_dns'] = True
                
                # Check for NS records if CNAME not found
                if not dns_result['cname']:
                    try:
                        ns_records = resolver.resolve(domain, 'NS')
                        ns_targets = [str(record).rstrip('.') for record in ns_records]
                        dns_result['ns'] = ns_targets
                        
                        # Check if NS delegation is dangling
                        try:
                            for ns in ns_targets:
                                ip_check = resolver.resolve(ns, 'A')
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            dns_result['vulnerable_dns'] = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        # For NS records, NXDOMAIN might indicate takeover possibility
                        dns_result['error'] = 'NXDOMAIN'
                        dns_result['vulnerable_dns'] = True
                
                # Check for MX records if needed
                if not dns_result['cname'] and not dns_result['ns']:
                    try:
                        mx_records = resolver.resolve(domain, 'MX')
                        mx_targets = [str(record.exchange).rstrip('.') for record in mx_records]
                        dns_result['mx'] = mx_targets
                        
                        # Check if MX records are dangling
                        try:
                            for mx in mx_targets:
                                ip_check = resolver.resolve(mx, 'A')  
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            dns_result['vulnerable_dns'] = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                
                return domain, dns_result
                
            except Exception as e:
                return domain, {
                    'domain': domain,
                    'error': str(e),
                    'vulnerable_dns': False
                }
        
        # Process domains in parallel
        tasks = [check_dns(domain) for domain in domains]
        dns_checks = await asyncio.gather(*tasks)
        
        # Organize results
        for domain, result in dns_checks:
            results[domain] = result
            
        return results
    
    async def _check_http_status_bulk(self, domains):
        """Check HTTP responses for domains to verify takeover signatures"""
        results = {}
        
        async def check_http(domain):
            try:
                async with aiohttp.ClientSession() as session:
                    # Try HTTPS first
                    try:
                        async with session.get(f"https://{domain}", 
                                              timeout=10, 
                                              allow_redirects=True,
                                              headers={"Host": domain}) as response:
                            content = await response.text()
                            status = response.status
                            protocol = "https"
                    except:
                        # Fall back to HTTP
                        try:
                            async with session.get(f"http://{domain}", 
                                                  timeout=10, 
                                                  allow_redirects=True,
                                                  headers={"Host": domain}) as response:
                                content = await response.text()
                                status = response.status
                                protocol = "http"
                        except:
                            return domain, {
                                'domain': domain,
                                'error': "Connection failed",
                                'vulnerable_http': False
                            }
                
                # Check for takeover signatures in the response
                vulnerable = False
                matched_provider = None
                
                for provider, signature in TAKEOVER_SIGNATURES.items():
                    if signature in content:
                        vulnerable = True
                        matched_provider = provider
                        break
                
                return domain, {
                    'domain': domain,
                    'status': status,
                    'protocol': protocol,
                    'vulnerable_http': vulnerable,
                    'provider': matched_provider,
                    'content_sample': content[:200] if vulnerable else None
                }
                
            except Exception as e:
                return domain, {
                    'domain': domain,
                    'error': str(e),
                    'vulnerable_http': False
                }
        
        # Process domains in parallel
        tasks = [check_http(domain) for domain in domains]
        http_checks = await asyncio.gather(*tasks)
        
        # Organize results
        for domain, result in http_checks:
            results[domain] = result
            
        return results
    
    async def _process_vulnerability_results(self, dns_results, http_results):
        """Process and record vulnerability findings"""
        timestamp = datetime.now().isoformat()
        
        vulnerable_domains = []
        
        # Process DNS-level vulnerabilities (NS, MX takeovers)
        for domain, dns_data in dns_results.items():
            if dns_data['vulnerable_dns']:
                takeover_type = None
                provider = None
                details = {}
                
                if dns_data.get('cname'):
                    takeover_type = "CNAME"
                    for cname in dns_data['cname']:
                        for provider_name in ['s3.amazonaws.com', 'cloudfront.net', 'github.io', 
                                             'azure-api.net', 'herokuapp.com']:
                            if provider_name in cname:
                                provider = provider_name
                                break
                    details = {"cname_targets": dns_data['cname']}
                    
                elif dns_data.get('ns'):
                    takeover_type = "NS"
                    details = {"ns_targets": dns_data['ns']}
                    
                elif dns_data.get('mx'):
                    takeover_type = "MX"
                    details = {"mx_targets": dns_data['mx']}
                
                # For DNS-only checks (like Azure), we can mark as vulnerable directly
                if takeover_type and ("azure" in str(details).lower() or 
                                      "office365" in str(details).lower()):
                    vulnerable_domains.append({
                        "domain": domain,
                        "type": takeover_type,
                        "provider": "Azure/Office365",
                        "timestamp": timestamp,
                        "details": json.dumps(details)
                    })
        
        # Process HTTP-level vulnerabilities
        for domain, http_data in http_results.items():
            if http_data.get('vulnerable_http'):
                vulnerable_domains.append({
                    "domain": domain,
                    "type": "HTTP",
                    "provider": http_data.get('provider', 'Unknown'),
                    "timestamp": timestamp,
                    "details": json.dumps({
                        "status": http_data.get('status'),
                        "protocol": http_data.get('protocol'),
                        "content_sample": http_data.get('content_sample')
                    })
                })
        
        # Record findings
        if vulnerable_domains:
            logger.warning(f"Found {len(vulnerable_domains)} potentially vulnerable subdomains!")
            
            with open(self.vulnerable_file, 'a', newline='') as f:
                writer = csv.writer(f)
                for domain_data in vulnerable_domains:
                    writer.writerow([
                        domain_data["domain"],
                        domain_data["type"],
                        domain_data["provider"],
                        domain_data["timestamp"],
                        domain_data["details"]
                    ])
            
            # You could also implement alerting mechanisms here (email, Slack, etc.)
            await self._send_alert(vulnerable_domains)
    
    async def _send_alert(self, vulnerable_domains):
        """Send alert for vulnerable domains (placeholder)"""
        # In a real implementation, this would send an email, Slack message, etc.
        logger.warning(f"ALERT: {len(vulnerable_domains)} vulnerable subdomains detected!")
        for domain in vulnerable_domains:
            logger.warning(f"  - {domain['domain']} ({domain['type']}): {domain['provider']}")


async def main():
    """Main function to run the tool"""
    parser = argparse.ArgumentParser(description="Automated Subdomain Takeover Tool")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Concurrency level")
    parser.add_argument("-d", "--dns", nargs="+", default=["8.8.8.8", "1.1.1.1"], 
                        help="DNS resolvers to use")
    args = parser.parse_args()
    
    print(f"""
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║   Automated Subdomain Takeover Tool           ║
    ║                                               ║
    ║   Target: {args.domain:<30} ║
    ║   Output: {args.output:<30} ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    tool = SubdomainTakeoverTool(
        target_domain=args.domain,
        output_dir=args.output,
        concurrency=args.concurrency,
        dns_resolver_ips=args.dns
    )
    
    try:
        await tool.run()
    except KeyboardInterrupt:
        logger.info("Tool stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())
