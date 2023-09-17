import asyncio
import logging
import re

import aiohttp

from src import cloudflare

replace_pattern = re.compile(r"(^([0-9.]+|[0-9a-fA-F:.]+)\s+|^(\|\||@@\|\||\*\.|\*))")
domain_pattern = re.compile(
    r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])"
    r"(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$"
)
ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

class App:
    def __init__(
        self, adlist_name: str, adlist_urls: list[str], whitelist_urls: list[str]
    ):
        self.adlist_name = adlist_name
        self.adlist_urls = adlist_urls
        self.whitelist_urls = whitelist_urls
        self.name_prefix = f"[AdBlock-{adlist_name}]"
        self.higher_level_domains = set()

    async def run(self):
        async with aiohttp.ClientSession() as session:
            file_content = "".join(
                await asyncio.gather(
                    *[
                        self.download_file_async(session, url)
                        for url in self.adlist_urls
                    ]
                )
            )
            white_content = "".join(
                await asyncio.gather(
                    *[
                        self.download_file_async(session, url)
                        for url in self.whitelist_urls
                    ]
                )
            )
        white_domains = self.convert_white_domains(white_content)
        domains = self.convert_to_domain_list(file_content, white_domains)

        # check if number of domains exceeds the limit
        if len(domains) == 0:
            logging.warning("No domains found in the adlist file. Exiting script.")
            return 
        
        # stop script if the number of final domains exceeds the limit
        if len(domains) > 300000:
            logging.warning("The number of final domains exceeds the limit. Exiting script.")
            return

        # check if the list is already in Cloudflare
        cf_lists = await cloudflare.get_lists(self.name_prefix)

        logging.info(f"Number of lists in Cloudflare: {len(cf_lists)}")

        # compare the lists size
        if len(domains) == sum([l["count"] for l in cf_lists]):
            logging.warning("Lists are the same size, checking policy")
            cf_policies = await cloudflare.get_firewall_policies(self.name_prefix)

            if len(cf_policies) == 0:
                logging.info("No firewall policy found, creating new policy")
                cf_policies = await cloudflare.create_gateway_policy(
                    f"{self.name_prefix} Block Ads", [l["id"] for l in cf_lists]
                )
            else:
                logging.warning("Firewall policy already exists, exiting script")
                return

            return 

        # Delete existing policy created by script
        policy_prefix = f"{self.name_prefix} Block Ads"
        deleted_policies = await cloudflare.delete_gateway_policy(policy_prefix)
        logging.info(f"Deleted {deleted_policies} gateway policies")

        # Delete old lists on Cloudflare 
        delete_list_tasks = []
        for l in cf_lists:
            logging.info(f"Deleting list {l['name']} - ID:{l['id']} ")
            delete_list_tasks.append(cloudflare.delete_list(l["name"], l["id"]))
        await asyncio.gather(*delete_list_tasks)

        # Start creating new lists and firewall policy concurrently
        create_list_tasks = []
        for i, chunk in enumerate(self.chunk_list(domains, 1000)):
            list_name = f"{self.name_prefix} {i + 1}"
            logging.info(f"Creating list {list_name}")
            create_list_tasks.append(cloudflare.create_list(list_name, chunk))
    
        cf_lists = await asyncio.gather(*create_list_tasks)

        cf_policies = await cloudflare.get_firewall_policies(self.name_prefix)
        logging.info(f"Number of policies in Cloudflare: {len(cf_policies)}")

        if len(cf_policies) == 0:
            logging.info("Creating firewall policy")
            cf_policies = await cloudflare.create_gateway_policy(
                policy_prefix, [l["id"] for l in cf_lists]
            )
        elif len(cf_policies) != 1:
            logging.error("More than one firewall policy found")
            raise Exception("More than one firewall policy found")
        else:
            logging.info("Updating firewall policy")
            update_policy_task = asyncio.create_task(
                cloudflare.update_gateway_policy(
                    policy_prefix, cf_policies[0]["id"], [l["id"] for l in cf_lists],
                )
            )
            await update_policy_task

        logging.info("Done")

    async def download_file_async(self, session: aiohttp.ClientSession, url: str):
        async with session.get(url) as response:
            text = await response.text("utf-8")
            logging.info(f"Downloaded file from {url} File size: {len(text)}")
            return text

    def convert_to_domain_list(self, file_content: str, white_domains: set[str]):
        domains = set()
        for line in file_content.splitlines():

            # skip comments and empty lines
            if line.startswith(("#", "!", "/")) or line == "":
                continue

            # convert to domains
            linex = line.lower().strip().split("#")[0].split("^")[0].replace("\r", "")
            domain = replace_pattern.sub("", linex, count=1)
            try:
                domain = domain.encode("idna").decode("utf-8", "replace")
            except Exception:
                continue

            # remove not domains
            if not domain_pattern.match(domain) or ip_pattern.match(domain):
                continue

            # Check if the domain is a subdomain of an existing higher-level domain
            parts = domain.split(".")
            is_subdomain = any(".".join(parts[i:]) in self.higher_level_domains for i in range(len(parts) - 1, 0, -1))

            # If it's not a subdomain, add it to the final list
            if not is_subdomain:
                domains.add(domain)

            # Add the domain to the set of higher-level domains
            self.higher_level_domains.add(domain)

        logging.info(f"Number of block domains: {len(domains)}")

        # remove white domains
        domains = sorted(list(domains - white_domains))

        logging.info(f"Number of final domains: {len(domains)}")

        return domains
    
    def convert_white_domains(self, white_content: str):
        white_domains = set()
        for line in white_content.splitlines():
            
            # skip comments and empty lines
            if line.startswith(("#", "!", "/")) or line == "":
                continue

            # convert to domains
            linex = line.lower().strip().split("#")[0].split("^")[0].replace("\r", "")
            white_domain = replace_pattern.sub("", linex, count=1)
            try:
                white_domain = white_domain.encode("idna").decode("utf-8", "replace")
            except Exception:
                continue
                
            # remove not domains
            if not domain_pattern.match(white_domain) or ip_pattern.match(white_domain):
                continue

            white_domains.add(white_domain)
            
        # remove duplicate line
        logging.info(f"Number of white domains: {len(white_domains)}")

        return white_domains

    def chunk_list(self, _list: list[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i : i + n]

    async def delete(self):
        # Delete gateway policy
        policy_prefix = f"{self.name_prefix} Block Ads"
        deleted_policies = await cloudflare.delete_gateway_policy(policy_prefix)
        logging.info(f"Deleted {deleted_policies} gateway policies")

        # Delete lists
        cf_lists = await cloudflare.get_lists(self.name_prefix)
        delete_list_tasks = []
        for l in cf_lists:
            logging.info(f"Deleting list {l['name']} - ID:{l['id']} ")
            delete_list_tasks.append(cloudflare.delete_list(l["name"], l["id"]))
        await asyncio.gather(*delete_list_tasks)
        logging.info("Deletion completed")
