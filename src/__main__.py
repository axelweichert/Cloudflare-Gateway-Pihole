import argparse
from src.domains import BlockDomainConverter, AllowDomainConverter
from src import utils, info, silent_error, error, BLOCK_PREFIX, ALLOW_PREFIX, ENABLE_SNI_FILTER
from src.cloudflare import (
    create_list, update_list, create_rule,
    update_rule, delete_list, delete_rule
)
from src.requests import NotFoundException

# Cloudflare Gateway free tier hard limit for number of lists
MAX_TOTAL_LISTS = 300


class CloudflareManager:
    def __init__(self, cache):
        self.cache = cache

        # Block config
        self.block_list_name = f"[{BLOCK_PREFIX}]"
        self.block_rule_name = f"[{BLOCK_PREFIX}] Block Ads"
        self.block_sni_rule_name = f"[{BLOCK_PREFIX}] Block Ads (SNI)"

        # Allow config
        self.allow_list_name = f"[{ALLOW_PREFIX}]"
        self.allow_rule_name = f"[{ALLOW_PREFIX}] Allow"

    # ------------------------------------------------------------------
    # Generic list/rule sync (shared by both block and allow)
    # ------------------------------------------------------------------
    def _sync_rule(self, list_ids, rule_name, rule_action, rule_priority,
                    filters=None, traffic_field="dns.domains"):
        current_rules = utils.get_current_rules(self.cache, rule_name)
        cgp_rule = next((r for r in current_rules if r["name"] == rule_name), None)
        cgp_list_ids = utils.extract_list_ids(cgp_rule)

        if cgp_rule:
            if set(list_ids) != cgp_list_ids:
                try:
                    updated = update_rule(rule_name, cgp_rule["id"], list_ids,
                                          action=rule_action, priority=rule_priority,
                                          filters=filters, traffic_field=traffic_field)
                    info(f"Updated rule: {updated['name']}")
                    self.cache["rules"] = [
                        r for r in self.cache["rules"] if r["id"] != cgp_rule["id"]
                    ]
                    self.cache["rules"].append(updated)
                except NotFoundException:
                    silent_error(
                        f"Rule {rule_name} ({cgp_rule['id']}) missing on Cloudflare "
                        f"— evicting from cache and recreating"
                    )
                    self.cache["rules"] = [
                        r for r in self.cache["rules"] if r["id"] != cgp_rule["id"]
                    ]
                    rule = create_rule(rule_name, list_ids, action=rule_action,
                                       priority=rule_priority, filters=filters,
                                       traffic_field=traffic_field)
                    info(f"Recreated rule: {rule['name']}")
                    self.cache["rules"].append(rule)
            else:
                silent_error(f"Skipping rule update (unchanged): {rule_name}")
        else:
            rule = create_rule(rule_name, list_ids, action=rule_action,
                               priority=rule_priority, filters=filters,
                               traffic_field=traffic_field)
            info(f"Created rule: {rule['name']}")
            self.cache["rules"].append(rule)

        utils.save_cache(self.cache)

    def _delete_rule_by_name(self, rule_name):
        current_rules = utils.get_current_rules(self.cache, rule_name)
        for rule in current_rules:
            try:
                delete_rule(rule["id"])
                info(f"Deleted rule: {rule['name']}")
            except NotFoundException:
                silent_error(f"Rule {rule['name']} already gone on Cloudflare — skipping")
            self.cache["rules"] = [r for r in self.cache["rules"] if r["id"] != rule["id"]]
            utils.save_cache(self.cache)

    def _sync_lists(self, domains, list_name_prefix, rule_name, rule_action, rule_priority,
                     sni_rule_name=None):
        current_lists = utils.get_current_lists(self.cache, list_name_prefix)

        list_id_to_domains = {}
        for lst in current_lists:
            # Live membership is the source of truth, NOT the cache. The cache
            # key is per-run (github.run_id) and delete_cache() wipes it, so the
            # cached view drifts from Cloudflare. A stale entry made remove_items
            # reference a domain no longer on the list → PATCH 400 "item to be
            # removed … not found in list", killing the whole run. Reading live
            # guarantees remove_items ⊆ actual membership. ~≤183 GETs/run, weekly
            # cron, well inside the rate budget (@retry/rate_limited_request).
            items = utils.get_list_items(lst["id"])
            list_id_to_domains[lst["id"]] = set(items)

        domain_to_list_id = {
            domain: lst_id
            for lst_id, doms in list_id_to_domains.items()
            for domain in doms
        }

        remaining_domains = set(domains) - set(domain_to_list_id.keys())

        list_name_to_id = {lst["name"]: lst["id"] for lst in current_lists}
        existing_indexes = sorted(
            [int(name.split("-")[-1]) for name in list_name_to_id.keys()]
        )

        needed_lists = (len(domains) + 999) // 1000
        all_indexes = set(range(1, max(existing_indexes + [needed_lists]) + 1))

        new_list_ids = []
        for i in all_indexes:
            list_name = f"{list_name_prefix} - {i:03d}"
            if list_name in list_name_to_id:
                list_id = list_name_to_id[list_name]
                current_values = list_id_to_domains[list_id]
                remove_items = current_values - set(domains)
                chunk = current_values - remove_items

                new_items = []
                if len(chunk) < 1000:
                    needed_items = 1000 - len(chunk)
                    new_items = list(remaining_domains)[:needed_items]
                    chunk.update(new_items)
                    remaining_domains.difference_update(new_items)

                if remove_items or new_items:
                    try:
                        update_list(list_id, remove_items, new_items)
                        info(
                            f"Updated list: {list_name} "
                            f"| Added {len(new_items)}, Removed {len(remove_items)} "
                            f"| Total: {len(chunk)}"
                        )
                        self.cache["mapping"][list_id] = list(chunk)
                    except NotFoundException:
                        # Cache is stale: this list was deleted outside the
                        # script (e.g. manually on the dashboard). Evict it
                        # and recreate from scratch instead of failing the run.
                        silent_error(
                            f"List {list_name} ({list_id}) missing on Cloudflare "
                            f"— evicting from cache and recreating"
                        )
                        self.cache["lists"] = [l for l in self.cache["lists"] if l["id"] != list_id]
                        self.cache["mapping"].pop(list_id, None)
                        lst = create_list(list_name, list(chunk))
                        info(f"Recreated list: {lst['name']} with {len(chunk)} domains")
                        self.cache["lists"].append(lst)
                        self.cache["mapping"][lst["id"]] = list(chunk)
                        list_id = lst["id"]
                else:
                    silent_error(f"Skipped (no changes): {list_name} | Total: {len(chunk)}")

                new_list_ids.append(list_id)
            else:
                if remaining_domains:
                    needed_items = min(1000, len(remaining_domains))
                    new_items = list(remaining_domains)[:needed_items]
                    remaining_domains.difference_update(new_items)
                    lst = create_list(list_name, new_items)
                    info(f"Created list: {lst['name']} with {len(new_items)} domains")
                    self.cache["lists"].append(lst)
                    self.cache["mapping"][lst["id"]] = new_items
                    new_list_ids.append(lst["id"])

        # Sync the DNS rule
        self._sync_rule(new_list_ids, rule_name, rule_action, rule_priority)

        # Optional companion Network (L4) rule: blocks by TLS SNI instead of
        # DNS resolution. Reuses the same domain lists — Cloudflare Zero
        # Trust lists of type DOMAIN can be referenced from either a DNS
        # rule (dns.domains) or a Network rule (net.sni.domains). Only takes
        # effect for devices connected via WARP with the TCP proxy enabled.
        if sni_rule_name:
            self._sync_rule(
                new_list_ids, sni_rule_name, rule_action, rule_priority,
                filters=["l4"], traffic_field="net.sni.domains",
            )

        utils.save_cache(self.cache)
        return len(new_list_ids)

    def _delete_by_prefix(self, list_name_prefix, rule_name):
        current_lists = utils.get_current_lists(self.cache, list_name_prefix)
        current_rules = utils.get_current_rules(self.cache, rule_name)
        current_lists.sort(key=utils.safe_sort_key)

        for rule in current_rules:
            try:
                delete_rule(rule["id"])
                info(f"Deleted rule: {rule['name']}")
            except NotFoundException:
                silent_error(f"Rule {rule['name']} already gone on Cloudflare — skipping")
            self.cache["rules"] = [r for r in self.cache["rules"] if r["id"] != rule["id"]]
            utils.save_cache(self.cache)

        for lst in current_lists:
            try:
                delete_list(lst["id"])
                info(f"Deleted list: {lst['name']}")
            except NotFoundException:
                silent_error(f"List {lst['name']} already gone on Cloudflare — skipping")
            self.cache["lists"] = [l for l in self.cache["lists"] if l["id"] != lst["id"]]
            if lst["id"] in self.cache["mapping"]:
                del self.cache["mapping"][lst["id"]]
            utils.save_cache(self.cache)

    # ------------------------------------------------------------------
    # Public actions
    # ------------------------------------------------------------------
    def update_resources(self):
        info("=== [1/2] Processing BLOCK domains ===")
        domains_to_block = BlockDomainConverter().process_urls()

        info("=== [2/2] Processing ALLOW domains ===")
        domains_to_allow = AllowDomainConverter().process_urls()

        # --- Guard: total lists must not exceed Cloudflare free tier limit ---
        block_lists_needed = (len(domains_to_block) + 999) // 1000
        allow_lists_needed = (len(domains_to_allow) + 999) // 1000
        total_lists_needed = block_lists_needed + allow_lists_needed

        info(
            f"Lists needed → Block: {block_lists_needed}, "
            f"Allow: {allow_lists_needed}, "
            f"Total: {total_lists_needed} / {MAX_TOTAL_LISTS}"
        )

        if total_lists_needed > MAX_TOTAL_LISTS:
            error(
                f"Total lists needed ({total_lists_needed}) exceeds "
                f"Cloudflare Gateway free limit of {MAX_TOTAL_LISTS} lists. "
                f"Reduce your adlists or whitelist sources."
            )

        info("=== Syncing BLOCK lists & rule ===")
        # Allow rule has higher precedence (lower number = higher priority)
        self._sync_lists(
            domains_to_block,
            self.block_list_name,
            self.block_rule_name,
            rule_action="block",
            rule_priority=1000,
            sni_rule_name=self.block_sni_rule_name if ENABLE_SNI_FILTER else None,
        )

        info("=== Syncing ALLOW lists & rule ===")
        self._sync_lists(
            domains_to_allow,
            self.allow_list_name,
            self.allow_rule_name,
            rule_action="allow",
            rule_priority=999,   # Lower number = evaluated first → allow wins over block
        )

        info("=== Done ===")

    def delete_resources(self):
        info("=== Deleting BLOCK resources ===")
        self._delete_rule_by_name(self.block_sni_rule_name)
        self._delete_by_prefix(self.block_list_name, self.block_rule_name)
        info("=== Deleting ALLOW resources ===")
        self._delete_by_prefix(self.allow_list_name, self.allow_rule_name)


def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Gateway DNS Filter Manager (Block + Allow)"
    )
    parser.add_argument(
        "action", choices=["run", "leave"], help="run: sync resources | leave: delete all"
    )
    args = parser.parse_args()

    cache = utils.load_cache()
    manager = CloudflareManager(cache)

    if args.action == "run":
        manager.update_resources()
        if utils.is_running_in_github_actions():
            utils.delete_cache()
    elif args.action == "leave":
        manager.delete_resources()
    else:
        error("Invalid action. Choose 'run' or 'leave'.")


if __name__ == "__main__":
    main()
