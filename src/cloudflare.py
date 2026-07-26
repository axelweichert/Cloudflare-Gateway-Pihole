import json
from src import silent_error
from src.requests import (
    cloudflare_gateway_request, retry, rate_limited_request, retry_config,
    ListItemStaleException,
)


@retry(**retry_config)
@rate_limited_request
def create_list(name, domains):
    endpoint = "/lists"
    data = {
        "name": name,
        "description": "Managed by Cloudflare-Gateway-DNS-Filter",
        "type": "DOMAIN",
        "items": [{"value": domain} for domain in domains]
    }
    status, response = cloudflare_gateway_request("POST", endpoint, body=json.dumps(data))
    return response["result"]


@retry(**retry_config)
@rate_limited_request
def update_list(list_id, remove_items, append_items):
    endpoint = f"/lists/{list_id}"
    remove = list(remove_items)
    append = [{"value": domain} for domain in append_items]
    # CF rejects the whole PATCH with 400 if any remove item is already gone
    # (cache↔CF drift). Drop the named item(s) and re-send until it goes through
    # or there is nothing left to do. Guards against loops that don't shrink.
    while True:
        try:
            status, response = cloudflare_gateway_request(
                "PATCH", endpoint, body=json.dumps({"remove": remove, "append": append})
            )
            return response["result"]
        except ListItemStaleException as e:
            trimmed = [d for d in remove if d not in set(e.items)]
            if len(trimmed) == len(remove):
                raise  # nothing matched the reported item(s) — don't loop forever
            remove = trimmed
            silent_error(
                f"Dropped {len(e.items)} stale remove item(s) already absent "
                f"from list {list_id}; retrying PATCH"
            )
            if not remove and not append:
                return None  # nothing left to apply


@retry(**retry_config)
def create_rule(rule_name, list_ids, action="block", priority=1000,
                 filters=None, traffic_field="dns.domains"):
    endpoint = "/rules"
    data = {
        "name": rule_name,
        "description": f"Managed by Cloudflare-Gateway-DNS-Filter ({action})",
        "action": action,
        "precedence": priority,
        "traffic": " or ".join(f'any({traffic_field}[*] in ${lst})' for lst in list_ids),
        "enabled": True,
    }
    if filters:
        data["filters"] = filters
    status, response = cloudflare_gateway_request("POST", endpoint, body=json.dumps(data))
    return response["result"]


@retry(**retry_config)
def update_rule(rule_name, rule_id, list_ids, action="block", priority=1000,
                 filters=None, traffic_field="dns.domains"):
    endpoint = f"/rules/{rule_id}"
    data = {
        "name": rule_name,
        "description": f"Managed by Cloudflare-Gateway-DNS-Filter ({action})",
        "action": action,
        "precedence": priority,
        "traffic": " or ".join(f'any({traffic_field}[*] in ${lst})' for lst in list_ids),
        "enabled": True,
    }
    if filters:
        data["filters"] = filters
    status, response = cloudflare_gateway_request("PUT", endpoint, body=json.dumps(data))
    return response["result"]


@retry(**retry_config)
def get_lists(prefix_name):
    status, response = cloudflare_gateway_request("GET", "/lists")
    lists = response["result"] or []
    return [l for l in lists if l["name"].startswith(prefix_name)]


@retry(**retry_config)
def get_rules(rule_name_prefix):
    status, response = cloudflare_gateway_request("GET", "/rules")
    rules = response["result"] or []
    return [r for r in rules if r["name"].startswith(rule_name_prefix)]


@retry(**retry_config)
@rate_limited_request
def delete_list(list_id):
    endpoint = f"/lists/{list_id}"
    status, response = cloudflare_gateway_request("DELETE", endpoint)
    return response["result"]


@retry(**retry_config)
def delete_rule(rule_id):
    endpoint = f"/rules/{rule_id}"
    status, response = cloudflare_gateway_request("DELETE", endpoint)
    return response["result"]


@retry(**retry_config)
def get_list_items(list_id):
    endpoint = f"/lists/{list_id}/items?limit=1000"
    status, response = cloudflare_gateway_request("GET", endpoint)
    items = response["result"] or []
    return [i["value"] for i in items]
