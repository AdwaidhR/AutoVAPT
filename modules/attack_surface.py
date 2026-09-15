"""
Attack Surface Map Module
-----------------------------
Pure aggregation - takes the results dict already produced by every
other module and reshapes it into the hierarchical summary used in the
report and the JSON output's "attack_surface" key. Makes no network
requests.
"""


def build(results):
    dns = results.get("dns", {})
    subdomains = results.get("subdomains", {})
    ports = results.get("ports", {})
    web = results.get("web", {})
    crawl = results.get("crawl", {})
    endpoints = results.get("endpoints", {})
    content_discovery = results.get("content_discovery", {})
    tech = results.get("technologies", [])

    target_info = results.get("target_info", {})
    return {
        "target": results.get("target"),
        "target_info": target_info,
        "domains": {
            "primary": results.get("target"),
            "resolved_ipv4": dns.get("ipv4", []),
            "resolved_ipv6": dns.get("ipv6", []),
        },
        "subdomains": {
            "count": len(subdomains.get("discovered", [])),
            "items": [s.get("hostname") for s in subdomains.get("discovered", [])],
        },
        "open_ports": {
            "count": len(ports.get("open_ports", [])),
            "services": [
                {"port": p.get("port"), "service": p.get("service"),
                 "product": p.get("product"), "version": p.get("version")}
                for p in ports.get("open_ports", [])
            ],
        },
        "web_applications": {
            "working_base_url": web.get("working_base_url"),
            "pages_crawled": crawl.get("pages_crawled", 0),
            "forms_found": len(crawl.get("forms", [])),
            "scripts_found": len(crawl.get("scripts", [])),
            "endpoints_found": endpoints.get("total_endpoints", 0),
            "directories_found": len(content_discovery.get("discovered", [])),
            "technologies_identified": [t["technology"] for t in tech],
        },
        "security_findings_summary": {
            "total": len(results.get("findings", {}).get("findings", [])),
        },
    }
