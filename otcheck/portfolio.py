"""See patterns across a client's sites."""

from collections import defaultdict


LABELS = {
    "traffic:inbound": "Control traffic arriving from the internet",
    "traffic:crossing": "Control devices reached from outside the control network",
    "traffic:outbound": "Control devices connecting to the internet",
}


def _pattern(key):
    """Reduce a finding key to what it is, leaving out where it was found."""
    parts = key.split(":")
    return ":".join(parts[:2])


def analyse(models, contractors):
    """models: slug -> report model. contractors: slug -> contractor name."""
    repeats = defaultdict(lambda: {"title": "", "sites": set()})
    by_contractor = defaultdict(set)
    for slug, model in models.items():
        for item in model["findings"]:
            entry = repeats[_pattern(item["key"])]
            entry["sites"].add(model["site"].name)
            pattern = _pattern(item["key"])
            if item["source"] == "scan":
                entry["title"] = item["title"].split(" visible on ")[0] + " visible from the internet"
            elif item["source"] == "asset":
                entry["title"] = "Product to check: %s" % pattern.split(":")[1]
            else:
                entry["title"] = LABELS.get(pattern, item["title"])
            if contractors.get(slug) and item["severity"] in ("critical", "high"):
                by_contractor[contractors[slug]].add(model["site"].name)
    return {
        "repeated": sorted(
            ({"title": value["title"], "sites": sorted(value["sites"])}
             for value in repeats.values() if len(value["sites"]) > 1),
            key=lambda item: (-len(item["sites"]), item["title"]),
        ),
        "contractors": sorted(
            ({"name": name, "sites": sorted(sites)} for name, sites in by_contractor.items() if len(sites) > 1),
            key=lambda item: (-len(item["sites"]), item["name"]),
        ),
    }
