import re


def check_subzone(zone: str, main_zone: str) -> bool:
    """Label-boundary aware: 'evilexample.de' is NOT a subzone of 'example.de'."""
    child = zone.rstrip(".").lower()
    parent = main_zone.rstrip(".").lower()
    if child == parent:
        return False
    return child.endswith("." + parent)


def check_zone_in_regex(zone: str, regex: str) -> bool:
    """Checks if zone is in regex"""
    return re.match(regex, zone.rstrip(".")) is not None


def check_record_in_regex(record: str, regex: str) -> bool:
    """Checks if record is in regex"""
    return re.match(regex, record.rstrip(".")) is not None


def check_zones_equal(zone1: str, zone2: str) -> bool:
    """Checks if zones equal with or without trailing dot"""
    return zone1.rstrip(".") == zone2.rstrip(".")
