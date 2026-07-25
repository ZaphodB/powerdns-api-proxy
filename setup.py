import re
from subprocess import check_output

from setuptools import find_packages, setup

requirements = []
with open("./requirements.txt") as f:
    lines = f.read().splitlines()
    for line in lines:
        if not line.startswith("git+ssh"):
            requirements.append(line)

test_requirements = []
with open("./requirements-dev.txt") as f:
    lines = f.read().splitlines()
    for line in lines:
        if not line.startswith("git+ssh"):
            test_requirements.append(line)


def _pep440(described: str) -> str:
    """Turn `git describe --tags` output into a version setuptools accepts.

    On a tag, describe returns `v1.11.1` -> `1.11.1`. Off a tag it returns
    `v1.11.1-35-g0f54f1f`, which is NOT PEP 440 and makes setuptools refuse to
    build at all (`packaging.version.InvalidVersion`). That is a real install
    failure, not cosmetic: it hit the first ans0 deployment of this fork, and
    only when the clone had tags fetched -- a tagless clone silently fell back
    to 1.0.0 below, so the same commit installed or failed depending on how it
    was cloned. Commits after a tag become a PEP 440 local version:
    `1.11.1+35.g0f54f1f`.

    A tag that is not itself a dotted release number (`v1.11-inberlin`) cannot
    be turned into a valid version at all, so it falls back to 1.0.0 rather than
    producing something setuptools will reject at build time.
    """
    base = described.strip().lstrip("v")
    # Anchored on the describe suffix (-<commits>-g<sha>) rather than splitting
    # blindly, so a dashed tag name cannot be mistaken for it.
    match = re.search(r"^(?P<base>.+)-(?P<count>\d+)-(?P<sha>g[0-9a-f]+)$", base)
    if match:
        base = f"{match['base']}+{match['count']}.{match['sha']}"
    if not re.match(r"^\d+(\.\d+)*(\+[0-9a-zA-Z.]+)?$", base):
        print(f"cannot derive a PEP 440 version from {described!r}; using 1.0.0")
        return "1.0.0"
    return base


try:
    version = _pep440(check_output(["git", "describe", "--tags"]).decode())
except Exception as e:
    print(e)
    version = "1.0.0"


setup(
    author="akquinet",
    author_email="noc@akquinet.de",
    python_requires=">=3.8",
    description="PowerDNS-API-Proxy",
    install_requires=requirements,
    include_package_data=True,
    keywords="powerdns_api_proxy",
    name="powerdns_api_proxy",
    packages=find_packages(include=["powerdns_api_proxy", "powerdns_api_proxy.*"]),
    test_suite="tests",
    tests_require=test_requirements,
    version=version,
    zip_safe=False,
)
