"""Read official public release metadata; never install or execute remote code."""
import argparse
import datetime
import json
import urllib.error
import urllib.request
from pathlib import Path


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "ebpf-monitor-research", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="out/competitors.json")
    args = parser.parse_args()
    result = {"observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "repositories": []}
    for repo in ("falcosecurity/falco", "aquasecurity/tracee"):
        row = {"repo": repo, "source": f"https://api.github.com/repos/{repo}/releases/latest", "installed": False, "tested": False}
        try:
            release = get(row["source"])
            row.update(tag=release["tag_name"], published_at=release["published_at"], url=release["html_url"],
                       assets=[{"name": a["name"], "url": a["browser_download_url"], "digest": a.get("digest")} for a in release["assets"]])
            commit = get(f"https://api.github.com/repos/{repo}/commits/{release['tag_name']}")
            row["commit_sha"] = commit["sha"]
        except (OSError, ValueError, KeyError) as exc:
            row["error"] = str(exc)
        result["repositories"].append(row)
    destination = Path(args.out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
