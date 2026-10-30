import argparse
import subprocess
from pathlib import Path

from inspect_evals.constants import INSPECT_EVALS_CACHE_PATH

REPO_URL = "https://github.com/NYU-LLM-CTF/NYU_CTF_Bench.git"
VERSION_REVISIONS = {
    "v20250206": "1dc13a0dc41a71504f727649679e2b5a6d0cb1b1",
    "v20241008": "b3bd1f499ae6883d61a090c3864ff3dad6e07f80",
}
AVAILABLE_VERSIONS = list(VERSION_REVISIONS)
DEFAULT_VERSION = "v20250206"
DEFAULT_DIRECTORY = INSPECT_EVALS_CACHE_PATH / "nyu_ctf_bench"

def download_dataset(version=DEFAULT_VERSION, download_dir=DEFAULT_DIRECTORY):
    """Clone a supported NYU CTF dataset version into the download directory."""

    if version not in AVAILABLE_VERSIONS:
        print(f"Available versions: {', '.join(AVAILABLE_VERSIONS)}")
        return
    target = (Path(download_dir) / version).expanduser().resolve()
    if target.exists():
        print(f"Target directory exists: {target}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    print("Cloning using git...")
    gitcmd = ["git", "clone", "--branch", version, "--depth", "1", REPO_URL, str(target)]
    subprocess.run(gitcmd, check=True)

    # Tags can be moved upstream, so verify that the downloaded dataset is the
    # exact revision reviewed by this implementation.
    actual_revision = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    expected_revision = VERSION_REVISIONS[version]
    if actual_revision != expected_revision:
        raise RuntimeError(
            f"Unexpected commit for {version}: expected {expected_revision}, "
            f"got {actual_revision}"
        )
    print("Cloned!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download the entire dataset from a GitHub",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", help="Version of the dataset",
                        default=DEFAULT_VERSION, choices=AVAILABLE_VERSIONS)
    parser.add_argument("-d", "--directory", help="Directory to download the dataset", default=DEFAULT_DIRECTORY)
    args = parser.parse_args()
    download_dataset(args.version, args.directory)
