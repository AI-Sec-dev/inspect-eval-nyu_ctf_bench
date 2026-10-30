import json
import re
from pathlib import Path
import logging

logger = logging.getLogger("CTFChallenge")


class CTFChallenge:
    """Represent one NYU CTF challenge and its normalized metadata."""

    def __init__(self, challenge, basedir):
        """Resolve the challenge directory and load its challenge.json file."""
        self.challenge_info = challenge
        self.challenge_dir = Path(basedir) / challenge["path"]
        self.challenge_dir = self.challenge_dir.expanduser().resolve()
        self.load_challenge(self.challenge_dir / "challenge.json")

    def load_challenge(self, challenge_json):
        """Load and normalize challenge metadata from a challenge.json file."""
        self.challenge_json = challenge_json
        self.challenge = json.loads(challenge_json.read_text())

        # The compose flag distinguishes server-backed challenges from challenges that expose only local artifacts.
        self.container = self.challenge.get("compose", False)

        self.files = self.challenge.get("files", [])
        self.has_files = len(self.files) > 0

        self.name = self.challenge.get("name", "UNKNOWN")
        self.category = self.challenge.get("category")
        self.year = int(self.challenge_info["year"])
        self.event = self.challenge_info["event"]
        
        # Dynamic-score challenges use "initial" instead of "points".
        self.points = self.challenge.get("points", self.challenge.get("initial", 0))
        self.flag = self.challenge["flag"]

        # Keep only the shape of a conventional flag for prompt construction; the full flag remains in self.flag for scoring.
        if "{" not in self.flag:
            logger.warning(f"Flag for challenge {self.name} does not follow a standard format, please check!")
            self.flag_format = "not provided"
        else:
            self.flag_format = re.sub(r'\{.*?\}', '{...}', self.flag)

        self.server_name = self.challenge.get("box", None)
        # MTA Prices has an incorrect box value in challenge.json. Its Compose service is reachable through this network alias.
        if self.name == "MTA Prices":
            self.server_name = "web.chal.csaw.io"

        self.port = self.challenge.get("internal_port", self.challenge.get("port", None))
        self.server_description = self.challenge.get("server_description", None)
        self.solved = False

        # Placeholders cannot be rendered into a usable endpoint when their corresponding metadata is absent.
        if "{box}" in self.challenge["description"] and not self.server_name:
            raise RuntimeError(f"Challenge {self.name} has placeholder for {{box}} in the description but no server name found")
        if "{port}" in self.challenge["description"] and not self.port:
            raise RuntimeError(f"Challenge {self.name} has placeholder for {{port}} in the description but no internal_port found")

    @property
    def description(self):
        """Return a formatted description containing a reachable endpoint."""
        # SafeDict leaves unknown placeholders intact while replacing the two endpoint placeholders used by this dataset.
        description = self.challenge["description"].format_map(
            SafeDict(box=self.server_name, port=self.port)
        )
        # Some descriptions omit {box} or {port} entirely. Append the endpoint unless both values are already visible in the formatted text.
        if (
            self.server_name
            and self.port is not None
            and (
                self.server_name not in description
                or str(self.port) not in description
            )
        ):
            description += (
                f"\n\nThe challenge server is available at "
                f"{self.server_name}:{self.port}."
            )
        
        return description    


class SafeDict(dict):
    """
    Helper so that we can format the challenge description without worrying about
    missing keys from accidental use of braces in the description
    """
    def __missing__(self, key):
        return '{' + key + '}'