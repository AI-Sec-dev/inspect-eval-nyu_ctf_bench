import json
import logging
from pathlib import Path

from .download import DEFAULT_DIRECTORY, DEFAULT_VERSION, AVAILABLE_VERSIONS, download_dataset

logger = logging.getLogger("CTFDataset")

class CTFDataset(dict):
    """Load and provide access to the metadata index for one NYU CTF split."""

    def __init__(self, dataset_json=None, split=None, version=DEFAULT_VERSION):
        if dataset_json is not None:
            dataset_json = Path(dataset_json).expanduser().resolve()
        elif split in ("test", "development") and version in AVAILABLE_VERSIONS:
            dataset_json = Path(DEFAULT_DIRECTORY) / version / f"{split}_dataset.json"
            dataset_json = dataset_json.expanduser().resolve()
            if not dataset_json.exists():
                download_dataset(version)
        else:
            raise ValueError("Pass either dataset_json or split (one of 'test' or 'development')")

        # Confirm that dataset is present
        if not dataset_json.exists():
            raise ValueError(f"Dataset not found: {dataset_json.parent}")
        self.dataset_dir = dataset_json.parent
        with dataset_json.open() as f:
            self.dataset = json.load(f)

    @property
    def basedir(self):
        return self.dataset_dir

    def all(self):
        return self.dataset.items()