"""Offline regression tests for NYU CTF metadata, sandboxes, and tasks."""

import importlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.solver import generate

from nyu_ctf_bench import dataset, download
from nyu_ctf_bench.challenge import CTFChallenge
from nyu_ctf_bench.ctf_dataset import CTFDataset

task_module = importlib.import_module("nyu_ctf_bench.task")


@pytest.fixture
def challenge_factory(tmp_path):
    def make(name="Example", **overrides):
        directory = tmp_path / name
        directory.mkdir(exist_ok=True)
        metadata = {
            "name": name,
            "category": "crypto",
            "description": "Find the flag.",
            "flag": "flag{secret}",
            **overrides,
        }
        (directory / "challenge.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        return CTFChallenge({"path": name, "year": "2023", "event": "CSAW"}, tmp_path)

    return make


@pytest.mark.parametrize(
    "points, expected",
    [({}, 0), ({"initial": 500}, 500), ({"points": 100, "initial": 500}, 100)],
)
def test_challenge_metadata(challenge_factory, points, expected):
    challenge = challenge_factory(**points)
    assert challenge.year == 2023
    assert challenge.points == expected
    assert challenge.flag == "flag{secret}"
    assert challenge.flag_format == "flag{...}"
    assert not challenge.container
    assert not challenge.has_files


@pytest.mark.parametrize(
    "description", ["Connect to {box}:{port}; keep {unknown}.", "Find the flag."]
)
def test_description_resolves_or_appends_endpoint(challenge_factory, description):
    challenge = challenge_factory(
        description=description, box="target", port=80, internal_port=8080
    )
    assert challenge.description.count("target:8080") == 1
    if "{unknown}" in description:
        assert "{unknown}" in challenge.description


@pytest.mark.parametrize("description", ["Connect to {box}", "Connect to {port}"])
def test_missing_endpoint_metadata_is_rejected(challenge_factory, description):
    with pytest.raises(RuntimeError, match="placeholder"):
        challenge_factory(description=description)


def test_mta_prices_endpoint_correction(challenge_factory):
    challenge = challenge_factory(name="MTA Prices", box="wrong", port=80)
    assert "web.chal.csaw.io:80" in challenge.description


def test_nonstandard_flag(challenge_factory, caplog):
    challenge = challenge_factory(flag="secret")
    assert challenge.flag_format == "not provided"
    assert "does not follow a standard format" in caplog.text


@pytest.mark.parametrize(
    "service",
    [
        {"privileged": True},
        {"privileged": "true"},
        {"volumes": ["/var/run/docker.sock:/socket:ro"]},
        {"volumes": ["/socket:/var/run/docker.sock"]},
        {"volumes": [{"source": "/var/run/docker.sock", "target": "/socket"}]},
        {"volumes": [{"source": "/socket", "target": "/var/run/docker.sock"}]},
        {"cap_add": ["net_admin"]},
        {"cap_add": "SYS_ADMIN"},
    ],
)
def test_unsafe_compose_is_rejected(tmp_path, service):
    path = tmp_path / "compose.yml"
    path.write_text(yaml.safe_dump({"services": {"target": service}}), encoding="utf-8")
    assert dataset._compose_is_unsafe(path)


@pytest.mark.parametrize(
    "service",
    [
        {},
        {"privileged": False},
        {"cap_add": ["NET_BIND_SERVICE"]},
        {"volumes": ["./data:/data:ro"]},
        {"volumes": None, "cap_add": None},
    ],
)
def test_safe_compose_is_accepted(tmp_path, service):
    path = tmp_path / "compose.yml"
    path.write_text(yaml.safe_dump({"services": {"target": service}}), encoding="utf-8")
    assert not dataset._compose_is_unsafe(path)


@pytest.mark.parametrize(
    "networks", [None, {}, {"ctfnet": {"external": True}, "private": None}]
)
def test_sandbox_hardening_preserves_backend_isolation(networks):
    compose = {
        "services": {
            "web": {
                "ports": ["80:80"],
                "restart": "always",
                "x-default": True,
                "networks": ["ctfnet", "private"],
            },
            "db": {"networks": ["private"]},
            "agent": {"image": "old-agent"},
        },
        "networks": networks,
    }
    dataset._configure_internal_networks(compose)
    dataset._configure_agent_service(compose)
    assert "default" in compose["networks"]
    assert all(
        config["internal"] and "external" not in config
        for config in compose["networks"].values()
    )
    services = compose["services"]
    agent = services["agent"]
    assert agent["networks"] == (["ctfnet"] if networks else ["default"])
    assert set(agent["depends_on"]) == {"web", "db"}
    assert agent["x-default"] is True
    assert agent["image"] == dataset.AGENT_IMAGE
    assert services["db"]["networks"] == ["private"]
    assert not {"ports", "restart", "x-default"} & services["web"].keys()


@pytest.fixture
def local_dataset(tmp_path, monkeypatch, challenge_factory):
    records = {}
    for name, metadata in [
        ("offline", {"files": ["public.txt"]}),
        ("server", {"compose": True, "files": ["public.txt"]}),
        ("unsafe", {"compose": True}),
        ("missing", {"files": ["missing.txt"]}),
        ("empty", {}),
        ("Philanthropy", {"compose": True, "files": ["public.txt"]}),
    ]:
        challenge = challenge_factory(name=name, **metadata)
        records[name] = challenge.challenge_info
        (challenge.challenge_dir / "public.txt").write_text(
            "public artifact", encoding="utf-8"
        )
        (challenge.challenge_dir / "private.txt").write_text(
            "private artifact", encoding="utf-8"
        )
        if challenge.container:
            compose = {
                "services": {
                    "target": {"image": "example", "privileged": name == "unsafe"}
                }
            }
            (challenge.challenge_dir / "docker-compose.yml").write_text(
                yaml.safe_dump(compose), encoding="utf-8"
            )
    index = tmp_path / "test_dataset.json"
    index.write_text(json.dumps(records), encoding="utf-8")
    source = CTFDataset(dataset_json=index)
    monkeypatch.setattr(dataset, "CTFDataset", lambda split: source)
    monkeypatch.setattr(dataset, "INSPECT_EVALS_CACHE_PATH", tmp_path / "cache")
    return source


@pytest.mark.parametrize("mode", ["offline", "server"])
def test_dataset_selection_and_public_artifacts(local_dataset, mode):
    samples = dataset.read_dataset(mode)
    assert len(samples) == 1
    sample = samples[0]
    assert sample.id == 0
    assert sample.target == "flag{secret}"
    assert "flag{secret}" not in sample.input
    assert f"named {mode}" in sample.input
    assert "/ctf_files" in sample.input
    assert sample.files == {
        "/ctf_files/public.txt": str(local_dataset.basedir / mode / "public.txt")
    }
    assert sample.metadata == {
        "source": str(local_dataset.basedir / mode),
        "tags": "crypto",
    }
    assert sample.sandbox.type == "docker"
    compose = yaml.safe_load(Path(sample.sandbox.config).read_text(encoding="utf-8"))
    if mode == "offline":
        assert compose["services"]["agent"]["network_mode"] == "none"
    else:
        assert compose["networks"]["default"]["internal"] is True
        assert compose["services"]["agent"]["x-default"] is True
    assert len(dataset.read_dataset(mode, sample_ids=[0])) == 1
    assert len(dataset.read_dataset(mode, sample_ids=[])) == 0
    assert len(dataset.read_dataset(mode, sample_ids=[99])) == 0


def test_cached_dataset_and_force_rebuild(local_dataset):
    dataset.create_files("offline")
    path = local_dataset.basedir / "offline" / "challenge.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))
    metadata["flag"] = "flag{updated}"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    assert dataset.read_dataset("offline")[0].target == "flag{secret}"
    assert (
        dataset.read_dataset("offline", force_rebuild=True)[0].target == "flag{updated}"
    )


@pytest.mark.parametrize(
    "kwargs", [{}, {"split": "invalid"}, {"split": "test", "version": "invalid"}]
)
def test_invalid_dataset_selection(kwargs):
    with pytest.raises(ValueError, match="Pass either"):
        CTFDataset(**kwargs)


def test_missing_dataset_file(tmp_path):
    with pytest.raises(ValueError, match="Dataset not found"):
        CTFDataset(dataset_json=tmp_path / "missing.json")


@pytest.mark.parametrize("mode", ["server", "offline"])
@pytest.mark.parametrize("custom_solver", [False, True])
def test_task_configuration(monkeypatch, mode, custom_solver):
    samples = MemoryDataset([Sample(input="challenge", target="flag{secret}")])
    read = Mock(return_value=samples)
    agent = Mock(return_value=generate())
    monkeypatch.setattr(task_module, "read_dataset", read)
    monkeypatch.setattr(task_module, "ctf_agent", agent)
    supplied = generate() if custom_solver else None
    task = getattr(task_module, f"NYU_{mode}")(
        solver=supplied,
        shuffle=True,
        max_attempts=2,
        max_messages=10,
        sample_ids=[0],
        force_rebuild=True,
    )
    read.assert_called_once_with(
        mode=mode, shuffle=True, sample_ids=[0], force_rebuild=True
    )
    assert task.dataset is samples
    assert task.scorer
    if custom_solver:
        agent.assert_not_called()
        assert task.solver is supplied
    else:
        agent.assert_called_once_with(max_attempts=2, max_messages=10)


@pytest.mark.parametrize("matching_revision", [True, False])
def test_download_verifies_pinned_revision(tmp_path, monkeypatch, matching_revision):
    run = Mock()
    revision = (
        download.VERSION_REVISIONS[download.DEFAULT_VERSION]
        if matching_revision
        else "unexpected"
    )
    check_output = Mock(return_value=revision + "\n")
    monkeypatch.setattr(download.subprocess, "run", run)
    monkeypatch.setattr(download.subprocess, "check_output", check_output)
    if matching_revision:
        download.download_dataset(download_dir=tmp_path)
    else:
        with pytest.raises(RuntimeError, match="Unexpected commit"):
            download.download_dataset(download_dir=tmp_path)
    target = str(tmp_path / download.DEFAULT_VERSION)
    run.assert_called_once_with(
        [
            "git",
            "clone",
            "--branch",
            download.DEFAULT_VERSION,
            "--depth",
            "1",
            download.REPO_URL,
            target,
        ],
        check=True,
    )
    check_output.assert_called_once_with(
        ["git", "-C", target, "rev-parse", "HEAD"], text=True
    )


@pytest.mark.parametrize("existing", [True, False])
def test_download_skips_existing_or_unsupported_version(
    tmp_path, monkeypatch, existing
):
    run = Mock()
    monkeypatch.setattr(download.subprocess, "run", run)
    version = download.DEFAULT_VERSION if existing else "invalid"
    if existing:
        (tmp_path / version).mkdir()
    download.download_dataset(version=version, download_dir=tmp_path)
    run.assert_not_called()
