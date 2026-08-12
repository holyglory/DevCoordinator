from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.docker_storage import (  # noqa: E402
    _NATIVE_BATCH_SIZE,
    project_docker_storage_inventory,
)


class DockerStorageTests(unittest.TestCase):
    def test_detached_compose_volume_is_exclusively_attributed_and_apply_supported(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="docker-storage-volume-", dir="/tmp") as directory:
            volume_path = Path(directory) / "volume"
            volume_path.mkdir()
            (volume_path / "data").write_bytes(b"volume-data")

            def completed(argv: list[str], stdout: str = "", returncode: int = 0):
                return subprocess.CompletedProcess(argv, returncode, stdout, "")

            def runner(argv, _timeout):
                argv = list(argv)
                if argv[1:4] == ["image", "ls", "--no-trunc"]:
                    return completed(argv)
                if argv[1:4] == ["volume", "ls", "-q"]:
                    return completed(argv, "example_data\n")
                if argv[1:3] == ["volume", "inspect"]:
                    return completed(
                        argv,
                        json.dumps(
                            {
                                "Name": "example_data",
                                "CreatedAt": "2026-08-09T20:00:00Z",
                                "Driver": "local",
                                "Scope": "local",
                                "Labels": {
                                    "com.docker.compose.project": "example",
                                    "com.docker.compose.volume": "data",
                                },
                                "Options": None,
                                "Mountpoint": str(volume_path),
                            }
                        )
                        + "\n",
                    )
                if argv[0:3] == ["/usr/bin/du", "-sb", "--"]:
                    return completed(argv, f"11\t{volume_path}\n")
                if argv[1:4] == ["builder", "du", "--verbose"]:
                    return completed(argv)
                if argv[1:] == ["system", "df", "--format", "json"]:
                    return completed(
                        argv,
                        json.dumps({"Type": "Local Volumes", "Size": "11B"}) + "\n",
                    )
                raise AssertionError(argv)

            graph = {
                "repository_trees": [
                    {
                        "root_repository": {
                            "repo_id": "repo-1",
                            "display_name": "Example",
                            "canonical_root": "/repo",
                        },
                        "scopes": [{"repo_id": "repo-1", "container_resource_ids": []}],
                    }
                ],
                "resources": {"docker": []},
            }
            result = project_docker_storage_inventory(
                graph,
                compose_project_owners={"example": ["repo-1"]},
                runner=runner,
            )

        volume = result["volumes"][0]
        self.assertEqual(volume["project_ids"], ["repo-1"])
        self.assertTrue(volume["compose_owned"])
        self.assertTrue(volume["identity_fingerprint"].startswith("sha256:"))
        plan = next(
            item
            for item in result["cleanup_plans"]
            if item["target_kind"] == "volume"
        )
        self.assertEqual(plan["target_id"], "example_data")
        self.assertEqual(plan["project_ids"], ["repo-1"])
        self.assertTrue(plan["apply_supported"])
        self.assertIn("exclusive_project_ownership", plan["proof"])

    def test_project_attribution_is_disjoint_and_cleanup_plans_are_exact(self) -> None:
        container_id = "a" * 64
        oneoff_id = "d" * 64
        ordinary_compose_id = "e" * 64
        image_id = "sha256:" + "b" * 64
        unused_image_id = "sha256:" + "c" * 64
        with tempfile.TemporaryDirectory(prefix="docker-storage-", dir="/tmp") as directory:
            volume_path = Path(directory) / "volume"
            volume_path.mkdir()
            (volume_path / "data").write_bytes(b"x" * 7)
            unused_volume_path = Path(directory) / "unused-volume"
            unused_volume_path.mkdir()

            def completed(argv: list[str], stdout: str = "", returncode: int = 0):
                return subprocess.CompletedProcess(argv, returncode, stdout, "")

            def runner(argv, _timeout):
                argv = list(argv)
                if argv[1:3] == ["inspect", "--size"]:
                    return completed(
                        argv,
                        json.dumps(
                            {
                                "Id": container_id,
                                "State": {"Running": False},
                                "LogPath": "",
                                "Image": image_id,
                                "SizeRw": 11,
                                "SizeRootFs": 111,
                                "Mounts": [
                                    {
                                        "Type": "volume",
                                        "Name": "owned-volume",
                                        "Source": str(volume_path),
                                    }
                                ],
                            }
                        )
                        + "\n"
                        + json.dumps(
                            {
                                "Id": oneoff_id,
                                "State": {"Running": False},
                                "Config": {
                                    "Labels": {
                                        "com.docker.compose.project": "example",
                                        "com.docker.compose.oneoff": "True",
                                    }
                                },
                                "LogPath": "",
                                "Image": image_id,
                                "SizeRw": 0,
                                "SizeRootFs": 111,
                                "Mounts": [],
                            }
                        )
                        + "\n"
                        + json.dumps(
                            {
                                "Id": ordinary_compose_id,
                                "State": {"Running": False},
                                "Config": {
                                    "Labels": {
                                        "com.docker.compose.project": "example",
                                        "com.docker.compose.oneoff": "False",
                                    }
                                },
                                "LogPath": "",
                                "Image": image_id,
                                "SizeRw": 0,
                                "SizeRootFs": 111,
                                "Mounts": [],
                            }
                        )
                        + "\n",
                    )
                if argv[1:4] == ["image", "ls", "--no-trunc"]:
                    return completed(
                        argv,
                        json.dumps({"ID": image_id})
                        + "\n"
                        + json.dumps({"ID": unused_image_id})
                        + "\n",
                    )
                if argv[1:3] == ["image", "inspect"]:
                    return completed(
                        argv,
                        json.dumps({"Id": image_id, "Size": 100, "RepoTags": ["app:1"]})
                        + "\n"
                        + json.dumps({"Id": unused_image_id, "Size": 50, "RepoTags": ["old:1"]})
                        + "\n",
                    )
                if argv[1:4] == ["volume", "ls", "-q"]:
                    return completed(argv, "owned-volume\nunused-volume\n")
                if argv[1:3] == ["volume", "inspect"]:
                    return completed(
                        argv,
                        json.dumps({"Name": "owned-volume", "Mountpoint": str(volume_path)})
                        + "\n"
                        + json.dumps({"Name": "unused-volume", "Mountpoint": str(unused_volume_path)})
                        + "\n",
                    )
                if argv[0:3] == ["/usr/bin/du", "-sb", "--"]:
                    return completed(
                        argv,
                        f"7\t{volume_path}\n0\t{unused_volume_path}\n",
                    )
                if argv[1:4] == ["builder", "du", "--verbose"]:
                    return completed(
                        argv,
                        json.dumps(
                            {
                                "ID": "cache-1",
                                "Size": "12B",
                                "Reclaimable": True,
                                "UsageCount": 0,
                            }
                        )
                        + "\n",
                    )
                if argv[1:] == ["system", "df", "--format", "json"]:
                    return completed(
                        argv,
                        "\n".join(
                            (
                                json.dumps({"Type": "Images", "Size": "150B"}),
                                json.dumps({"Type": "Containers", "Size": "11B"}),
                                json.dumps({"Type": "Local Volumes", "Size": "7B"}),
                                json.dumps({"Type": "Build Cache", "Size": "12B"}),
                            )
                        )
                        + "\n",
                    )
                raise AssertionError(argv)

            graph = {
                "repository_trees": [
                    {
                        "root_repository": {
                            "repo_id": "repo-1",
                            "display_name": "Example",
                            "canonical_root": "/repo",
                        },
                        "scopes": [
                            {
                                "repo_id": "repo-1",
                                "container_resource_ids": [
                                    "docker-1",
                                    "docker-oneoff",
                                    "docker-compose-service",
                                ],
                            }
                        ],
                    }
                ],
                "resources": {
                    "docker": [
                        {
                            "docker_resource_id": "docker-1",
                            "full_container_id": container_id,
                            "current_name": "example-1",
                        },
                        {
                            "docker_resource_id": "docker-oneoff",
                            "full_container_id": oneoff_id,
                            "current_name": "example-run-1",
                        },
                        {
                            "docker_resource_id": "docker-compose-service",
                            "full_container_id": ordinary_compose_id,
                            "current_name": "example-service-1",
                        },
                    ]
                },
            }

            result = project_docker_storage_inventory(graph, runner=runner)

        self.assertTrue(result["available"])
        project = result["projects"][0]
        self.assertEqual(project["exclusive_attributed_bytes"], 118)
        self.assertEqual(project["components"]["container_writable_bytes"], 11)
        self.assertEqual(project["components"]["exclusive_image_bytes"], 100)
        self.assertEqual(project["components"]["exclusive_volume_bytes"], 7)
        self.assertEqual(result["physical_total_bytes"], 180)
        self.assertEqual(
            result["accounting"]["physical_total_source"], "docker_system_df"
        )
        plan_keys = {
            (plan["target_kind"], plan["target_id"])
            for plan in result["cleanup_plans"]
        }
        self.assertIn(("image", unused_image_id), plan_keys)
        self.assertIn(("volume", "unused-volume"), plan_keys)
        self.assertIn(("build_cache", "cache-1"), plan_keys)
        self.assertNotIn(("container", "docker-1"), plan_keys)
        self.assertIn(("container", "docker-oneoff"), plan_keys)
        self.assertNotIn(("container", "docker-compose-service"), plan_keys)
        oneoff_plan = next(
            plan
            for plan in result["cleanup_plans"]
            if plan["target_id"] == "docker-oneoff"
        )
        self.assertTrue(oneoff_plan["apply_supported"])
        self.assertIn("compose_oneoff", oneoff_plan["proof"])

    def test_image_inspection_batches_large_native_inventory(self) -> None:
        image_ids = [
            "sha256:" + format(index, "064x")
            for index in range(_NATIVE_BATCH_SIZE + 1)
        ]
        inspected_batches: list[list[str]] = []

        def completed(argv: list[str], stdout: str = "", returncode: int = 0):
            return subprocess.CompletedProcess(argv, returncode, stdout, "")

        def runner(argv, _timeout):
            argv = list(argv)
            if argv[1:4] == ["image", "ls", "--no-trunc"]:
                return completed(
                    argv,
                    "".join(json.dumps({"ID": value}) + "\n" for value in image_ids),
                )
            if argv[1:3] == ["image", "inspect"]:
                batch = argv[5:]
                inspected_batches.append(batch)
                return completed(
                    argv,
                    "".join(
                        json.dumps({"Id": value, "Size": 1, "RepoTags": []}) + "\n"
                        for value in batch
                    ),
                )
            if argv[1:4] == ["volume", "ls", "-q"]:
                return completed(argv)
            if argv[1:4] == ["builder", "du", "--verbose"]:
                return completed(argv)
            if argv[1:] == ["system", "df", "--format", "json"]:
                return completed(argv, json.dumps({"Type": "Images", "Size": "33B"}) + "\n")
            raise AssertionError(argv)

        result = project_docker_storage_inventory(
            {"repository_trees": [], "resources": {"docker": []}},
            runner=runner,
        )

        self.assertTrue(result["available"])
        self.assertEqual([len(batch) for batch in inspected_batches], [32, 1])
        self.assertEqual(len(result["images"]), 33)


if __name__ == "__main__":
    unittest.main()
