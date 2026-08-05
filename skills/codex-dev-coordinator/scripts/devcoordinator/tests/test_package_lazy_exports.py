from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


MODULE_ROOT = Path(__file__).resolve().parents[2]


class PackageLazyExportTests(unittest.TestCase):
    def _run(self, source: str) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", source, str(MODULE_ROOT)],
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        value = json.loads(completed.stdout)
        self.assertIsInstance(value, dict)
        return value

    def test_plain_package_import_does_not_load_runtime_backends(self) -> None:
        value = self._run(
            "import json,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "import devcoordinator;"
            "print(json.dumps({'loaded':sorted(name for name in sys.modules "
            "if name.startswith('devcoordinator.')),'exports':devcoordinator.__all__}))"
        )
        self.assertEqual(value["loaded"], [])
        self.assertIn("AccountStore", value["exports"])
        self.assertIn("build_store_backed_broker_runtime", value["exports"])

    def test_legacy_symbol_is_loaded_only_when_requested(self) -> None:
        value = self._run(
            "import json,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "import devcoordinator;"
            "before='devcoordinator.store' in sys.modules;"
            "resolved=devcoordinator.AccountStore;"
            "from devcoordinator.store import AccountStore;"
            "print(json.dumps({'before':before,'same':resolved is AccountStore,"
            "'broker_backend':'devcoordinator.broker_backend' in sys.modules}))"
        )
        self.assertFalse(value["before"])
        self.assertTrue(value["same"])
        self.assertFalse(value["broker_backend"])

    def test_submodule_from_import_remains_compatible(self) -> None:
        value = self._run(
            "import json,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "from devcoordinator import repository_context;"
            "print(json.dumps({'module':repository_context.__name__,"
            "'broker_backend':'devcoordinator.broker_backend' in sys.modules}))"
        )
        self.assertEqual(value["module"], "devcoordinator.repository_context")
        self.assertFalse(value["broker_backend"])

    def test_current_agent_entrypoints_import_without_host_backends(self) -> None:
        value = self._run(
            "import json,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "from devcoordinator import agent_cli,agent_mcp;"
            "loaded=sorted(name for name in sys.modules "
            "if name.startswith('devcoordinator.'));"
            "print(json.dumps({'loaded':loaded,'cli':agent_cli.__name__,"
            "'mcp':agent_mcp.__name__}))"
        )
        self.assertEqual(value["cli"], "devcoordinator.agent_cli")
        self.assertEqual(value["mcp"], "devcoordinator.agent_mcp")
        self.assertNotIn("devcoordinator.broker_backend", value["loaded"])
        self.assertNotIn("devcoordinator.broker_persistence", value["loaded"])
        self.assertNotIn("devcoordinator.store", value["loaded"])

    def test_every_historical_export_resolves_to_its_original_symbol(self) -> None:
        value = self._run(
            "import importlib,json,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "import devcoordinator;"
            "different=[];"
            "[(different.append(name) if getattr(devcoordinator,name) is not "
            "getattr(importlib.import_module(module,devcoordinator.__name__),attribute) "
            "else None) for name,(module,attribute) in "
            "devcoordinator._LAZY_EXPORTS.items()];"
            "print(json.dumps({'different':different}))"
        )
        self.assertEqual(value["different"], [])


if __name__ == "__main__":
    unittest.main()
