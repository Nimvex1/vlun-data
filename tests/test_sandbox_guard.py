"""The PoC sandbox guard must actually enforce its allowlist.

`rerun_v1_pocs.py` used to contain a condition that could never be true —
`any(... for k in ())` iterates nothing — leaving the effective rule as
"the command starts with the word forge". That admits `forge snapshot`,
`forge inspect` and any future subcommand, none of which the campaign needs,
while reading as if a three-entry allowlist were enforced. These tests pin the
narrow rule and fail on the loose one.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import rerun_v1_pocs as R  # noqa: E402


class AllowlistIsPrefixExact(unittest.TestCase):
    def test_the_documented_commands_are_permitted(self):
        for cmd in (["forge", "build"],
                    ["forge", "test", "--match", "test_X", "t.sol"],
                    ["forge", "--version"]):
            R.assert_command_is_sandboxed(cmd)

    def test_other_forge_subcommands_are_rejected(self):
        # A forge token alone is not the allowlist.
        for cmd in (["forge", "snapshot"], ["forge", "inspect", "Contract"],
                    ["forge", "doc"]):
            with self.subTest(cmd=" ".join(cmd)):
                with self.assertRaises(RuntimeError):
                    R.assert_command_is_sandboxed(cmd)

    def test_non_forge_commands_are_rejected(self):
        for cmd in (["curl", "http://169.254.169.254/latest/meta-data"],
                    ["rm", "-rf", "work"], ["bash", "-c", "forge test"]):
            with self.subTest(cmd=" ".join(cmd)):
                with self.assertRaises(RuntimeError):
                    R.assert_command_is_sandboxed(cmd)


class ForbiddenOperationsAreRejected(unittest.TestCase):
    def test_broadcast_and_key_material_never_pass(self):
        for cmd in (["forge", "script", "--broadcast", "s.sol"],
                    ["forge", "test", "--private-key", "0xdead"],
                    ["cast", "send", "0xabc"],
                    ["anvil", "--fork", "http://rpc.invalid"]):
            with self.subTest(cmd=" ".join(cmd)):
                with self.assertRaises(RuntimeError):
                    R.assert_command_is_sandboxed(cmd)

    def test_forbidden_check_runs_before_the_allowlist(self):
        # `forge build` is allowed, so the refusal must come from the
        # forbidden-string scan rather than the allowlist branch.
        with self.assertRaises(RuntimeError) as ctx:
            R.assert_command_is_sandboxed(["forge", "build", "--private-key", "x"])
        self.assertIn("non-sandboxed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
