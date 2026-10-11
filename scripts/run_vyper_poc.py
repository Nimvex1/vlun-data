#!/usr/bin/env python3
"""Run the Vyper compile/executable PoCs of VLUN v2.2 and print observations.

Two experiments, each reproducing one published Vyper advisory:

  optimizer_ternary  GHSA-6j9c-gvcw-74fj
      With optimization on, `(msg.value | K)` used as a branch of a ternary
      compiles to the constant 1; `--optimize none` keeps the correct value.
      Verified statically (compiler IR) *and* by deploying both builds on a
      local anvil node and calling the function with value=5.

  rawcall_value      GHSA-x2c2-q32w-4w6m
      `raw_call(..., is_delegate_call=True, value=...)` compiles without error
      on the vulnerable compiler and is rejected on the patched one, with a
      control contract that has no `value=` kwarg and compiles on both.

Every observation is printed as `OBS name=value`; every assertion as
`CHECK pass name` / `CHECK fail name`.  The caller (scripts/run_ml_pocs.py)
asserts on those lines rather than on an exit code, because these runs are
judged against the published claim.

Exit codes: 0 assertions ran (check the CHECK lines), 127 an environment
requirement (python env, anvil, cast) is unavailable.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POCS = ROOT / "experiments_v2_2" / "pocs" / "vyper"
TEMP = Path(os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp")
VENV = {
    "0.3.10": TEMP / "opencode" / "vyp310",
    "0.4.0": TEMP / "opencode" / "vyp40",
}
# anvil's first development account; local test node only, no funds of value.
ANVIL_KEY = ("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

CHECKS: list[dict] = []


def obs(name: str, value) -> None:
    print(f"OBS {name}={value}", flush=True)


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail})
    tail = f" :: {detail}" if detail else ""
    print(f"CHECK {'pass' if ok else 'fail'} {name}{tail}", flush=True)


def venv_python(tag: str) -> Path | None:
    exe = VENV[tag] / "Scripts" / "python.exe"
    if exe.exists():
        return exe
    exe = VENV[tag] / "bin" / "python"
    return exe if exe.exists() else None


def unavailable(reason: str) -> "None":
    print(f"ERROR {reason}", flush=True)
    raise SystemExit(127)


def vyper_compile(tag: str, args: list[str], timeout: int = 240):
    py = venv_python(tag)
    if py is None:
        unavailable(f"venv_missing vyper-{tag}")
    argv = [str(py), "-m", "vyper"] + args
    p = subprocess.run(argv, cwd=str(POCS), capture_output=True, text=True,
                       errors="replace", timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def vyper_version(tag: str) -> str:
    py = venv_python(tag)
    if py is None:
        return "unavailable"
    p = subprocess.run([str(py), "-m", "vyper", "--version"],
                       capture_output=True, text=True, errors="replace",
                       timeout=120)
    return (p.stdout or p.stderr).strip().splitlines()[0]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Node:
    def __init__(self, port: int):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["anvil", "--port", str(self.port), "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                unavailable("anvil_exited_before_it_was_ready")
            try:
                p = subprocess.run(
                    ["cast", "chain-id", "--rpc-url", self.url],
                    capture_output=True, text=True, errors="replace", timeout=10)
                if p.returncode == 0:
                    return self
            except (OSError, subprocess.TimeoutExpired):
                pass
            time.sleep(0.4)
        unavailable("anvil_did_not_become_ready")
        return self

    def __exit__(self, *exc):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def cast(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["cast"] + args, capture_output=True, text=True,
                              errors="replace", timeout=timeout)
    except FileNotFoundError:
        unavailable("cast_missing")


def deploy(node: Node, bytecode: str) -> str | None:
    # cast 1.8.3 parses everything after `--create <CODE>` as positional, so the
    # wallet and rpc options have to come first.
    p = cast(["send", "--private-key", ANVIL_KEY, "--rpc-url", node.url,
              "--json", "--create", bytecode])
    if p.returncode != 0:
        obs("deploy_error", (p.stderr or p.stdout).strip().splitlines()[0][:160]
            if (p.stderr or p.stdout).strip() else "no output")
        return None
    try:
        receipt = json.loads(p.stdout)
    except json.JSONDecodeError:
        obs("deploy_error", "non json receipt")
        return None
    addr = receipt.get("contractAddress")
    if not addr:
        r = cast(["receipt", receipt.get("transactionHash", ""), "--rpc-url",
                  node.url, "--json"])
        try:
            addr = json.loads(r.stdout).get("contractAddress")
        except json.JSONDecodeError:
            addr = None
    return addr


def call_calc(node: Node, addr: str) -> str:
    """calc(true) payable with msg.value = 5 wei."""
    p = cast(["call", addr, "calc(bool)(uint256)", "true", "--value", "5wei",
              "--rpc-url", node.url])
    if p.returncode != 0:
        return "error:" + ((p.stderr or p.stdout).strip().splitlines() or
                           ["no output"])[0][:160]
    return p.stdout.strip()


def hexint(text: str) -> int | None:
    try:
        return int(text, 16)
    except (ValueError, TypeError):
        return None


def experiment_optimizer() -> None:
    src = "optimizer_ternary.vy"
    obs("vyper_0.3.10", vyper_version("0.3.10"))
    obs("vyper_0.4.0", vyper_version("0.4.0"))

    rc, ir_gas, err = vyper_compile("0.3.10", ["-f", "ir", "--optimize", "gas", src])
    folded = "1 <msg.value | 2" in ir_gas
    check("ir_v0.3.10_optimize_gas_folds_msg_value_or_2_to_1",
          rc == 0 and folded, f"rc={rc} folded={folded}")

    rc2, ir_none, _ = vyper_compile("0.3.10", ["-f", "ir", "--optimize", "none", src])
    folded_none = "1 <msg.value | 2" in ir_none
    has_callvalue = "callvalue" in ir_none
    check("ir_v0.3.10_optimize_none_keeps_the_callvalue_expression",
          rc2 == 0 and not folded_none and has_callvalue,
          f"rc={rc2} folded={folded_none} callvalue={has_callvalue}")

    rc4, ir_gas4, _ = vyper_compile("0.4.0", ["-f", "ir", "--optimize", "gas", src])
    obs("ir_v0.4.0_optimize_gas_still_folds",
        rc4 == 0 and "1 <msg.value | 2" in ir_gas4)
    obs("advisory_names_a_patched_version", "no")

    rc_b, bytecode_gas, err_b = vyper_compile(
        "0.3.10", ["-f", "bytecode", "--optimize", "gas", src])
    rc_n, bytecode_none, _ = vyper_compile(
        "0.3.10", ["-f", "bytecode", "--optimize", "none", src])
    check("bytecode_builds_produced", rc_b == 0 and rc_n == 0,
          f"gas_rc={rc_b} none_rc={rc_n}")
    if not (rc_b == 0 and rc_n == 0):
        return

    with Node(free_port()) as node:
        addr_gas = deploy(node, bytecode_gas.strip())
        addr_none = deploy(node, bytecode_none.strip())
        check("both_builds_deployed", bool(addr_gas) and bool(addr_none),
              f"gas={addr_gas} none={addr_none}")
        if not (addr_gas and addr_none):
            return
        got_gas = call_calc(node, addr_gas)
        got_none = call_calc(node, addr_none)
        obs("calc_true_with_5wei_on_optimize_gas", got_gas)
        obs("calc_true_with_5wei_on_optimize_none", got_none)
        check("runtime_optimize_gas_calc_true_with_value_5_returns_1",
              hexint(got_gas) == 1, f"returned {got_gas}")
        check("runtime_optimize_none_calc_true_with_value_5_returns_7",
              hexint(got_none) == 7, f"returned {got_none}")


def experiment_rawcall() -> None:
    value_src, control_src = "rawcall_value.vy", "rawcall_control.vy"
    obs("vyper_0.3.10", vyper_version("0.3.10"))
    obs("vyper_0.4.0", vyper_version("0.4.0"))

    rc_vuln, _, _ = vyper_compile("0.3.10", [value_src])
    check("vulnerable_compiler_accepts_value_kwarg_on_a_delegate_call",
          rc_vuln == 0, f"rc={rc_vuln}")

    rc_ctl, _, _ = vyper_compile("0.3.10", [control_src])
    check("vulnerable_compiler_also_accepts_the_control_without_value",
          rc_ctl == 0, f"rc={rc_ctl}")

    rc_fixed, _, err_fixed = vyper_compile("0.4.0", [value_src])
    exc_line = next((ln.strip() for ln in err_fixed.splitlines()
                     if "Exception" in ln or "Error" in ln),
                    (err_fixed.strip().splitlines() or [""])[-1])
    rejected = "value=" in err_fixed and "static or delegate" in err_fixed
    obs("patched_compiler_error", exc_line[:200])
    check("patched_compiler_rejects_value_kwarg_on_a_delegate_call",
          rc_fixed != 0 and rejected, f"rc={rc_fixed} rejected={rejected}")

    rc_ctl_fixed, _, _ = vyper_compile("0.4.0", [control_src])
    check("patched_compiler_still_accepts_the_control_without_value",
          rc_ctl_fixed == 0, f"rc={rc_ctl_fixed}")


EXPERIMENTS = {
    "optimizer_ternary": experiment_optimizer,
    "rawcall_value": experiment_rawcall,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--id", required=True, choices=sorted(EXPERIMENTS))
    args = ap.parse_args()

    EXPERIMENTS[args.id]()

    failed = [c for c in CHECKS if not c["ok"]]
    print(f"checks: {len(CHECKS)} passed, {len(failed)} failed, 0 skipped",
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
