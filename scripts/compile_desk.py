#!/usr/bin/env python3
"""Compile the production Gall agent with Vere's standalone Ivory compiler.

No pier, ship, lifecycle arm, request, fixture, or test input is created or run.
Clay imports become typed library vases; source bodies are compiled unchanged.
Slap evaluates only top-level library/core construction, as compilation requires.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

IMPORT = re.compile(r"^/([+-])[ \t]+([^\n]+)\n", re.MULTILINE)
MODULE = re.compile(r"[a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*)*\Z")
FACE = re.compile(r"[a-z][a-z0-9-]*\Z")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def source_cord(data: bytes) -> str:
    # Fixed-width encoding chunks avoid quadratic parsing of giant hex atoms.
    # rep's final high zero padding does not alter the atom; interior zeros remain.
    chunks = []
    for offset in range(0, len(data), 4096):
        digits = format(int.from_bytes(data[offset:offset + 4096], "little"), "x")
        first = len(digits) % 4 or 4
        groups = [digits[:first]] + [digits[index:index + 4] for index in range(first, len(digits), 4)]
        chunks.append("0x" + ".".join(groups))
    return "`@t`(rep 15 ~[" + " ".join(chunks) + "])"


def compile_source(desk: Path, arvo: Path) -> tuple[str, list[dict[str, str]]]:
    roots = [desk.resolve(), arvo.resolve()]
    nodes: list[str] = []
    names: dict[str, str] = {}
    visiting: set[str] = set()
    sources: list[dict[str, str]] = []

    def visit(relative: str) -> str:
        if relative in names:
            return names[relative]
        if relative in visiting:
            raise ValueError(f"Cyclic production import: {relative}")
        visiting.add(relative)
        source = next((root / relative for root in roots if (root / relative).is_file()), None)
        if source is None:
            raise ValueError(f"Missing production dependency: {relative}")
        source = source.resolve()
        # Urbit's pkg/arvo contains supported symlinks into sibling pkg desks.
        # Resolve them normally and record the actual file in the build receipt.
        data = source.read_bytes()
        text = data.decode("utf-8")
        dependencies: list[tuple[str | None, str]] = []
        for kind, items in IMPORT.findall(text):
            for item in items.split(","):
                item = item.strip()
                if "=" in item:
                    face, module = item.split("=", 1)
                elif item.startswith("*"):
                    face, module = None, item[1:]
                else:
                    face = module = item
                if not MODULE.fullmatch(module) or (face is not None and not FACE.fullmatch(face)):
                    raise ValueError(f"Unsupported Clay import {item!r} in {source}")
                dependency = visit(("lib/" if kind == "+" else "sur/") + module + ".hoon")
                dependencies.append((face, dependency))
        # Preserve line numbers in compiler diagnostics when removing import declarations.
        body = IMPORT.sub(lambda match: "\n" * match.group(0).count("\n"), text)
        if re.search(r"^/[^/\s]", body, re.MULTILINE):
            raise ValueError(f"Unsupported Clay directive in {source}")
        subject = "base"
        for face, dependency in reversed(dependencies):
            label = "~" if face is None else "`%" + face
            subject = f"(join {dependency} {label} {subject})"
        # A cord encoded as a hex atom retains the source bytes without quote interpolation.
        cord = source_cord(body.encode("utf-8"))
        name = "dep-" + str(len(nodes))
        names[relative] = name
        nodes.append(f"=/  {name}\n  (slap {subject} (parse /{relative.removesuffix('.hoon')} {cord}))")
        visiting.remove(relative)
        sources.append({"path": str(source), "sha256": hashlib.sha256(data).hexdigest()})
        return name

    system_nodes = []
    for layer in ("hoon", "arvo", "lull", "zuse"):
        source = (roots[1] / "sys" / (layer + ".hoon")).resolve()
        data = source.read_bytes()
        system_nodes.append(f"=/  {layer}-src  {source_cord(data)}")
        sources.append({"path": str(source), "sha256": hashlib.sha256(data).hexdigest()})
    result = visit("app/bitwarden.hoon")
    prelude = """=/  base=vase  !>(.)
=/  join
  |=  [dep=vase name=(unit @tas) tail=vase]
  ^-  vase
  [[%cell ?~(name p.dep [%face u.name p.dep]) p.tail] [q.dep q.tail]]
=/  parse
  |=  [file=path text=@t]
  ^-  hoon
  ~|  file
  [%tssg (scan (trip text) (full (ifix [gay gay] (most gap tall:(vang & file)))))]
"""
    body = prelude + "\n".join(nodes) + f"\n[%compiled zuse (mug p.{result}) (mug q.{result})]\n"
    script = "\n".join(system_nodes) + f"\n=/  body-src  {source_cord(body.encode('utf-8'))}\n"
    # Upstream lib/pill.hoon +solid's double-compile branch: compile new +ride,
    # then let that compiler construct its own kernel/types and our build core.
    # +7 selects the Hoon compiler gate's context, as the upstream bootstrap does.
    # No Arvo lifecycle gate, Gall arm, or event is invoked.
    script += """=/  compiler-formula
  q:(~(mint ut %noun) %noun (rain /sys/hoon hoon-src))
=/  whole-src
  (rap 3 ~['=>  ' hoon-src '\\0a=>  +7  =>  ' arvo-src '\\0a=>  ' lull-src '\\0a=>  ' zuse-src '\\0a' body-src])
=/  whole-formula
  =<  +
  .*  [%noun whole-src]
  [%8 compiler-formula [%9 2 %10 [6 %0 3] [%0 2]]]
;;([@tas @ud @ud @ud] .*(~ whole-formula))
"""
    return script, sources


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arvo-root", required=True, type=Path, help="Real Urbit pkg/arvo source directory")
    parser.add_argument("--vere", help="Vere executable; defaults to urbit or vere on PATH")
    parser.add_argument("--output-dir", type=Path, help="Build receipt/log directory (default: new temporary directory)")
    args = parser.parse_args()
    desk = Path(__file__).resolve().parents[1] / "desk"
    vere = args.vere or shutil.which("urbit") or shutil.which("vere")
    if not vere:
        parser.error("Vere is required; pass --vere /path/to/vere")
    binary = Path(vere).expanduser().resolve()
    if not binary.is_file():
        parser.error(f"Vere executable does not exist: {binary}")
    kelvin_file = desk / "sys.kelvin"
    kelvin_match = re.fullmatch(r"\[%zuse (\d+)\]\s*", kelvin_file.read_text())
    if not kelvin_match:
        parser.error("Unsupported desk/sys.kelvin format")
    expected_kelvin = int(kelvin_match.group(1))
    script, sources = compile_source(desk, args.arvo_root)
    sources.append({"path": str(kelvin_file), "sha256": digest(kelvin_file)})
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="bitwarden-compile-"))
    output.mkdir(parents=True, exist_ok=True)
    request = output / "compile.hoon"
    request.write_text(script)
    command = [str(binary), "eval"]
    stdout_path, stderr_path = output / "stdout.log", output / "stderr.log"
    print(f"Compiling production sources; logs: {stdout_path} and {stderr_path}", flush=True)
    with stdout_path.open("w") as out, stderr_path.open("w") as err:
        result = subprocess.run(command, input=script, text=True, stdout=out, stderr=err, cwd=output, check=False)
    stdout = ANSI.sub("", stdout_path.read_text(errors="replace"))
    stderr = ANSI.sub("", stderr_path.read_text(errors="replace"))
    stdout_path.write_text(stdout)
    stderr_path.write_text(stderr)
    marker = re.search(r"\[%compiled %?(\d+) ([\d.]+) ([\d.]+)\]", stdout)
    unchanged = all(digest(Path(item["path"])) == item["sha256"] for item in sources)
    success = result.returncode == 0 and marker is not None and int(marker[1]) == expected_kelvin and unchanged
    receipt = {
        "compiled": success,
        "validation": "production source compilation only; no agent events or test inputs",
        "environment": "upstream double-compilation of actual Hoon, Arvo, Lull and Zuse sources before the desk",
        "command": command,
        "compiler_sha256": digest(binary),
        "adapter_sha256": digest(Path(__file__).resolve()),
        "compiler_input_sha256": digest(request),
        "expected_zuse": expected_kelvin,
        "actual_zuse": int(marker[1]) if marker else None,
        "source_hashes_unchanged": unchanged,
        "sources": sources,
        "returncode": result.returncode,
        "stdout": str(output / "stdout.log"),
        "stderr": str(output / "stderr.log"),
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"{'Compiled' if success else 'Compilation failed'}: {output / 'receipt.json'}")
    if not success:
        print(stdout)
        print(stderr)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
