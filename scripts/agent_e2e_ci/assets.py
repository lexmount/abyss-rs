"""Safe materialization of Codex-generated text and raster fixtures."""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from .model import ImageSpec, Scenario


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class FixtureManifest:
    """Hashes and sizes supplied to the semantic judge as immutable evidence."""

    files: tuple[dict[str, object], ...]
    image: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        return {"files": list(self.files), "image": self.image}


class FixtureWriter:
    """Creates one scenario in an already isolated runtime directory."""

    def materialize(self, scenario: Scenario, workspace: Path) -> FixtureManifest:
        workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
        file_manifests: list[dict[str, object]] = []
        for fixture in scenario.files:
            path = workspace.joinpath(*fixture.path.split("/"))
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            content = fixture.content.encode("utf-8")
            path.write_bytes(content)
            file_manifests.append(
                {
                    "path": fixture.path,
                    "byte_size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )

        image_path = workspace / "input.png"
        image_bytes = PngEncoder().encode(scenario.image)
        image_path.write_bytes(image_bytes)
        image_manifest: dict[str, object] = {
            "path": image_path.name,
            "media_type": "image/png",
            "width": scenario.image.width,
            "height": scenario.image.height,
            "byte_size": len(image_bytes),
            "sha256": hashlib.sha256(image_bytes).hexdigest(),
            "pattern": scenario.image.pattern,
            "palette": list(scenario.image.palette),
        }
        return FixtureManifest(files=tuple(file_manifests), image=image_manifest)


class PngEncoder:
    """Encodes small deterministic RGB images without third-party dependencies."""

    def encode(self, spec: ImageSpec) -> bytes:
        colors = tuple(self._rgb(color) for color in spec.palette)
        rows = bytearray()
        for y in range(spec.height):
            rows.append(0)
            for x in range(spec.width):
                rows.extend(self._pixel(spec, colors, x, y))
        header = struct.pack(
            ">IIBBBBB",
            spec.width,
            spec.height,
            8,
            2,
            0,
            0,
            0,
        )
        return b"".join(
            (
                PNG_SIGNATURE,
                self._chunk(b"IHDR", header),
                self._chunk(b"IDAT", zlib.compress(bytes(rows), level=9)),
                self._chunk(b"IEND", b""),
            )
        )

    @staticmethod
    def _rgb(color: str) -> bytes:
        return bytes.fromhex(color[1:])

    @staticmethod
    def _chunk(kind: bytes, payload: bytes) -> bytes:
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))

    @staticmethod
    def _pixel(
        spec: ImageSpec,
        colors: tuple[bytes, ...],
        x: int,
        y: int,
    ) -> bytes:
        if spec.pattern == "checkerboard":
            tile = max(4, min(spec.width, spec.height) // 8)
            return colors[((x // tile) + (y // tile)) % len(colors)]
        if spec.pattern == "horizontal_stripes":
            stripe = max(4, spec.height // (len(colors) * 2))
            return colors[(y // stripe) % len(colors)]
        if spec.pattern == "vertical_stripes":
            stripe = max(4, spec.width // (len(colors) * 2))
            return colors[(x // stripe) % len(colors)]
        quadrant = (2 if y >= spec.height // 2 else 0) + (1 if x >= spec.width // 2 else 0)
        return colors[quadrant % len(colors)]
