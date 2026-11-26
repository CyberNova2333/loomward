# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Multimodal packet verification, magic-byte inspection, SVG sanitization, and fail-closed optional decoder probing."""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


class MediaValidationError(ValueError):
    """Raised when a media payload is malformed, oversized, unsafe, or unverified."""

    def __init__(self, message: str, *, rule_id: str = "MODERATION-MEDIA-INVALID", fail_closed: bool = True):
        super().__init__(message)
        self.rule_id = rule_id
        self.fail_closed = fail_closed


@dataclass
class SanitizedPacket:
    modality: str
    ref_kind: str
    mime_type: Optional[str] = None
    inline_text: str = ""
    raw_bytes: Optional[bytes] = None
    extracted_text: str = ""
    source_index: Optional[int] = None


def probe_optional_decoders() -> Dict[str, bool]:
    caps = {"pillow": False, "av": False, "faster_whisper": False, "rapidocr": False}
    for mod_name, cap_key in (
        ("PIL", "pillow"),
        ("av", "av"),
        ("faster_whisper", "faster_whisper"),
        ("rapidocr_onnxruntime", "rapidocr"),
    ):
        try:
            __import__(mod_name)
            caps[cap_key] = True
        except Exception:
            caps[cap_key] = False
    return caps


def _decode_inline_bytes(inline_data: str, max_bytes: int) -> bytes:
    cleaned = inline_data.strip()
    if cleaned.startswith("data:"):
        comma = cleaned.find(",")
        if comma < 0:
            raise MediaValidationError("Malformed data: URL media payload.")
        cleaned = cleaned[comma + 1 :]
    if len(cleaned) > ((max_bytes * 4) // 3 + 64):
        raise MediaValidationError("Media base64 payload exceeds byte limit.", rule_id="MODERATION-MEDIA-SIZE-LIMIT")
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MediaValidationError("Invalid base64 encoding in media payload.", rule_id="MODERATION-MEDIA-BASE64") from exc
    if len(raw) > max_bytes:
        raise MediaValidationError("Decoded media payload exceeds byte limit.", rule_id="MODERATION-MEDIA-SIZE-LIMIT")
    return raw


def _read_workspace_media_file(raw_path: str, workspace_roots: List[str], max_bytes: int) -> bytes:
    if not workspace_roots:
        raise MediaValidationError("Workspace media inspection disabled without verified workspaceRoots.", rule_id="MODERATION-MEDIA-ROOT-DENIED")
    candidate = os.path.abspath(raw_path)
    allowed = False
    for root in workspace_roots:
        abs_root = os.path.realpath(root)
        real_candidate = os.path.realpath(candidate)
        if real_candidate == abs_root or real_candidate.startswith(abs_root + os.sep):
            allowed = True
            candidate = real_candidate
            break
    if not allowed:
        raise MediaValidationError("Workspace media path escaped authorized workspace roots.", rule_id="MODERATION-MEDIA-PATH-ESCAPE")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise MediaValidationError(f"Failed to open workspace media file safely: {exc}", rule_id="MODERATION-MEDIA-OPEN") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise MediaValidationError("Workspace media target must be a regular single-link file.", rule_id="MODERATION-MEDIA-NOT-REG")
        if st.st_size > max_bytes:
            raise MediaValidationError("Workspace media file exceeds maximum size limit.", rule_id="MODERATION-MEDIA-SIZE-LIMIT")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise MediaValidationError("Workspace media file exceeded byte budget.", rule_id="MODERATION-MEDIA-SIZE-LIMIT")
        return data
    finally:
        os.close(fd)


def _check_svg_safe(raw: bytes) -> str:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise MediaValidationError("SVG DOCTYPE/ENTITY declarations are forbidden.", rule_id="MODERATION-SVG-XXE")
    text = raw.decode("utf-8", errors="replace")
    lower = text.lower()
    if "<script" in lower or re.search(r"\bon[a-z]+\s*=", lower) or "javascript:" in lower:
        raise MediaValidationError("SVG contains active script or event handler payload.", rule_id="MODERATION-SVG-ACTIVE")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise MediaValidationError("Malformed SVG XML payload.", rule_id="MODERATION-SVG-MALFORMED") from exc
    extracted_parts = []
    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower()
        if tag in ("script", "foreignobject", "iframe"):
            raise MediaValidationError(f"Forbidden SVG tag <{tag}> detected.", rule_id="MODERATION-SVG-FORBIDDEN-TAG")
        for attr_val in elem.attrib.values():
            if isinstance(attr_val, str) and re.search(r"https?://", attr_val, re.IGNORECASE):
                raise MediaValidationError("External href URL inside SVG is forbidden.", rule_id="MODERATION-SVG-EXTERNAL-REF")
        if elem.text and elem.text.strip():
            extracted_parts.append(elem.text.strip())
    return " ".join(extracted_parts)


def _inspect_image_magic_and_dims(raw: bytes, mime_type: Optional[str], max_pixels: int, caps: Dict[str, bool], allow_remote_cloud: bool) -> None:
    if len(raw) < 8:
        raise MediaValidationError("Image payload too small to carry valid header.", rule_id="MODERATION-IMAGE-HEADER")
    is_png = raw.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = raw.startswith(b"\xff\xd8\xff")
    is_gif = raw.startswith(b"GIF87a") or raw.startswith(b"GIF89a")
    is_webp = raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"
    if not (is_png or is_jpeg or is_gif or is_webp):
        raise MediaValidationError("Image bytes failed magic-header verification.", rule_id="MODERATION-IMAGE-MAGIC")

    if is_png and len(raw) >= 24:
        w, h = struct.unpack(">II", raw[16:24])
        if w <= 0 or h <= 0 or (w * h) > max_pixels:
            raise MediaValidationError("PNG image dimensions exceed safe pixel budget.", rule_id="MODERATION-IMAGE-PIXELS")

    if not caps["pillow"] and not allow_remote_cloud:
        raise MediaValidationError(
            "Local image decoder (Pillow) is not installed; local image moderation fails closed (pure text/cloud remains unaffected).",
            rule_id="MODALITY-DEPENDENCY-MISSING",
            fail_closed=True,
        )


def _inspect_audio_or_video_bytes(modality: str, raw: bytes, caps: Dict[str, bool], allow_remote_cloud: bool) -> None:
    if len(raw) < 12:
        raise MediaValidationError(f"{modality.title()} payload too small to carry container header.", rule_id=f"MODERATION-{modality.upper()}-HEADER")
    if modality == "audio":
        valid = (raw[:4] == b"RIFF" and raw[8:12] == b"WAVE") or raw.startswith(b"ID3") or raw[:2] in (b"\xff\xfb", b"\xff\xf3") or raw.startswith(b"OggS") or raw.startswith(b"fLaC")
    else:
        valid = raw[4:8] == b"ftyp" or raw.startswith(b"\x1a\x45\xdf\xa3")
    if not valid:
        raise MediaValidationError(f"{modality.title()} container failed magic-header check.", rule_id=f"MODERATION-{modality.upper()}-MAGIC")

    if not allow_remote_cloud and not (caps["av"] and (modality != "audio" or caps["faster_whisper"])):
        raise MediaValidationError(
            f"Local {modality} decoder dependencies (PyAV/Whisper) are missing; failing closed for {modality}.",
            rule_id="MODALITY-DEPENDENCY-MISSING",
            fail_closed=True,
        )


def sanitize_modality_packets(
    raw_packets: Any,
    *,
    media_cfg: Dict[str, Any],
    workspace_roots: List[str],
    allow_remote_cloud: bool,
) -> List[SanitizedPacket]:
    if not raw_packets:
        return []
    caps = probe_optional_decoders()
    max_img_bytes = int(media_cfg.get("maxImageBytes", 20 * 1024 * 1024))
    max_img_pixels = int(media_cfg.get("maxImagePixels", 4096 * 4096))
    scan_ws = bool(media_cfg.get("scanWorkspacePaths", False))

    sanitized: List[SanitizedPacket] = []
    for idx, pkt in enumerate(raw_packets):
        if not isinstance(pkt, dict):
            raise MediaValidationError(f"Invalid modality packet at index {idx}.")
        modality = str(pkt.get("modality") or "")
        ref_kind = str(pkt.get("refKind") or "inline")
        mime_type = pkt.get("mimeType")
        src_idx = pkt.get("sourceIndex")

        if modality == "text":
            sanitized.append(SanitizedPacket(
                modality="text",
                ref_kind=ref_kind,
                inline_text=str(pkt.get("inlineData") or ""),
                source_index=src_idx if isinstance(src_idx, int) else None,
            ))
            continue

        if ref_kind == "workspace-ref":
            if not scan_ws:
                raise MediaValidationError("Workspace media path inspection requires media.scanWorkspacePaths=true.", rule_id="MODERATION-MEDIA-WS-DISABLED")
            ws_path = str(pkt.get("workspacePath") or "")
            raw_bytes = _read_workspace_media_file(ws_path, workspace_roots, max_img_bytes)
        elif ref_kind == "inline":
            inline_data = pkt.get("inlineData")
            if not isinstance(inline_data, str) or not inline_data.strip():
                raise MediaValidationError(f"Empty {modality} inline payload at index {idx}.")
            raw_bytes = _decode_inline_bytes(inline_data, max_img_bytes)
        else:
            raise MediaValidationError(f"Unsupported modality refKind: {ref_kind}")

        extracted_text = ""
        if modality == "image":
            if (mime_type or "").lower() == "image/svg+xml" or raw_bytes.lstrip().startswith(b"<"):
                extracted_text = _check_svg_safe(raw_bytes)
            else:
                _inspect_image_magic_and_dims(raw_bytes, mime_type, max_img_pixels, caps, allow_remote_cloud)
        elif modality in ("audio", "video"):
            _inspect_audio_or_video_bytes(modality, raw_bytes, caps, allow_remote_cloud)
        elif modality == "document":
            if not raw_bytes.startswith(b"%PDF-") and not raw_bytes.lstrip().startswith(b"{"):
                extracted_text = raw_bytes[:16384].decode("utf-8", errors="replace")

        sanitized.append(SanitizedPacket(
            modality=modality,
            ref_kind=ref_kind,
            mime_type=mime_type if isinstance(mime_type, str) else None,
            raw_bytes=raw_bytes,
            extracted_text=extracted_text,
            source_index=src_idx if isinstance(src_idx, int) else None,
        ))
    return sanitized
