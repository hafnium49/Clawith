"""File upload API for chat — saves files to agent workspace and extracts text."""

import base64
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Form
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import check_agent_access
from app.core.security import get_current_user
from app.database import get_db
from app.models.user import User
from app.config import get_settings
from app.services import text_extractor

router = APIRouter(prefix="/chat", tags=["chat"])

_settings = get_settings()
WORKSPACE_ROOT = Path(_settings.AGENT_DATA_DIR)

# Supported extensions and their text extraction method
TEXT_EXTENSIONS = {
    ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml",
    ".py", ".js", ".ts", ".html", ".css", ".sql", ".sh", ".log",
    ".ini", ".cfg", ".conf", ".env", ".toml",
}
OFFICE_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
EXTRACTABLE = TEXT_EXTENSIONS | OFFICE_EXTENSIONS

MIME_MAP = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
}


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    agent_id: uuid.UUID = Form(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a file for chat context. Saves to agent workspace/uploads/ and returns extracted text."""
    # Authorization: ensure caller can access this agent
    await check_agent_access(db, current_user, agent_id)

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename")

    # Sanitize filename: strip directory components, reject traversal tricks
    raw = file.filename or ""
    safe_name = os.path.basename(raw).replace("/", "_").replace("\\", "_")
    if "\x00" in safe_name or safe_name in ("", ".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    # Truncate to 200 bytes to stay under typical FS limits
    if len(safe_name.encode("utf-8")) > 200:
        stem, ext = os.path.splitext(safe_name)
        safe_name = stem[:200 - len(ext)].encode("utf-8", "ignore").decode("utf-8", "ignore") + ext

    ext = os.path.splitext(safe_name)[1].lower()

    content = await file.read()

    # Resolve and enforce containment BEFORE creating directories (prevents symlink TOCTOU)
    uploads_dir = (WORKSPACE_ROOT / str(agent_id) / "workspace" / "uploads").resolve()
    save_path_candidate = (uploads_dir / safe_name).resolve()
    if not str(save_path_candidate).startswith(str(uploads_dir) + os.sep):
        raise HTTPException(status_code=400, detail="Invalid path")
    uploads_dir.mkdir(parents=True, exist_ok=True)

    # Collision handling with O_EXCL (avoids exists()+write race)
    stem, suffix = os.path.splitext(safe_name)
    counter = 0
    save_path: Path
    while True:
        candidate = uploads_dir / (safe_name if counter == 0 else f"{stem}_{counter}{suffix}")
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "wb") as f:
                f.write(content)
            save_path = candidate
            break
        except FileExistsError:
            counter += 1
            if counter > 1000:
                raise HTTPException(status_code=500, detail="Upload failed")

    workspace_path = f"workspace/uploads/{save_path.name}"

    # Extract text (only for known formats)
    is_image = ext in IMAGE_EXTENSIONS
    image_data_url = ""
    if is_image:
        # For images: generate base64 data URL for vision models
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail="Image too large (max 10MB)")
        mime = MIME_MAP.get(ext, "image/png")
        b64 = base64.b64encode(content).decode("ascii")
        image_data_url = f"data:{mime};base64,{b64}"
        extracted = f"[图片文件: {safe_name}，需要视觉模型分析]"
    elif ext in TEXT_EXTENSIONS:
        # Plain-text formats: decode in-memory without touching disk tools
        try:
            extracted = content.decode("utf-8", errors="replace")
        except Exception:
            extracted = content.decode("gbk", errors="replace")
    elif ext in OFFICE_EXTENSIONS:
        # Office formats: delegate to the shared safe extractor (bytes + filename)
        extracted_opt = text_extractor.extract_text(content, safe_name)
        if extracted_opt is None:
            extracted = f"[文件已保存，格式 {ext} 暂不支持文本提取，Agent 可通过 read_document 工具读取]"
        else:
            extracted = extracted_opt
    else:
        extracted = f"[文件已保存，格式 {ext} 暂不支持文本提取，Agent 可通过 read_document 工具读取]"

    # Truncate if too long
    if len(extracted) > 6000:
        extracted = extracted[:6000] + "\n\n...[内容已截断，共 " + str(len(extracted)) + " 字]"

    return {
        "filename": safe_name,
        "saved_filename": save_path.name,
        "size": len(content),
        "extracted_text": extracted,
        "workspace_path": workspace_path,
        "is_image": is_image,
        "image_data_url": image_data_url,
    }
