"""ubz-ctf core: 附件下载与解压。

- 多链接逐个下载到 <workdir>/attachments/
- zip/tar/tar.gz 自动解压到 attachments/ 原位 (带 zip-slip 防护)
- 支持 config 里的 download_cookies (需要登录的平台) 和 zip_passwords
- 结果写回 meta.json: download_status = done/partial/failed, download_errors
"""

from __future__ import annotations

import re
import tarfile
import zipfile
from pathlib import Path

import requests

from .store import Challenge

_UA = {"User-Agent": "ubz-ctf/0.1"}


def sanitize_filename(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]  # 防浏览器带路径
    return re.sub(r"[^A-Za-z0-9._\-一-鿿]+", "_", name).strip("._")


def _filename_from_response(resp: requests.Response, url: str, idx: int) -> str:
    cd = resp.headers.get("Content-Disposition", "")
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', cd)
    if m:
        name = m.group(1)
    else:
        name = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    return sanitize_filename(name) or f"file_{idx}"


def _safe_members_zip(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    out = []
    for info in zf.infolist():
        p = Path(info.filename)
        if p.is_absolute() or ".." in p.parts:
            continue
        out.append(info)
    return out


def _extract(path: Path, dest: Path, passwords: list[str]) -> str | None:
    """能解则解, 返回错误信息或 None。"""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                members = _safe_members_zip(zf)
                try:
                    zf.extractall(dest, members=members)
                except RuntimeError as e:
                    if "password" not in str(e).lower():
                        raise
                    for pwd in passwords:
                        try:
                            zf.extractall(dest, members=members,
                                          pwd=pwd.encode())
                            break
                        except RuntimeError:
                            continue
                    else:
                        return f"{path.name}: 加密 zip, 密码均不对"
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                members = [m for m in tf.getmembers()
                           if not Path(m.name).is_absolute()
                           and ".." not in Path(m.name).parts]
                tf.extractall(dest, members=members, filter="data")
    except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError) as e:
        return f"{path.name}: 解压失败 ({e})"
    return None


def download_all(ch: Challenge, config: dict) -> Challenge:
    """同步下载全部附件, 更新 ch 并落盘。抛不出异常, 错误记在 meta 里。"""
    attach_dir = Path(ch.workdir) / "attachments"
    attach_dir.mkdir(exist_ok=True)
    ch.download_status = "pending"
    ch.download_errors = []
    ch.save()

    headers = dict(_UA)
    cookies = config.get("download_cookies") or ""
    if cookies:
        headers["Cookie"] = cookies
    passwords = config.get("zip_passwords") or []

    failures = 0
    for idx, url in enumerate(ch.attachment_urls):
        try:
            with requests.get(url.strip(), headers=headers, stream=True,
                              timeout=(10, 300)) as resp:
                resp.raise_for_status()
                name = _filename_from_response(resp, url, idx)
                dest = attach_dir / name
                with open(dest, "wb") as f:
                    for chunk in resp.iter_content(1 << 20):
                        f.write(chunk)
            err = _extract(dest, attach_dir, passwords)
            if err:
                ch.download_errors.append(err)
        except requests.RequestException as e:
            failures += 1
            ch.download_errors.append(f"{url}: {e}")

    if not ch.attachment_urls:
        ch.download_status = "done"
    elif failures == len(ch.attachment_urls):
        ch.download_status = "failed"
    elif failures or ch.download_errors:
        ch.download_status = "partial"
    else:
        ch.download_status = "done"
    ch.save()
    return ch
