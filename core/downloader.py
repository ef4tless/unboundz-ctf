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


class DownloadCancelled(RuntimeError):
    pass


def _check_cancel(ch: Challenge, cancel_event) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise DownloadCancelled(ch.id)
    if not ch.meta_path.is_file():
        raise DownloadCancelled(f"题目已删除: {ch.id}")


def _save_download(ch: Challenge, cancel_event) -> None:
    _check_cancel(ch, cancel_event)
    try:
        ch.save(require_existing=True)
    except FileNotFoundError as exc:
        raise DownloadCancelled(f"题目已删除: {ch.id}") from exc


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


_NESTED_ARCH_SUFFIXES = (
    ".zip", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar",
)
_SKIP_NESTED_NAMES = {"layer.tar"}


def _is_nested_archive_candidate(p: Path) -> bool:
    low = p.name.lower()
    if low in _SKIP_NESTED_NAMES:
        return False
    return low.endswith(_NESTED_ARCH_SUFFIXES)


def _extract_single(path: Path, dest: Path, passwords: list[str]) -> str | None:
    """单层解压 path 到 dest, 返回错误信息或 None。"""
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


def _extract(path: Path, dest: Path, passwords: list[str],
             max_depth: int = 2, cancel_event=None,
             ch: Challenge | None = None) -> str | None:
    """能解则解 (支持最多 max_depth 层套娃压缩包就地展开), 返回错误信息或 None。"""
    if ch is not None:
        _check_cancel(ch, cancel_event)
    seen: set[Path] = {path.resolve()}
    if dest.is_dir():
        for existing in dest.rglob("*"):
            if existing.is_file() and _is_nested_archive_candidate(existing):
                seen.add(existing.resolve())

    err = _extract_single(path, dest, passwords)
    if err:
        return err

    nested_errors: list[str] = []
    for _ in range(max_depth):
        if not dest.is_dir():
            break
        candidates = sorted(
            p for p in dest.rglob("*")
            if p.is_file()
            and _is_nested_archive_candidate(p)
            and p.resolve() not in seen
        )
        if not candidates:
            break
        for cand in candidates:
            if ch is not None:
                _check_cancel(ch, cancel_event)
            seen.add(cand.resolve())
            sub_err = _extract_single(cand, cand.parent, passwords)
            if sub_err:
                nested_errors.append(sub_err)
    return "; ".join(nested_errors) if nested_errors else None


def download_all(ch: Challenge, config: dict, cancel_event=None) -> Challenge:
    """同步下载全部附件并落盘；取消/删题通过 DownloadCancelled 尽快退出。"""
    _check_cancel(ch, cancel_event)
    attach_dir = Path(ch.workdir) / "attachments"
    attach_dir.mkdir(exist_ok=True)
    ch.download_status = "pending"
    ch.download_errors = []
    _save_download(ch, cancel_event)

    headers = dict(_UA)
    cookies = config.get("download_cookies") or ""
    if cookies:
        headers["Cookie"] = cookies
    passwords = config.get("zip_passwords") or []

    failures = 0
    for idx, url in enumerate(ch.attachment_urls):
        _check_cancel(ch, cancel_event)
        try:
            with requests.get(url.strip(), headers=headers, stream=True,
                              timeout=(10, 60)) as resp:
                resp.raise_for_status()
                name = _filename_from_response(resp, url, idx)
                dest = attach_dir / name
                with open(dest, "wb") as f:
                    for chunk in resp.iter_content(1 << 20):
                        _check_cancel(ch, cancel_event)
                        f.write(chunk)
            _check_cancel(ch, cancel_event)
            err = _extract(dest, attach_dir, passwords,
                           cancel_event=cancel_event, ch=ch)
            if err:
                ch.download_errors.append(err)
        except requests.RequestException as e:
            failures += 1
            ch.download_errors.append(f"{url}: {e}")

    _check_cancel(ch, cancel_event)
    if not ch.attachment_urls:
        ch.download_status = "done"
    elif failures == len(ch.attachment_urls):
        ch.download_status = "failed"
    elif failures or ch.download_errors:
        ch.download_status = "partial"
    else:
        ch.download_status = "done"
    if ch.status == "downloading":
        # 不 auto_launch 的题下载完要回到 ready, 否则会一直卡在「下载中」
        ch.status = "ready"
    _save_download(ch, cancel_event)
    return ch
