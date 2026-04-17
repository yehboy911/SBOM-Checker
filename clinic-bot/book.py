#!/usr/bin/env python3
"""
clinic-bot/book.py
自動掛號機器人 — 超越復健診所 王薏茜醫師

排程：
  - 20:30 每天：檢查隔日王薏茜剩餘名額，有則立即掛號
  - 00:00 每天：檢查三週後王薏茜新開名額，有則立即掛號
  - 排除日期：config.EXCLUDE_DATES（預設含 2026-05-01）

用法：
  python3 book.py --mode evening    # 20:30 模式（隔日剩餘名額）
  python3 book.py --mode midnight   # 00:00 模式（三週後新名額）
  python3 book.py --dry-run         # 不實際掛號，只印出找到的名額
"""

import argparse
import datetime
import json
import logging
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar

from config import (
    LOGIN_ID, LOGIN_BIRTHDAY, TARGET_DOCTOR,
    EXCLUDE_DATES, BASE_URL
)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("clinic-bot.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)


# ── HTTP Session (cookie-aware) ───────────────────────────────────────────────
def make_session() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0.0.0 Safari/537.36"),
        ("Accept-Language", "zh-TW,zh;q=0.9"),
    ]
    return opener


def fetch(session: urllib.request.OpenerDirector, url: str,
          post_data: dict | None = None, timeout: int = 30) -> str:
    if post_data:
        data = urllib.parse.urlencode(post_data).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
    else:
        req = urllib.request.Request(url)
    with session.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ── Login ─────────────────────────────────────────────────────────────────────
def get_tpl_token(session: urllib.request.OpenerDirector) -> str:
    """Load login page and extract hidden tpl token."""
    html = fetch(session, f"{BASE_URL}/appointment/login.php")
    import re
    m = re.search(r'name="tpl"\s+value="([^"]+)"', html)
    if not m:
        raise RuntimeError("Cannot find tpl token on login page")
    return m.group(1)


def login(session: urllib.request.OpenerDirector) -> bool:
    tpl = get_tpl_token(session)
    post = {
        "tpl": tpl,
        "doctor_id": "",
        "useno": LOGIN_ID,
        "pwd": LOGIN_BIRTHDAY,
    }
    html = fetch(session, f"{BASE_URL}/appointment/pro_edit.php", post_data=post)
    # Success if we're redirected to index or html contains 登入成功
    success = "登入成功" in html or "會員登出" in html or "掛號查詢" in html
    if success:
        log.info("登入成功")
    else:
        log.error("登入失敗，請檢查身分證/生日格式")
    return success


# ── Schedule Parsing ──────────────────────────────────────────────────────────
def week_monday(date: datetime.date) -> datetime.date:
    """Return Monday of the week containing date."""
    return date - datetime.timedelta(days=date.weekday())


def parse_schedule_page(session: urllib.request.OpenerDirector,
                         monday: datetime.date) -> list[dict]:
    """
    Fetch schedule page for the week starting on monday.
    Returns list of bookable slots for TARGET_DOCTOR:
      { "date": "2026-04-21", "link": "https://...onlineappointment.php?id=...&get_time=..." }

    Strategy: parse <table> → <tr> → <td> structure, mapping column index
    to dates extracted from <th> headers.
    Cells with class="active" and a booking link are bookable.
    """
    import re

    act = monday.strftime("%Y-%m-%d")
    html = fetch(session, f"{BASE_URL}/index.php?act={act}")

    date_re = re.compile(r'(\d{4}-\d{2}-\d{2})')
    th_re = re.compile(r'<th[^>]*>(.*?)</th>', re.DOTALL)
    tr_re = re.compile(r'<tr[^>]*>(.*?)</tr>', re.DOTALL)
    td_re = re.compile(r'<td([^>]*)>(.*?)</td>', re.DOTALL)
    link_re = re.compile(r'href="(appointment/onlineappointment\.php\?[^"]+)"')

    # ── Extract per-table header dates ──────────────────────────────────────
    # There are two schedule tables on the page (第一診, 第二診).
    # Each table has its own <thead> with <th> date headers.
    # We process each table independently.

    table_re = re.compile(r'<table[^>]*>(.*?)</table>', re.DOTALL)
    slots: list[dict] = []

    for table_match in table_re.finditer(html):
        table_html = table_match.group(1)

        # Extract header dates from <th> in this table
        header_dates: list[str] = []
        for th_m in th_re.finditer(table_html):
            th_text = re.sub(r'<[^>]+>', '', th_m.group(1))
            d = date_re.search(th_text)
            if d:
                header_dates.append(d.group(1))

        if not header_dates:
            continue  # skip tables without date headers (e.g. nav tables)

        # ── Walk each <tr> → each <td> ──────────────────────────────────
        for tr_m in tr_re.finditer(table_html):
            row_html = tr_m.group(1)
            tds = list(td_re.finditer(row_html))
            # tds[0] is the time-label column; tds[1..N] are Mon-Sat columns
            for col_offset, td_m in enumerate(tds[1:], start=0):
                td_attrs = td_m.group(1)
                td_inner = td_m.group(2)

                if 'class="active"' not in td_attrs:
                    continue
                if TARGET_DOCTOR not in td_inner:
                    continue

                link_m = link_re.search(td_inner)
                if not link_m:
                    continue

                full_url = f"{BASE_URL}/appointment/{link_m.group(1).split('appointment/')[-1]}"
                # Safer: just prepend base
                full_url = f"{BASE_URL}/{link_m.group(1)}"

                if col_offset < len(header_dates):
                    slot_date = header_dates[col_offset]
                else:
                    slot_date = "unknown"

                log.info(f"找到名額：{slot_date} {TARGET_DOCTOR} → {link_m.group(1)}")
                slots.append({"date": slot_date, "link": full_url})

    return slots


def is_excluded(date_str: str) -> bool:
    return date_str in EXCLUDE_DATES


# ── Booking ───────────────────────────────────────────────────────────────────
def book_slot(session: urllib.request.OpenerDirector,
              slot: dict, dry_run: bool = False) -> bool:
    date_str = slot["date"]
    link = slot["link"]

    if is_excluded(date_str):
        log.info(f"跳過排除日期：{date_str}")
        return False

    if dry_run:
        log.info(f"[DRY-RUN] 模擬掛號：{date_str} → {link}")
        return True

    log.info(f"嘗試掛號：{date_str} → {link}")
    try:
        html = fetch(session, link)
        if "預約成功" in html or "掛號號碼" in html:
            log.info(f"✅ 掛號成功！日期：{date_str}")
            return True
        elif "預約名額已滿" in html:
            log.warning(f"名額剛被搶走：{date_str}")
            return False
        else:
            # Try to extract number from response
            import re
            m = re.search(r'號碼為(\d+)', html)
            if m:
                log.info(f"✅ 掛號成功！日期：{date_str}，號碼：{m.group(1)}")
                return True
            log.warning(f"預約結果不明，請手動確認：{date_str}")
            log.debug(f"Response (200 chars): {html[:200]}")
            return False
    except Exception as e:
        log.error(f"掛號失敗：{e}")
        return False


# ── Mode: Evening (20:30) — check tomorrow ────────────────────────────────────
def run_evening(session: urllib.request.OpenerDirector, dry_run: bool) -> None:
    """Check next day's released slots."""
    tomorrow = datetime.date.today() + datetime.timedelta(days=1)
    log.info(f"[evening] 檢查隔日剩餘名額：{tomorrow}")

    # Wang Yi-Qian works Tue-Fri
    if tomorrow.weekday() not in (1, 2, 3, 4):  # 1=Tue, 2=Wed, 3=Thu, 4=Fri
        log.info(f"隔日 {tomorrow} 不是王薏茜看診日（週二-週五），略過")
        return

    monday = week_monday(tomorrow)
    slots = parse_schedule_page(session, monday)
    tomorrow_str = tomorrow.strftime("%Y-%m-%d")
    tomorrow_slots = [s for s in slots if s["date"] == tomorrow_str]

    if not tomorrow_slots:
        log.info(f"隔日 {tomorrow_str} 無王薏茜剩餘名額")
        return

    for slot in tomorrow_slots:
        if book_slot(session, slot, dry_run=dry_run):
            log.info("掛號完成，結束")
            return


# ── Mode: Midnight (00:00) — check 3 weeks out ───────────────────────────────
def run_midnight(session: urllib.request.OpenerDirector, dry_run: bool) -> None:
    """Check newly released slots 3 weeks from now."""
    target_date = datetime.date.today() + datetime.timedelta(weeks=3)
    log.info(f"[midnight] 檢查三週後新開名額：{target_date}")

    monday = week_monday(target_date)
    # Check that whole week for Wang Yi-Qian slots (Tue-Fri)
    slots = parse_schedule_page(session, monday)

    # Filter to the specific target date and Tue-Fri
    target_str = target_date.strftime("%Y-%m-%d")
    target_slots = [
        s for s in slots
        if s["date"] == target_str
        and datetime.date.fromisoformat(s["date"]).weekday() in (1, 2, 3, 4)
    ]

    if not target_slots:
        log.info(f"三週後 {target_str} 無王薏茜可預約名額")
        return

    for slot in target_slots:
        if book_slot(session, slot, dry_run=dry_run):
            log.info("掛號完成，結束")
            return


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="超越復健診所 王薏茜醫師自動掛號")
    parser.add_argument(
        "--mode", choices=["evening", "midnight"], required=True,
        help="evening=20:30隔日剩餘名額 / midnight=00:00三週後新名額"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="不實際掛號，只印出找到的名額")
    args = parser.parse_args()

    session = make_session()

    if not login(session):
        log.error("無法登入，程式結束")
        sys.exit(1)

    if args.mode == "evening":
        run_evening(session, dry_run=args.dry_run)
    elif args.mode == "midnight":
        run_midnight(session, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
