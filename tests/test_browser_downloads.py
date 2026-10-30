"""Real Chromium regression checks for SOC Log Lab's saved browser downloads.

Run with: uv run --with playwright --with pytest python3 -m pytest -q tests/test_browser_downloads.py
Set PLAYWRIGHT_CHROMIUM_EXECUTABLE when Chromium is installed outside Playwright's default cache.
Set SOC_LOG_LAB_URL to override the public target for an approved test environment.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, sync_playwright

APP_URL = os.environ.get("SOC_LOG_LAB_URL")
CHROMIUM_EXECUTABLE = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as playwright:
        options = {"headless": True}
        if CHROMIUM_EXECUTABLE:
            options["executable_path"] = CHROMIUM_EXECUTABLE
        instance = playwright.chromium.launch(**options)
        yield instance
        instance.close()


def _watch_errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(f"pageerror: {error}"))
    page.on(
        "console",
        lambda message: errors.append(f"console: {message.text}")
        if message.type == "error"
        else None,
    )
    page.on(
        "requestfailed",
        lambda request: errors.append(f"requestfailed: {request.url}: {request.failure}")
        if request.failure != "net::ERR_ABORTED"
        else None,
    )
    return errors


def _open_page(browser: Browser, viewport: dict[str, int]):
    assert APP_URL, "set SOC_LOG_LAB_URL to the exact app target before running browser tests"
    context = browser.new_context(viewport=viewport, accept_downloads=True)
    page = context.new_page()
    errors = _watch_errors(page)
    response = page.goto(APP_URL, wait_until="networkidle", timeout=60_000)
    assert response is not None and response.status == 200, f"app response: {response}"
    assert page.get_by_role("heading", name="Small synthetic log drills. Ready in your browser.").is_visible()
    assert page.locator(".cookie-banner").is_visible(), "fresh browser should show the cookie notice"
    return context, page, errors


def _save_download(page: Page, button_id: str, expected_name: str, destination: Path) -> bytes:
    with page.expect_download(timeout=30_000) as download_info:
        page.locator(f"#{button_id}").click()
    download = download_info.value
    assert download.suggested_filename == expected_name
    download.save_as(str(destination))
    assert destination.is_file() and destination.stat().st_size > 0
    return destination.read_bytes()


def test_real_browser_downloads_are_separate_and_cross_referenced(browser: Browser):
    context, page, errors = _open_page(browser, {"width": 1440, "height": 1000})
    temporary_files = tempfile.TemporaryDirectory(prefix="soc-log-lab-downloads-")
    tmp_path = Path(temporary_files.name)
    try:
        seed = page.locator("#seed").input_value()
        assert seed
        analyst_bytes = _save_download(
            page, "download-logs", "soc-log-lab-analyst.jsonl", tmp_path / "analyst.jsonl"
        )
        analyst_text = analyst_bytes.decode("utf-8")
        analyst_rows = [json.loads(line) for line in analyst_text.splitlines()]
        assert len(analyst_rows) == 120
        expected_fields = {
            "timestamp", "host", "process", "message", "severity", "facility",
            "facility_code", "process_id", "source_ip", "record_id",
        }
        assert all(set(row) == expected_fields for row in analyst_rows), "analyst JSONL schema changed"
        string_fields = {"timestamp", "host", "process", "message", "severity", "facility", "process_id", "record_id"}
        for row in analyst_rows:
            assert all(type(row[field]) is str for field in string_fields), "analyst JSONL string field type changed"
            assert type(row["facility_code"]) is int, "analyst JSONL facility_code type changed"
            assert row["source_ip"] is None or type(row["source_ip"]) is str, "analyst JSONL source_ip type changed"
        row_ids = {row["record_id"] for row in analyst_rows}
        assert len(row_ids) == len(analyst_rows)
        assert all(re.fullmatch(r"SYN-[0-9a-f]{32}", row_id) for row_id in row_ids)
        assert seed not in analyst_text, "private trainer seed leaked into analyst JSONL"

        key_bytes = _save_download(
            page, "download-key", "soc-log-lab-answer-key.json", tmp_path / "answer-key.json"
        )
        answer_key = json.loads(key_bytes.decode("utf-8"))
        assert answer_key["seed"] == seed
        assert answer_key["trainingOnly"] is True
        row_by_id = {row["record_id"]: row for row in analyst_rows}
        finding_ids = {finding["id"] for finding in answer_key["findings"]}
        assert finding_ids and all(finding_id not in analyst_text for finding_id in finding_ids), "finding IDs leaked into analyst JSONL"
        referenced_ids = set()
        for finding in answer_key["findings"]:
            evidence_ids = [evidence["recordId"] for evidence in finding["evidence"]]
            assert evidence_ids == finding["rowIds"]
            for evidence in finding["evidence"]:
                assert evidence["recordId"] in row_by_id
                assert evidence["message"] == row_by_id[evidence["recordId"]]["message"]
                referenced_ids.add(evidence["recordId"])
        assert referenced_ids and referenced_ids <= row_ids

        raw_bytes = _save_download(
            page, "download-raw", "soc-log-lab-linux-messages.log", tmp_path / "analyst.log"
        )
        raw_lines = raw_bytes.decode("utf-8").splitlines()
        assert len(raw_lines) == len(analyst_rows)
        for raw_line, row in zip(raw_lines, analyst_rows, strict=True):
            parsed = re.fullmatch(
                r"<\d+>1 \S+ \S+ \S+ \S+ \S+ - (.*) \[training_record_id=(SYN-[0-9a-f]{32})\]",
                raw_line,
            )
            assert parsed is not None, f"raw syslog line does not match the expected record shape: {raw_line}"
            assert parsed.group(1) == row["message"], "raw syslog message differs from its matching JSONL row"
            assert parsed.group(2) == row["record_id"]
        assert seed not in "\n".join(raw_lines)
        assert not errors, "browser errors: " + " | ".join(errors)
    finally:
        try:
            context.close()
        finally:
            temporary_files.cleanup()


def test_fresh_narrow_mobile_generates_without_overflow_or_browser_errors(browser: Browser):
    context, page, errors = _open_page(browser, {"width": 390, "height": 844})
    try:
        layout = page.evaluate(
            """() => ({
              viewport: document.documentElement.clientWidth,
              scroll: document.documentElement.scrollWidth,
              noticeTop: document.querySelector('.cookie-banner').getBoundingClientRect().top,
              noticeBottom: document.querySelector('.cookie-banner').getBoundingClientRect().bottom,
              height: window.innerHeight
            })"""
        )
        assert layout["scroll"] <= layout["viewport"], f"horizontal overflow: {layout}"
        assert 0 <= layout["noticeTop"] < layout["height"]
        assert layout["noticeBottom"] <= layout["height"], f"notice is below first viewport: {layout}"
        page.locator("#total-rows").fill("24")
        assert page.locator("#row-count").inner_text() == "24"
        assert "Preview updated" in page.locator("#status").inner_text()
        assert not errors, "browser errors: " + " | ".join(errors)
    finally:
        context.close()
