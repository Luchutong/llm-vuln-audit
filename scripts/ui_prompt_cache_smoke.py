#!/usr/bin/env python3
"""Cache statistics in running/finished conversations. Every API request is mocked."""
import argparse
import os
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from ui_fixtures import finding, run, sources_api
from ui_smoke import Checks, goto, install_activity_stream, no_overflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base')
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    api, checks = sources_api(), Checks()
    cases = [('complete', 'completed', 3, 3, .75, '75.0%'),
             ('partial', 'running', 3, 2, .5, '50.0%（部分数据）'),
             ('zero', 'completed', 3, 3, 0, '0.0%'),
             ('unknown', 'completed', 3, 0, None, '暂无缓存计数'),
             ('legacy', 'completed', 0, 0, None, '暂无数据')]
    for name, status, total, reported, ratio, _label in cases:
        rid = f'cache-{name}'
        item = run(rid, status)
        if name != 'legacy':
            row = dict(usage_records=total, reported_records=reported, cache_hit_ratio=ratio,
                       cache_read_tokens=round(1000 * ratio) if ratio is not None else None,
                       reported_input_tokens=1000 if reported else 0, cache_write_tokens=None)
            item['usage']['prompt_cache'] = dict(row, by_role={'worker': row})
        api.runs[rid], api.findings[rid] = item, finding(rid)
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
        for width in (1440, 390):
            page = browser.new_page(viewport=dict(width=width, height=1000))
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.route('**/api/**', api.handle)
            install_activity_stream(page)
            for name, _status, total, reported, _ratio, label in cases:
                goto(page, args.base, f'#run/cache-{name}')
                section = page.get_by_role('region', name='API 输入缓存', exact=True)
                expect(section).to_contain_text(label)
                section.get_by_role('button').click()
                expect(section).to_contain_text(f'{reported}/{total} 条用量记录')
                expect(section).to_contain_text('提示缓存仍占用模型请求额度')
                if name != 'legacy':
                    expect(section.get_by_role('cell', name='源码 Worker', exact=True)).to_be_visible()
                no_overflow(page, f'{width}px {name}', checks)
                if args.screenshots and name in ('partial', 'unknown'):
                    page.screenshot(path=str(args.screenshots / f'{name}-{width}.png'), full_page=True)
            assert not errors, errors
            page.close()
        browser.close()
    print(f'PASS: {checks.count} cache presentation checks; no live API/model traffic')


if __name__ == '__main__':
    main()
