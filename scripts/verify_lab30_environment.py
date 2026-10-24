#!/usr/bin/env python3
"""Exercise a disposable Lab30 runner without a model or audit database.

Run inside poc-runner with POC_RUNNER_TOKEN already in the environment, or set
POC_RUNNER_URL and POC_RUNNER_TOKEN explicitly. This creates fixture-only POC jobs.
"""
from __future__ import annotations

import json
import os
import textwrap
import uuid
import urllib.error
import urllib.parse
import urllib.request


def main():
    base = os.environ.get('POC_RUNNER_URL', 'http://127.0.0.1:8080').rstrip('/')
    token = os.environ.get('POC_RUNNER_TOKEN', '')
    if not token: raise SystemExit('POC_RUNNER_TOKEN is required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    checks = 0

    def request(path, body=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, headers={
            'Authorization':'Bearer ' + token, 'Content-Type':'application/json'}, method=method)
        with opener.open(req, timeout=120) as response:
            return json.load(response)

    def check(condition, message):
        nonlocal checks
        if not condition: raise AssertionError(message)
        checks += 1
        print('PASS', message, flush=True)

    health = request('/healthz')
    check(health['ok'] and health['supported_targets'] == ['lab30'], 'runner advertises Lab30 only')
    try:
        request('/v1/targets/dvwa/prepare', {})
    except urllib.error.HTTPError as exc:
        check(exc.code == 404, 'removed target is refused')
    else: raise AssertionError('removed target accepted')
    context_id = uuid.uuid4().hex
    created = request('/v1/verification-contexts', {'target':'lab30','run_id':'environment-check',
                      'finding_id':'fixture-session','context_id':context_id})
    check(created['context_id'] == context_id, 'verification acquires an exclusive context')

    def scoped(path, body=None, identity='alice'):
        payload = {**(body or {}), 'context_id':context_id, 'identity':identity}
        return request(path, payload)

    try:
        prepared = scoped('/v1/targets/lab30/prepare')
        check(prepared['ok'] and prepared['authenticated'] and prepared['user'] == os.environ.get('LAB30_USER','alice'), 'member authentication succeeds')
        member = scoped('/v1/http', {'path':'/orders/index.php'})
        check(member['status'] == 200, 'HTTP observation reuses the member session')
        redirect = scoped('/v1/http', {'path':'/auth/continue.php?next=%2F%2Fexample.invalid'})
        check(redirect['status'] == 302 and redirect['headers']['location'] == '//example.invalid', 'HTTP reports the first redirect without following it')
        status = request('/v1/targets/lab30/status?context_id=' + context_id + '&identity=alice')
        check(status['ok'] and status['authenticated'], 'target status confirms the live member session')
        script = '''
    import os, urllib.request, urllib.parse, http.cookiejar
    base=os.environ['LAB30_URL'].rstrip('/')
    jar=http.cookiejar.CookieJar()
    client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    client.open(base+'/auth/login.php',timeout=10).read()
    client.open(base+'/auth/login.php',timeout=10,data=urllib.parse.urlencode({
        'username':os.environ['LAB30_USER'],'password':os.environ['LAB30_PASSWORD']}).encode()).read()
    response=client.open(base+'/orders/index.php',timeout=10)
    assert response.status==200 and '/auth/login.php' not in response.url
    assert not any(key.startswith('DVWA_') for key in os.environ)
    print('LAB30_SCRIPT_MEMBER_OK')
    '''
        job = scoped('/v1/jobs', {'language':'python','script':textwrap.dedent(script)})
        check(job['exit_code'] == 0 and 'LAB30_SCRIPT_MEMBER_OK' in job['stdout'], 'isolated script receives Lab30 configuration and establishes its own session')
        if health['capabilities']['php']:
            php = scoped('/v1/jobs', {'language':'php','script':"<?php if (!getenv('LAB30_URL') || !getenv('LAB30_USER')) exit(2); echo 'LAB30_PHP_OK';"})
            check(php['exit_code'] == 0 and 'LAB30_PHP_OK' in php['stdout'], 'PHP jobs receive the Lab30 environment')
        if health['capabilities']['browser']:
            page = scoped('/v1/browser/check', {'path':'/orders/index.php','script':"!document.querySelector('input[name=password]')"})
            check(page.get('job_id') and page.get('evaluated') == 'True' and '/orders/' in page['url'], 'Chromium reuses the authenticated member session')
            normal = scoped('/v1/browser/check', {'path':'/catalog/greeting.php?name=lab30-normal'})
            marker = 'LAB30_BROWSER_CHECK'
            attack = scoped('/v1/browser/check', {'path':'/catalog/greeting.php?name=' + urllib.parse.quote("<script>alert('" + marker + "')</script>",safe='')})
            check(not normal['dialogs'] and marker in attack['dialogs'], 'browser distinguishes ordinary reflection from actual script execution')
            check(bool(attack['artifacts']), 'browser execution persists screenshot evidence')
        guest = scoped('/v1/http', {'path':'/account/me.php'}, identity='guest')
        check(guest['status'] == 401, 'guest cookie jar is independent from member')
        operator = scoped('/v1/http', {'path':'/account/me.php'}, identity='operator')
        check(operator['status'] == 200 and json.loads(operator['body'])['role'] == 'operator', 'configured operator authenticates without credential guessing')
        try:
            request('/v1/verification-contexts', {'target':'lab30','run_id':'another-run','finding_id':'another-finding'})
        except urllib.error.HTTPError as exc:
            check(exc.code == 409, 'another verification cannot interleave on the target')
        else: raise AssertionError('overlapping verification accepted')
        stable_id = uuid.uuid4().hex
        first = scoped('/v1/jobs', {'job_id':stable_id,'language':'python','script':"print('STABLE_JOB_ONCE')"})
        replay = scoped('/v1/jobs', {'job_id':stable_id,'language':'python','script':"print('STABLE_JOB_ONCE')"})
        check(first['job_id'] == replay['job_id'] and replay['stdout'] == first['stdout'], 'stable job id returns the original job without executing again')
    finally:
        closed = request('/v1/verification-contexts/' + context_id, method='DELETE')
    check(closed['state'] == 'closed', 'context closes and releases the target')
    print(f'PASS {checks} real Lab30 environment checks; no model or audit records', flush=True)


if __name__ == '__main__': main()
