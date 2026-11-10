"""Bounded, idempotent runner context cleanup. Never submits or replays jobs."""
from __future__ import annotations

import asyncio
import time

from .poc_runner import PocRunnerError, PocRunnerUnavailable


def context_state(value, context_id):
    """Only an explicit, correctly bound zero-job acknowledgement grants reuse."""
    if not isinstance(value, dict) or value.get('context_id') != context_id:
        return None
    state = value.get('state')
    if state not in {'open', 'closing', 'closed', 'unresolved'}:
        return None
    if any(type(value.get(key)) is not int or value[key] < 0 for key in ('active', 'pending_jobs')):
        return None
    if state == 'closed' and (value['active'] or value['pending_jobs']):
        return None
    return {key: value[key] for key in ('state', 'active', 'pending_jobs')}


async def confirm_closed(client, context_id, *, timeout=15.0, request_timeout=5.0, interval=.25, request_close=True):
    """Reconcile a lost DELETE ack with GET; transient failures are not busy facts.

    DELETE is safe to repeat for this exact context, including delayed creation.
    A closing/active context keeps its lease. No reset is authorized by a timeout,
    missing counters, an ambiguous response, or failure to read the runner.
    """
    started = time.monotonic()
    deadline = started + max(0., timeout)
    result = dict(context_id=context_id, state='unknown', runner_state=None, active=None,
                  pending_jobs=None, close_attempts=0, status_attempts=0,
                  acknowledged=False, diagnostics=[])
    failures = 0
    last_status = None
    async def request(operation):
        nonlocal failures
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            value = await asyncio.wait_for(operation(), timeout=min(request_timeout, remaining))
            if (operation.__name__ == 'status' and isinstance(value, dict) and value.get('was_unknown')
                    and not result['acknowledged']):
                # A GET 404 cannot fence a delayed create request. Only DELETE
                # acknowledges the runner's cancellation tombstone in that case.
                raise PocRunnerError('unknown context without close acknowledgement')
            parsed = context_state(value, context_id)
            if parsed is None:
                raise PocRunnerError('invalid context acknowledgement')
            failures = 0
            result.update(runner_state=parsed['state'], active=parsed['active'], pending_jobs=parsed['pending_jobs'])
            return parsed
        except (PocRunnerUnavailable, PocRunnerError, TimeoutError) as exc:
            failures += 1
            # No exception message, response body, address or credential is durable.
            category = ('timeout' if isinstance(exc, TimeoutError) else
                        'connection' if isinstance(exc, PocRunnerUnavailable) else 'runner_response')
            status = getattr(exc, 'status_code', None)
            status = status if type(status) is int and 100 <= status <= 599 else None
            result['diagnostics'].append(dict(operation=operation.__name__, category=category, status_code=status))
            result['diagnostics'] = result['diagnostics'][-12:]
            if status in {401, 403}:
                result['authorization_failed'] = True
            reconnect = getattr(client, 'reset_connection', None)
            if reconnect is not None and not result.get('authorization_failed'):
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    try:
                        await asyncio.wait_for(reconnect(), timeout=min(1., remaining))
                    except (PocRunnerError, PocRunnerUnavailable, TimeoutError, OSError):
                        pass
            return None

    async def close():
        return await client.close_context(context_id)

    async def status():
        return await client.context_status(context_id)

    while time.monotonic() < deadline:
        if request_close and result['close_attempts'] < 3 and (last_status is None or last_status['state'] == 'open'):
            result['close_attempts'] += 1
            ack = await request(close)
            if ack is not None:
                result['acknowledged'] = True
                last_status = ack
                if ack['state'] in {'closed', 'unresolved'}:
                    result['state'] = ack['state']
                    break
        if result.get('authorization_failed'):
            break
        if time.monotonic() >= deadline:
            break
        result['status_attempts'] += 1
        observed = await request(status)
        if observed is not None:
            last_status = observed
            if observed['state'] in {'closed', 'unresolved'}:
                result['state'] = observed['state']
                break
        if result.get('authorization_failed') or failures >= 3:
            break
        await asyncio.sleep(min(interval, max(0., deadline - time.monotonic())))
    if result['state'] == 'unknown' and last_status is not None and not failures:
        result['state'] = 'busy'
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result
