import test from 'node:test';
import assert from 'node:assert/strict';
import { cachePresentation } from '../src/promptCache.ts';

test('real zero hits differ from absent and partial provider reports', () => {
  assert.equal(cachePresentation().label, '暂无数据');
  assert.equal(cachePresentation({usage_records: 3, reported_records: 0}).label, '暂无缓存计数');
  assert.equal(cachePresentation({usage_records: 3, reported_records: 0}).partial, false);
  const zero = cachePresentation({usage_records: 3, reported_records: 3, cache_hit_ratio: 0});
  assert.equal(zero.label, '0.0%'); assert.equal(zero.partial, false);
  const partial = cachePresentation({usage_records: 3, reported_records: 2, cache_hit_ratio: .754});
  assert.equal(partial.label, '75.4%'); assert.equal(partial.coverage, '2/3 条用量记录');
  assert.equal(partial.partial, true);
  assert.equal(cachePresentation({usage_records: 1, reported_records: 1, reported_input_tokens: 0}).label, '无输入 token');
});
