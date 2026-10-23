import type { CvssFields } from './types';
export const CVSS_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;
export const CVSS_VALUES: Record<string, string[]> = { AV: ['N','A','L','P'], AC: ['L','H'], PR: ['N','L','H'], UI: ['N','R'], S: ['U','C'], C: ['N','L','H'], I: ['N','L','H'], A: ['N','L','H'] };
export const CVSS_LABELS: Record<string,string> = { AV: '攻击途径', AC: '攻击复杂度', PR: '所需权限', UI: '用户交互', S: '影响范围', C: '机密性影响', I: '完整性影响', A: '可用性影响' };
export const CVSS_VALUE_LABELS: Record<string,Record<string,string>> = {
  AV: {N:'网络', A:'相邻网络', L:'本地', P:'物理'}, AC:{L:'低', H:'高'}, PR:{N:'无需权限', L:'低权限', H:'高权限'},
  UI:{N:'无需交互', R:'需要另一用户交互'}, S:{U:'不改变', C:'改变安全范围'},
  C:{N:'无', L:'低', H:'高'}, I:{N:'无', L:'低', H:'高'}, A:{N:'无', L:'低', H:'高'},
};
export const RATING_LABELS: Record<string,string> = {none:'无基础影响',low:'低危',medium:'中危',high:'高危',critical:'严重',unknown:'待评分'};
export const CVSS_STATUS_LABELS: Record<string,string> = {scored:'已量化', needs_information:'待补充指标', legacy_unrated:'历史未量化', stale:'评分已失效'};
export function ratingLabel(item: CvssFields & {severity?: string}) {
  if (item.cvss && item.cvss.base_score != null) return `${RATING_LABELS[item.cvss.severity] ?? item.cvss.severity} · ${item.cvss.base_score.toFixed(1)}`;
  const old = item.legacy_severity ?? (!item.cvss_assessment && item.severity !== 'unknown' ? item.severity : null);
  return old ? `历史等级 ${RATING_LABELS[old] ?? old} · 未量化` : '待评分';
}
