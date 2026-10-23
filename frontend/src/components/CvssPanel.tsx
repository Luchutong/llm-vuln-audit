import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorText, post } from '../api';
import type { CvssFields, CvssMetricDetail, CvssHistoryPage, Finding } from '../types';
import { CVSS_LABELS, CVSS_METRICS, CVSS_STATUS_LABELS, CVSS_VALUES, CVSS_VALUE_LABELS, ratingLabel } from '../cvss';
import { Disclosure } from './Disclosure';
import { SourceViewer } from './SourceViewer';
import { localDate } from '../status';
import { useLedgerResource } from '../useLedgerResource';
import '../cvss.css';

export function SeverityBadge({ finding }: {finding: CvssFields & {severity?: string}}) {
  return <span className={`chip sev-${finding.cvss?.severity ?? 'unknown'}`} title="CVSS 3.1 基础评级">{ratingLabel(finding)}</span>;
}

export function CvssPanel({ finding }: {finding:CvssFields}) {
  const info = finding.cvss_assessment;
  return <section className="cvss-panel" aria-label="CVSS 3.1 基础评分"><div className="between"><strong>CVSS 3.1 基础评分</strong><SeverityBadge finding={finding} /></div>
    <p className="small muted">{CVSS_STATUS_LABELS[info?.status ?? 'legacy_unrated']} · {info?.source === 'manual' ? '人工修订' : info?.source === 'auto' ? '自动指标，宿主计算' : '历史记录'}{info?.assessment_revision ? ` · 评分第 ${info.assessment_revision} 版` : ''}。评分、证据校验、自动验证与结论处置分别记录。</p>
    {finding.cvss && <code className="cvss-vector">{finding.cvss.base_vector}</code>}
    <Disclosure title="查看八项指标与评分依据"><div className="cvss-metrics">{CVSS_METRICS.map(key => {
      const item = info?.metric_details?.[key];
      return <div className="cvss-metric" key={key}><strong>{key} · {CVSS_LABELS[key]}：{item?.value ? `${item.value} · ${CVSS_VALUE_LABELS[key][item.value] ?? item.value}` : '待补充'}</strong><p>{item?.rationale || '暂无评分依据'}</p>{item?.assumption && <span className="chip">人工假设</span>}{item?.issues?.map((issue,i) => <p className="small muted" key={i}>{issue}</p>)}{item?.evidence?.map((ref,i) => <Disclosure key={i} title={`${ref.path}:${ref.start_line}-${ref.end_line}`}>
        {ref.snapshot_id || info?.snapshot_id ? <SourceViewer snapshotId={ref.snapshot_id ?? info!.snapshot_id!} path={ref.path} start={ref.start_line} end={ref.end_line} /> : <p>来源快照不可用，保留原始引用。</p>}
      </Disclosure>)}</div>;
    })}</div></Disclosure>
  </section>;
}

function CvssHistory({id}: {id:string}) {
  const [offset,setOffset] = useState(0);
  const {data,error,refresh} = useLedgerResource<CvssHistoryPage>(`/project-findings/${encodeURIComponent(id)}/cvss-history?offset=${offset}&limit=25`);
  return <div className="grid">{error && <div className="error-box" role="alert">{error}<button className="btn" onClick={refresh}>重试</button></div>}{!data && !error && <p>正在读取评分历史…</p>}{data?.items.map(item => <div key={item.id}><p className="small muted">{item.cvss_assessment?.created_at && localDate(item.cvss_assessment.created_at)} · 结论第 {item.cvss_assessment?.conclusion_revision} 版 · {item.applicable ? '适用于当前结论' : '不再适用'} · {item.source_run_available ? '来源任务可追溯' : '来源任务不可用'}</p>{item.cvss_assessment?.reason && <p>修订原因：{item.cvss_assessment.reason}</p>}<CvssPanel finding={item} /></div>)}{data?.total === 0 && <p>暂无独立评分历史。</p>}<div className="row"><button className="btn" disabled={!offset} onClick={()=>setOffset(value=>Math.max(0,value-25))}>上一页</button><span>{data?.total ?? 0} 条</span><button className="btn" disabled={!data || offset+25>=data.total} onClick={()=>setOffset(value=>value+25)}>下一页</button></div></div>;
}

export function CvssEditor({finding,onChanged}: {finding:Finding; onChanged:()=>void}) {
  const [editing,setEditing] = useState(false);
  return <section className="panel panel-body cvss-editor"><p className="small muted">人工修订更新项目台账评级，保留单次审计当时的评分及验证记录。</p><button className="btn" onClick={()=>setEditing(value=>!value)}>{editing ? '收起指标编辑' : '修订 CVSS 指标'}</button>{editing && <MetricForm key={finding.id} finding={finding} onChanged={onChanged} />}
    <Disclosure title="评分修订历史"><CvssHistory id={finding.id} /></Disclosure></section>;
}

function MetricForm({finding,onChanged}: {finding:Finding; onChanged:()=>void}) {
  const initial = () => Object.fromEntries(CVSS_METRICS.map(key => [key, finding.cvss_assessment?.metric_details?.[key] ?? {value:null,rationale:'',evidence:[],assumption:false}])) as Record<string,CvssMetricDetail>;
  const [metrics,setMetrics] = useState(initial);
  const [reason,setReason] = useState('');
  const [expected,setExpected] = useState({expected_revision:finding.revision, expected_assessment_revision:finding.cvss_assessment?.assessment_revision ?? 0});
  const [preview,setPreview] = useState<CvssFields|null>(null);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState('');
  const [conflict,setConflict] = useState(false);
  const lock = useRef(false), alive = useRef(true);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  const update = (key:string,patch:Partial<CvssMetricDetail>) => {setMetrics(items=>({...items,[key]:{...items[key],...patch}}));setPreview(null);};
  const submit = async (save:boolean) => {
    if(lock.current)return;
    lock.current=true;setBusy(true);setError('');
    try {
      const path=`/project-findings/${encodeURIComponent(finding.id)}/cvss`;
      const body={metrics,reason,...expected};
      const value = save ? await api<CvssFields>(path,{method:'PUT',body:JSON.stringify(body)}) : await post<CvssFields>(`${path}/preview`,body);
      if(!alive.current)return;
      setPreview(value);setConflict(false);
      if(save){setExpected({expected_revision:finding.revision,expected_assessment_revision:value.cvss_assessment!.assessment_revision});onChanged();window.dispatchEvent(new Event('audit-records-changed'));}
    } catch(exc){if(alive.current){setError(errorText(exc));setPreview(null);setConflict(exc instanceof ApiError && exc.status===409);}}
    finally{lock.current=false;if(alive.current)setBusy(false);}
  };
  return <form className="cvss-form" onSubmit={event=>{event.preventDefault();void submit(false);}}><p className="small muted">每项填写判断依据；保留有效源码引用，或明确选择人工假设。预览由后端计算。</p>
    {CVSS_METRICS.map(key=><fieldset key={key} disabled={busy}><legend>{key} · {CVSS_LABELS[key]}</legend><label>指标取值<select aria-label={`${key} 指标取值`} value={metrics[key].value ?? ''} onChange={event=>update(key,{value:event.target.value || null})}><option value="">待补充</option>{CVSS_VALUES[key].map(value=><option key={value} value={value}>{value} · {CVSS_VALUE_LABELS[key][value]}</option>)}</select></label><label>判断依据<textarea aria-label={`${key} 判断依据`} value={metrics[key].rationale} maxLength={2400} onChange={event=>update(key,{rationale:event.target.value})} /></label><EvidenceInput metric={key} disabled={busy} onAdd={(ref)=>update(key,{assumption:false,evidence:[...metrics[key].evidence,ref]})} /><label className="cvss-check"><input type="checkbox" checked={metrics[key].assumption ?? false} onChange={event=>update(key,{assumption:event.target.checked,evidence:event.target.checked ? [] : metrics[key].evidence})} />此项基于人工假设（需在依据中说明）</label>{metrics[key].evidence.length>0 && <div className="cvss-refs">{metrics[key].evidence.map((ref,i)=><span key={i}>{ref.path}:{ref.start_line}-{ref.end_line}<button type="button" className="text-button" onClick={()=>update(key,{evidence:metrics[key].evidence.filter((_,index)=>index!==i)})}>移除引用</button></span>)}</div>}</fieldset>)}
    <label>修订原因<textarea aria-label="CVSS 修订原因" minLength={3} maxLength={2000} required value={reason} disabled={busy} onChange={event=>{setReason(event.target.value);setPreview(null);}} /></label>
    {error && <div className="error-box" role="alert">{error}</div>}{conflict && <div className="grid"><p>草稿已保留。刷新详情比较后，可将草稿基于最新版本重新预览。</p><button type="button" className="btn" onClick={onChanged}>刷新当前评分</button><button type="button" className="btn" onClick={()=>{setExpected({expected_revision:finding.revision,expected_assessment_revision:finding.cvss_assessment?.assessment_revision ?? 0});setConflict(false);setPreview(null);}}>基于当前版本重新预览</button><CvssPanel finding={finding} /></div>}
    {preview && <div role="status"><CvssPanel finding={preview} /></div>}<div className="row"><button className="btn" disabled={busy || conflict} type="submit">{busy?'处理中…':'预览 CVSS 评分'}</button><button className="btn btn-primary" type="button" disabled={busy || !preview || conflict} onClick={()=>void submit(true)}>保存项目评分</button></div>
  </form>;
}


function EvidenceInput({metric,disabled,onAdd}:{metric:string;disabled:boolean;onAdd:(ref:{path:string;start_line:number;end_line:number})=>void}) {
  const [path,setPath]=useState('');
  const [start,setStart]=useState(1),[end,setEnd]=useState(1);
  return <Disclosure title="添加源码引用"><div className="cvss-reference-input"><label>源码路径<input aria-label={`${metric} 源码路径`} value={path} disabled={disabled} onChange={event=>setPath(event.target.value)} placeholder="快照内的完整相对路径" /></label><label>起始行<input aria-label={`${metric} 起始行`} type="number" min={1} value={start} disabled={disabled} onChange={event=>setStart(Math.max(1,Math.trunc(Number(event.target.value)||1)))} /></label><label>结束行<input aria-label={`${metric} 结束行`} type="number" min={start} value={end} disabled={disabled} onChange={event=>setEnd(Math.max(1,Math.trunc(Number(event.target.value)||1)))} /></label><button type="button" className="btn" disabled={disabled || !path.trim() || end<start} onClick={()=>{onAdd({path:path.trim(),start_line:start,end_line:end});setPath('');}}>添加引用</button></div></Disclosure>;
}
