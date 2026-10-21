import { useId, useState } from 'react';
import { Check, Copy } from 'lucide-react';

export function LongContent({ value, label, previewLines = 3 }: { value: unknown; label?: string; previewLines?: number }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const id = useId();
  const text = value == null ? '—' : typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const long = text.length > 160 || text.split('\n').length > previewLines;
  return (
    <div className="long-content">
      {(label || long) && <div className="long-content-actions">
        {label && <span className="field-label">{label}</span>}
        <span className="row">
          {long && <button type="button" className="text-button" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded(!expanded)}>{expanded ? '收起' : '展开全文'}</button>}
          <button type="button" className="icon-button small-icon" aria-label={`复制${label ?? '内容'}`} onClick={async () => {
            try { await navigator.clipboard.writeText(text); setCopied(true); setCopyError(false); }
            catch { setCopyError(true); }
          }}>{copied ? <Check size={14} /> : <Copy size={14} />}</button>
        </span>
      </div>}
      <div id={id} className={`long-content-text${expanded ? ' expanded' : long ? ' clamped' : ''}`} style={expanded || !long ? undefined : { WebkitLineClamp: previewLines }}>{expanded || !long ? text : text.slice(0, 600)}</div>
      {copyError && <span className="field-hint" role="status">复制失败，请展开后选中文本复制。</span>}
    </div>
  );
}
