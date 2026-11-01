import { useId, useLayoutEffect, useRef, useState } from 'react';

/** Expansion survives live updates. Measuring wrapping also covers narrow screens. */
export function CompactText({ text, lines = 2, label = '说明' }: { text: string; lines?: number; label?: string }) {
  const [open, setOpen] = useState(false);
  const [overflows, setOverflows] = useState(false);
  const content = useRef<HTMLParagraphElement>(null);
  const id = useId();
  useLayoutEffect(() => {
    const element = content.current;
    if (!element || open) return;
    const measure = () => setOverflows(element.scrollHeight > element.clientHeight + 1);
    measure();
    const observer = new ResizeObserver(measure); observer.observe(element);
    return () => observer.disconnect();
  }, [text, lines, open]);
  return <div className="compact-text">
    <p ref={content} id={id} className={open ? undefined : 'compact-clamp'} style={{ WebkitLineClamp: lines }}>{text}</p>
    {(overflows || open) && <button type="button" className="text-button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>{open ? `收起${label}` : `展开${label}`}</button>}
  </div>;
}
