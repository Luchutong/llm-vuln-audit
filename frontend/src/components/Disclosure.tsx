import { useId, useState } from 'react';
import type { ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

/** Children mount only while expanded, including any source requests. */
export function Disclosure({ title, children, defaultOpen = false, className = '' }: { title: ReactNode; children: ReactNode; defaultOpen?: boolean; className?: string }) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return <section className={`disclosure ${className}`}>
    <button type="button" className="disclosure-toggle" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
      <span className="disclosure-title">{title}</span><ChevronDown size={16} className={open ? 'rotated' : ''} />
    </button>
    {open && <div id={id} className="disclosure-content">{children}</div>}
  </section>;
}
