import { useEffect, useId, useRef } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

const panels: HTMLElement[] = [];
function syncPanels() {
  panels.forEach((node, index) => {
    node.inert = index < panels.length - 1;
    if (node.inert) node.setAttribute('aria-hidden', 'true');
    else node.removeAttribute('aria-hidden');
  });
}

export function Overlay({ title, children, onClose, drawer = false, className = '' }: { title: string; children: ReactNode; onClose: () => void; drawer?: boolean; className?: string }) {
  const panel = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  const id = useId();
  useEffect(() => {
    const node = panel.current;
    if (!node) return;
    const previous = document.activeElement as HTMLElement | null;
    panels.push(node);
    const focusable = () => [...(panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]') ?? [])].filter((node) => node.getClientRects().length > 0);
    (focusable()[0] ?? panel.current)?.focus();
    syncPanels();
    const keydown = (event: KeyboardEvent) => {
      if (panels.at(-1) !== node) return;
      if (event.key === 'Escape') { event.preventDefault(); close.current(); }
      if (event.key === 'Tab') {
        const nodes = focusable();
        if (!nodes.length) { event.preventDefault(); panel.current?.focus(); return; }
        const first = nodes[0], last = nodes[nodes.length - 1];
        if (event.shiftKey && (document.activeElement === first || !panel.current?.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && (document.activeElement === last || !panel.current?.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', keydown);
    return () => {
      document.removeEventListener('keydown', keydown);
      const wasTop = panels.at(-1) === node;
      const index = panels.indexOf(node);
      if (index >= 0) panels.splice(index, 1);
      syncPanels();
      if (wasTop && previous?.isConnected && !previous.closest('[inert]')) previous.focus();
    };
  }, []);
  return createPortal(<div className={`overlay${drawer ? ' drawer-overlay' : ''}`} onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <div ref={panel} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={id} className={`${drawer ? 'drawer-panel' : 'dialog-panel'} ${className}`}>
      <div className="overlay-header"><h2 id={id}>{title}</h2><button type="button" className="icon-button" aria-label={`关闭${title}`} onClick={onClose}><X size={20} /></button></div>
      {children}
    </div>
  </div>, document.body);
}
