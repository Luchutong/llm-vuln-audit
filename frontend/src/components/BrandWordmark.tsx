/** A local, CSS-rendered wordmark: no remote font request or raster asset. */
export function BrandWordmark({ compact = false }: { compact?: boolean }) {
  return <strong className={`brand-wordmark${compact ? ' brand-wordmark-compact' : ''}`}>VULN-AUDIT</strong>;
}
