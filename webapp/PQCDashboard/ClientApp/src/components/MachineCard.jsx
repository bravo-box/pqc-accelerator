import React, { useState } from 'react';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function platformClass(p) {
  if (!p) return '';
  const lower = p.toLowerCase();
  if (lower.includes('windows')) return 'platform-windows';
  if (lower.includes('linux'))   return 'platform-linux';
  if (lower.includes('darwin') || lower.includes('mac')) return 'platform-darwin';
  return '';
}

function formatRelative(dt) {
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (diff < 60)    return `${Math.round(diff)}s ago`;
  if (diff < 3600)  return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

export default function MachineCard({ machine: m }) {
  const [expanded, setExpanded] = useState(false);

  const pct = m.totalChecks > 0
    ? Math.round((m.compliantChecks / m.totalChecks) * 100)
    : 100;

  const sortedGaps = [...m.gaps].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );

  const displayGaps = expanded ? sortedGaps : sortedGaps.slice(0, 3);

  return (
    <div className={`machine-card ${m.gapCount > 0 ? 'has-gaps' : 'compliant'}`}>
      <div className="machine-header">
        <div>
          <div className="machine-name">{m.hostname}</div>
          <div className="machine-meta">{m.osVersion || m.platform}</div>
        </div>
        <span className={`platform-badge ${platformClass(m.platform)}`}>
          {m.platform}
        </span>
      </div>

      <div className="machine-stats">
        <div className="stat-item">
          <div className="stat-value" style={{ color: 'var(--green)' }}>{m.compliantChecks}</div>
          <div className="stat-label">Compliant</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: m.nonCompliantChecks > 0 ? 'var(--orange)' : 'var(--muted)' }}>
            {m.nonCompliantChecks}
          </div>
          <div className="stat-label">Issues</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: m.gapCount > 0 ? 'var(--red)' : 'var(--muted)' }}>
            {m.gapCount}
          </div>
          <div className="stat-label">Gaps</div>
        </div>
      </div>

      <div className="compliance-bar-wrap">
        <div className="compliance-bar">
          <div className="compliance-fill" style={{ width: `${pct}%`, background: pct === 100 ? 'var(--green)' : pct >= 75 ? 'var(--yellow)' : 'var(--red)' }} />
        </div>
        <div className="compliance-pct">{pct}% compliant ({m.compliantChecks}/{m.totalChecks} checks)</div>
      </div>

      {m.gapCount > 0 ? (
        <div className="gap-list">
          {displayGaps.map((g, i) => (
            <div key={i} className="gap-item">
              <div className={`severity-dot sev-${g.severity}`} />
              <div>
                <div className="gap-type">{g.gapType.replace(/_/g, ' ')}</div>
                <div className="gap-component">{g.affectedComponent}</div>
              </div>
            </div>
          ))}
          {sortedGaps.length > 3 && (
            <button
              onClick={() => setExpanded(e => !e)}
              style={{ background: 'none', border: 'none', color: 'var(--blue)', cursor: 'pointer', fontSize: '0.78rem', marginTop: '0.25rem', padding: 0 }}
            >
              {expanded ? 'Show less' : `+${sortedGaps.length - 3} more gaps`}
            </button>
          )}
        </div>
      ) : (
        <div className="no-gaps">✓ No compliance gaps detected</div>
      )}

      <div className="last-seen">Last seen: {formatRelative(m.lastSeen)}</div>
    </div>
  );
}
