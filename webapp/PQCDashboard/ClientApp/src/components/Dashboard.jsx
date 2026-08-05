import React from 'react';
import MachineCard from './MachineCard';

function platformMatchesFilter(platform, filter) {
  if (filter === 'all') return true;
  if (!platform) return false;

  const lower = platform.toLowerCase();
  if (filter === 'windows') return lower.includes('windows');
  if (filter === 'linux') return lower.includes('linux');
  return true;
}

export default function Dashboard({ fleet, platformFilter = 'all' }) {
  if (!fleet) return null;

  const visibleMachines = fleet.machines.filter(machine =>
    platformMatchesFilter(machine.platform, platformFilter)
  );

  const compliancePct = fleet.totalMachines > 0
    ? Math.round((fleet.fullyCompliantMachines / fleet.totalMachines) * 100)
    : 0;

  const visibleCompliancePct = visibleMachines.length > 0
    ? Math.round((visibleMachines.filter(machine => machine.gapCount === 0).length / visibleMachines.length) * 100)
    : 0;

  return (
    <div>
      {/* Fleet summary */}
      <div className="summary-grid">
        <div className="summary-card">
          <div className={`value ${visibleCompliancePct === 100 ? 'value-green' : visibleCompliancePct >= 50 ? 'value-yellow' : 'value-red'}`}>
            {visibleCompliancePct}%
          </div>
          <div className="label">Visible Compliance</div>
        </div>
        <div className="summary-card">
          <div className="value value-blue">{visibleMachines.length}</div>
          <div className="label">Visible Machines</div>
        </div>
        <div className="summary-card">
          <div className="value value-green">{visibleMachines.filter(machine => machine.gapCount === 0).length}</div>
          <div className="label">Fully Compliant</div>
        </div>
        <div className="summary-card">
          <div className="value value-red">{visibleMachines.filter(machine => machine.gapCount > 0).length}</div>
          <div className="label">With Gaps</div>
        </div>
        <div className="summary-card">
          <div className="value value-red">
            {visibleMachines.reduce((count, machine) => count + machine.gaps.filter(gap => gap.severity === 'CRITICAL' || gap.severity === 'HIGH').length, 0)}
          </div>
          <div className="label">Critical / High</div>
        </div>
        <div className="summary-card">
          <div className="value value-orange">
            {visibleMachines.reduce((count, machine) => count + machine.gaps.filter(gap => gap.severity === 'MEDIUM').length, 0)}
          </div>
          <div className="label">Medium Gaps</div>
        </div>
        <div className="summary-card">
          <div className="value value-yellow">
            {visibleMachines.reduce((count, machine) => count + machine.gaps.filter(gap => gap.severity === 'LOW').length, 0)}
          </div>
          <div className="label">Low Gaps</div>
        </div>
        <div className="summary-card">
          <div className="value value-white">
            {visibleMachines.reduce((count, machine) => count + machine.gapCount, 0)}
          </div>
          <div className="label">Visible Gaps</div>
        </div>
      </div>

      {/* Machine cards */}
      <div className="section-title">Machines ({visibleMachines.length})</div>
      <div className="machine-grid">
        {visibleMachines.map(m => (
          <MachineCard key={m.hostname} machine={m} />
        ))}
        {visibleMachines.length === 0 && (
          <div style={{ color: 'var(--muted)', gridColumn: '1/-1', padding: '2rem', textAlign: 'center' }}>
            No machines match the selected filter.
          </div>
        )}
      </div>
    </div>
  );
}
