const vaultReport = require('../production_audit_results/vulnerable-vault_report.json');
const tokenReport = require('../production_audit_results/vulnerable_token_report.json');
const stakingReport = require('../production_audit_results/vulnerable_staking_report.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    var allExploits = []
        .concat((vaultReport.exploits || []).map(function (e) { return Object.assign({}, e, { _program: 'vulnerable-vault' }); }))
        .concat((tokenReport.exploits || []).map(function (e) { return Object.assign({}, e, { _program: 'vulnerable-token' }); }))
        .concat((stakingReport.exploits || []).map(function (e) { return Object.assign({}, e, { _program: 'vulnerable-staking' }); }));

    var criticalAlerts = allExploits.filter(function (e) { return e.severity >= 4; });

    var alerts = criticalAlerts.slice(0, 10).map(function (f) {
        return {
            timestamp: vaultReport.timestamp || tokenReport.timestamp || '2026-02-13T00:00:00Z',
            description: f.vulnerability_type + ' in ' + (f.instruction || 'unknown') + ' (' + f._program + ')',
            severity: (f.severity_label || 'HIGH').toLowerCase(),
            program: f._program,
            finding_id: f.id,
            resolved: f.state === 'Fixed'
        };
    });

    res.status(200).json({
        status: 'active',
        total_alerts: criticalAlerts.length,
        active_monitors: 3,
        alerts: alerts
    });
};
