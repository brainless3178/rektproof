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

    var reports = [
        { name: 'vulnerable-vault', data: vaultReport, id: 'FZ-VAULT-01' },
        { name: 'vulnerable-token', data: tokenReport, id: 'FZ-TOKEN-01' },
        { name: 'vulnerable-staking', data: stakingReport, id: 'FZ-STAKE-01' }
    ];

    var campaigns = reports.map(function (r) {
        return {
            id: r.id,
            target: r.name,
            status: 'completed',
            crashes_found: r.data.critical_count + r.data.high_count,
            unique_paths: r.data.total_exploits,
            findings_breakdown: {
                critical: r.data.critical_count,
                high: r.data.high_count,
                medium: r.data.medium_count
            }
        };
    });

    var totalCrashes = campaigns.reduce(function (s, c) { return s + c.crashes_found; }, 0);

    res.status(200).json({
        total_crashes: totalCrashes,
        total_campaigns: campaigns.length,
        campaigns: campaigns
    });
};
