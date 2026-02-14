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
        {
            id: 'REP-VAULT',
            name: 'vulnerable-vault audit report',
            program_id: vaultReport.program_id,
            date: vaultReport.timestamp || '2026-02-13',
            type: 'Full Audit',
            total_findings: vaultReport.total_exploits,
            critical: vaultReport.critical_count,
            high: vaultReport.high_count,
            medium: vaultReport.medium_count
        },
        {
            id: 'REP-TOKEN',
            name: 'vulnerable-token audit report',
            program_id: tokenReport.program_id,
            date: tokenReport.timestamp || '2026-02-09',
            type: 'Full Audit',
            total_findings: tokenReport.total_exploits,
            critical: tokenReport.critical_count,
            high: tokenReport.high_count,
            medium: tokenReport.medium_count
        },
        {
            id: 'REP-STAKING',
            name: 'vulnerable-staking audit report',
            program_id: stakingReport.program_id,
            date: stakingReport.timestamp || '2026-02-09',
            type: 'Full Audit',
            total_findings: stakingReport.total_exploits,
            critical: stakingReport.critical_count,
            high: stakingReport.high_count,
            medium: stakingReport.medium_count
        }
    ];

    res.status(200).json({ reports });
};
