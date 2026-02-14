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

    function computeScore(report) {
        if (report.security_score != null) return report.security_score;
        var c = report.critical_count || 0;
        var h = report.high_count || 0;
        var m = report.medium_count || 0;
        return Math.max(0, 100 - (c * 5) - (h * 2) - (m * 1));
    }

    var programs = [
        {
            name: 'vulnerable-vault',
            program_id: vaultReport.program_id,
            total_exploits: vaultReport.total_exploits,
            critical_count: vaultReport.critical_count,
            high_count: vaultReport.high_count,
            medium_count: vaultReport.medium_count,
            security_score: computeScore(vaultReport),
            timestamp: vaultReport.timestamp || '2026-02-13T00:00:00Z'
        },
        {
            name: 'vulnerable-token',
            program_id: tokenReport.program_id,
            total_exploits: tokenReport.total_exploits,
            critical_count: tokenReport.critical_count,
            high_count: tokenReport.high_count,
            medium_count: tokenReport.medium_count,
            security_score: computeScore(tokenReport),
            timestamp: tokenReport.timestamp || '2026-02-09T14:54:32Z'
        },
        {
            name: 'vulnerable-staking',
            program_id: stakingReport.program_id,
            total_exploits: stakingReport.total_exploits,
            critical_count: stakingReport.critical_count,
            high_count: stakingReport.high_count,
            medium_count: stakingReport.medium_count,
            security_score: computeScore(stakingReport),
            timestamp: stakingReport.timestamp || '2026-02-09T14:54:32Z'
        }
    ];

    res.status(200).json({ programs });
};
