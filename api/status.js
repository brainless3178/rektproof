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

    var latestTimestamp = [vaultReport.timestamp, tokenReport.timestamp, stakingReport.timestamp]
        .filter(Boolean)
        .sort()
        .pop() || new Date().toISOString();

    var totalFindings = vaultReport.total_exploits + tokenReport.total_exploits + stakingReport.total_exploits;

    res.status(200).json({
        status: 'Operational',
        engine_version: 'v4.2.1-prod',
        last_scan: latestTimestamp,
        programs_audited: 3,
        total_findings: totalFindings,
        analyzers: [
            { name: 'Static Analysis', status: 'online' },
            { name: 'Taint Engine', status: 'online' },
            { name: 'Formal Prover', status: 'online' },
            { name: 'Fuzzer', status: 'online' }
        ]
    });
};
