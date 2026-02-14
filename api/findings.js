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

    function mapFindings(report, programName) {
        return (report.exploits || []).map(function (e) {
            return {
                id: e.id,
                program_name: programName,
                category: e.category,
                vulnerability_type: e.vulnerability_type,
                severity: e.severity,
                severity_label: e.severity_label,
                instruction: e.instruction,
                description: e.description,
                attack_scenario: e.attack_scenario,
                secure_fix: e.secure_fix,
                economic_impact: e.value_at_risk_usd
                    ? '$' + Number(e.value_at_risk_usd).toLocaleString() + ' at risk'
                    : (e.economic_impact || 'See report for details')
            };
        });
    }

    var findings = []
        .concat(mapFindings(vaultReport, 'vulnerable-vault'))
        .concat(mapFindings(tokenReport, 'vulnerable-token'))
        .concat(mapFindings(stakingReport, 'vulnerable-staking'));

    res.status(200).json({ findings });
};
