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

    var nodes = [
        { id: 'user_input', label: 'User Instruction Data', type: 'source', color: '#ff4757' },
        { id: 'vault_handler', label: 'Vault Handler', type: 'transform', color: '#ffa502' },
        { id: 'token_handler', label: 'Token Handler', type: 'transform', color: '#ffa502' },
        { id: 'staking_handler', label: 'Staking Handler', type: 'transform', color: '#ffa502' }
    ];
    var edges = [
        { from: 'user_input', to: 'vault_handler', label: 'tainted' },
        { from: 'user_input', to: 'token_handler', label: 'tainted' },
        { from: 'user_input', to: 'staking_handler', label: 'tainted' }
    ];

    var reports = [
        { data: vaultReport, handler: 'vault_handler', prefix: 'vault' },
        { data: tokenReport, handler: 'token_handler', prefix: 'token' },
        { data: stakingReport, handler: 'staking_handler', prefix: 'staking' }
    ];

    reports.forEach(function (r) {
        var exploits = (r.data.exploits || []).slice(0, 5);
        exploits.forEach(function (f, i) {
            var nodeId = r.prefix + '_sink_' + i;
            nodes.push({
                id: nodeId,
                label: f.instruction || f.vulnerability_type || 'sink',
                type: 'sink',
                color: f.severity >= 4 ? '#ff4757' : '#ffa502'
            });
            edges.push({ from: r.handler, to: nodeId, label: f.category || 'flow' });
        });
    });

    var deepTaint = (vaultReport.deep_analysis && vaultReport.deep_analysis.enhanced_taint) || {};

    res.status(200).json({
        nodes,
        edges,
        total_sources: nodes.filter(function (n) { return n.type === 'source'; }).length,
        total_sinks: nodes.filter(function (n) { return n.type === 'sink'; }).length,
        total_flows: edges.length,
        critical_flows: nodes.filter(function (n) { return n.color === '#ff4757'; }).length,
        enhanced_taint_summary: {
            interprocedural_flows: deepTaint.interprocedural_flows || 0,
            context_sensitive_findings: deepTaint.context_sensitive_findings || 0,
            field_sensitive_findings: deepTaint.field_sensitive_findings || 0,
            path_sensitive_findings: deepTaint.path_sensitive_findings || 0
        }
    });
};
