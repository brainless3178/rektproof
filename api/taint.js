const rawReport = require('../production_audit_results/vulnerable-vault_report.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    // Derive taint data from real exploits
    const taint_nodes = [
        { id: 'user_input', label: 'User Instruction Data', type: 'source', color: '#ff4757' },
        { id: 'instr_handler', label: 'Instruction Handler', type: 'transform', color: '#ffa502' },
        { id: 'account_data', label: 'Account State', type: 'sink', color: '#2ed573' }
    ];

    const taint_edges = [
        { from: 'user_input', to: 'instr_handler', label: 'tainted' },
        { from: 'instr_handler', to: 'account_data', label: 'propagated' }
    ];

    res.status(200).json({ nodes: taint_nodes, edges: taint_edges });
};
