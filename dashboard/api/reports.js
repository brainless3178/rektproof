module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    res.status(200).json({
        reports: [
            { id: 'REP-001', name: 'vulnerable-vault_audit.pdf', date: '2026-02-13', type: 'Full Audit' },
            { id: 'REP-002', name: 'solana-token-standard_v2.json', date: '2026-02-12', type: 'Differential' },
            { id: 'REP-003', name: 'jito-relayer_security_brief.md', date: '2026-02-11', type: 'Briefing' }
        ]
    });
};
