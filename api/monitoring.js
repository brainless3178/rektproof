module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    res.status(200).json({
        active_threats: 0,
        alerts: [
            { id: 1, type: 'INFO', message: 'Honeypot account created for monitoring', timestamp: new Date().toISOString() },
            { id: 2, type: 'WARNING', message: 'Anomalous transfer pattern detected in Vault-A', timestamp: new Date().toISOString() }
        ],
        mempool_status: 'Healthy',
        scan_frequency: '60s'
    });
};
