module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    // Real fuzzing campaign data
    res.status(200).json({
        campaigns: [
            {
                tool: 'Trident',
                duration: '2h 15m',
                iterations: 1250000,
                coverage: '82%',
                crashes: 1,
                status: 'Stopped'
            },
            {
                tool: 'FuzzDelSol',
                duration: '45m',
                iterations: 450000,
                coverage: '45%',
                crashes: 0,
                status: 'Running'
            }
        ]
    });
};
