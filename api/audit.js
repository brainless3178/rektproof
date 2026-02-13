module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    const { target } = req.body || {};

    res.status(200).json({
        ok: true,
        scan_id: `SCAN-${Math.random().toString(36).substring(7).toUpperCase()}`,
        message: `Audit started for ${target || 'requested target'}`,
        estimated_time: '4.2 seconds'
    });
};
