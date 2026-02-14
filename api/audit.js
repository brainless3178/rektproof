module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Method not allowed. Use POST.' });
        return;
    }

    var body = req.body || {};
    var target = body.target || body.program_id;

    if (!target) {
        res.status(400).json({ error: 'Missing required field: target or program_id' });
        return;
    }

    res.status(200).json({
        ok: true,
        message: 'Audit request received for ' + target,
        target: target,
        note: 'Audit engine processes requests asynchronously. Check /api/status for engine state.'
    });
};
