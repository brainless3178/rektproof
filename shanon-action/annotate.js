/**
 * Shanon Security — PR Comment Annotator
 *
 * Posts branded security scan results as a PR comment
 * and adds inline review comments on vulnerable lines.
 *
 * Usage: GITHUB_TOKEN=xxx node annotate.js '<combined_json>'
 */

const { Octokit } = require('@octokit/rest');
const fs = require('fs');

async function run() {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
        console.log('No GITHUB_TOKEN — skipping PR annotation');
        return;
    }

    const eventPath = process.env.GITHUB_EVENT_PATH;
    if (!eventPath) {
        console.log('No GITHUB_EVENT_PATH — skipping PR annotation');
        return;
    }

    let event;
    try {
        event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    } catch (e) {
        console.log('Cannot read event file — skipping PR annotation');
        return;
    }

    // Only annotate on pull requests
    if (!event.pull_request) {
        console.log('Not a pull request event — skipping PR annotation');
        return;
    }

    const prNumber = event.pull_request.number;
    const [owner, repo] = (process.env.GITHUB_REPOSITORY || '/').split('/');

    let result;
    try {
        result = JSON.parse(process.argv[2]);
    } catch (e) {
        console.log('Cannot parse scan results — skipping PR annotation');
        return;
    }

    const octokit = new Octokit({ auth: token });

    // ─── Post summary comment ───────────────────────────

    const riskEmoji = result.risk_score >= 70 ? '🔴' :
        result.risk_score >= 40 ? '🟡' : '🟢';

    const guardSection = result.guard_risk_score > 0
        ? `\n### 🛡️ Dependency Firewall\n` +
        `| Metric | Value |\n|--------|-------|\n` +
        `| Supply Chain Risk | ${result.guard_risk_score}/100 |\n`
        : `\n### 🛡️ Dependency Firewall\n✅ All dependencies are clean.\n`;

    const body = [
        `## 🛡️ Shanon Security Scan Results`,
        ``,
        `| Severity | Count |`,
        `|----------|-------|`,
        `| 🔴 Critical | ${result.critical_count || 0} |`,
        `| 🟠 High | ${result.high_count || 0} |`,
        `| 🟡 Medium | ${result.medium_count || 0} |`,
        `| 🔵 Low | ${result.low_count || 0} |`,
        ``,
        `${riskEmoji} **Risk Score: ${result.risk_score}/100**`,
        guardSection,
        `---`,
    ].join('\n');

    // Find and update existing Shanon comment, or create new one
    const COMMENT_TAG = '<!-- shanon-security-scan -->';
    const fullBody = `${COMMENT_TAG}\n${body}\n*Powered by [Shanon Security Oracle](https://shanon.security)*`;

    try {
        const { data: comments } = await octokit.issues.listComments({
            owner, repo,
            issue_number: prNumber,
            per_page: 100,
        });

        const existing = comments.find(c => c.body && c.body.includes(COMMENT_TAG));

        if (existing) {
            await octokit.issues.updateComment({
                owner, repo,
                comment_id: existing.id,
                body: fullBody,
            });
            console.log(`Updated existing Shanon comment (id: ${existing.id})`);
        } else {
            await octokit.issues.createComment({
                owner, repo,
                issue_number: prNumber,
                body: fullBody,
            });
            console.log('Created new Shanon comment');
        }
    } catch (e) {
        console.log(`Failed to post PR comment: ${e.message}`);
    }

    // ─── Post inline annotations on findings ────────────

    if (!result.findings || result.findings.length === 0) {
        return;
    }

    // Get PR changed files for accurate annotation
    let changedFiles = [];
    try {
        const { data: files } = await octokit.pulls.listFiles({
            owner, repo,
            pull_number: prNumber,
            per_page: 300,
        });
        changedFiles = files.map(f => f.filename);
    } catch (e) {
        console.log(`Cannot list PR files: ${e.message}`);
        return;
    }

    // Only annotate findings in files that are part of the PR
    const relevantFindings = result.findings.filter(f =>
        f.location && changedFiles.some(cf => cf.endsWith(f.location) || f.location.endsWith(cf))
    );

    // Limit to 10 inline comments to avoid spam
    const toAnnotate = relevantFindings.slice(0, 10);

    for (const finding of toAnnotate) {
        const matchedFile = changedFiles.find(cf =>
            cf.endsWith(finding.location) || finding.location.endsWith(cf)
        );

        if (!matchedFile) continue;

        const line = finding.line_number || 1;
        const severityIcon = finding.severity_label === 'CRITICAL' ? '🔴' :
            finding.severity_label === 'HIGH' ? '🟠' :
                finding.severity_label === 'MEDIUM' ? '🟡' : '🔵';

        const commentBody = [
            `${severityIcon} **[Shanon Security]** ${finding.severity_label}: ${finding.vuln_type}`,
            ``,
            `> ${finding.id} — ${finding.description}`,
            ``,
            `**Fix:** ${finding.secure_fix || finding.prevention || 'See recommendation above.'}`,
        ].join('\n');

        try {
            await octokit.pulls.createReviewComment({
                owner, repo,
                pull_number: prNumber,
                body: commentBody,
                path: matchedFile,
                line: line,
                side: 'RIGHT',
            });
        } catch (e) {
            // Line might not be in diff — fall back to PR-level comment
            console.log(`Inline annotation failed for ${matchedFile}:${line} — ${e.message}`);
        }
    }

    console.log(`Annotated ${toAnnotate.length} findings on PR #${prNumber}`);
}

run().catch(e => {
    console.error(`Annotator error: ${e.message}`);
    process.exit(0); // Non-fatal — don't fail the action
});
