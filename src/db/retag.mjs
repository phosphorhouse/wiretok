/**
 * Wiretok — Historical & Unattributed Request Account Re-Tagger
 * Uses parameterized prepared statements (`?`) exclusively.
 */

/**
 * Re-assign matching historical or unattributed requests and sessions to a target account.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {{
 *   accountId?: string,
 *   account_id?: string,
 *   account?: string,
 *   targetAccountId?: string,
 *   email?: string,
 *   email_or_label?: string,
 *   displayName?: string,
 *   sourceTool?: string,
 *   source_tool?: string,
 *   from?: string,
 *   to?: string,
 *   workspace?: string,
 *   era?: string,
 *   oldAccountId?: string,
 *   fromAccountId?: string,
 *   sessionId?: string,
 *   session_id?: string,
 *   onlyUnattributed?: boolean
 * }} [opts]
 */
export function retagLegacy(db, opts = {}) {
  const targetAccountId = String(
    opts.accountId || opts.account_id || opts.account || opts.targetAccountId || ''
  ).trim();

  if (!targetAccountId) {
    throw new Error('retagLegacy requires target accountId (opts.accountId or opts.account)');
  }

  const now = new Date().toISOString();
  const emailOrLabel = String(
    opts.email || opts.email_or_label || (targetAccountId.includes('@') ? targetAccountId : '')
  ).trim();
  const displayName = String(opts.displayName || emailOrLabel || targetAccountId).trim();
  const sourceTool = String(opts.sourceTool || opts.source_tool || '').trim();

  // Ensure the target account row exists
  db.prepare(`
    INSERT INTO accounts (
      account_id,
      source_tool,
      provider,
      email_or_label,
      display_name,
      auth_type,
      plan_type,
      monthly_fee_usd,
      created_at,
      updated_at
    ) VALUES (?, ?, 'google', ?, ?, 'oauth', 'api', 0.0, ?, ?)
    ON CONFLICT(account_id) DO UPDATE SET
      email_or_label = CASE WHEN excluded.email_or_label != '' THEN excluded.email_or_label ELSE accounts.email_or_label END,
      display_name = CASE WHEN accounts.display_name = '' THEN excluded.display_name ELSE accounts.display_name END,
      updated_at = excluded.updated_at
  `).run(
    targetAccountId,
    sourceTool || 'antigravity',
    emailOrLabel || targetAccountId,
    displayName,
    now,
    now
  );

  const reqClauses = [];
  const reqParams = [targetAccountId, emailOrLabel];

  const sessClauses = [];
  const sessParams = [targetAccountId];

  if (opts.from) {
    const fromIso = String(opts.from).trim();
    reqClauses.push('created_at >= ?');
    reqParams.push(fromIso);
    sessClauses.push('last_event_at >= ?');
    sessParams.push(fromIso);
  }

  if (opts.to) {
    let toIso = String(opts.to).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(toIso)) {
      toIso = `${toIso}T23:59:59.999Z`;
    }
    reqClauses.push('created_at <= ?');
    reqParams.push(toIso);
    sessClauses.push('started_at <= ?');
    sessParams.push(toIso);
  }

  if (opts.workspace) {
    const wsLike = `%${String(opts.workspace).trim()}%`;
    reqClauses.push('workspace LIKE ?');
    reqParams.push(wsLike);
    sessClauses.push('workspace LIKE ?');
    sessParams.push(wsLike);
  }

  if (sourceTool && sourceTool !== 'all') {
    reqClauses.push('source_tool = ?');
    reqParams.push(sourceTool);
    sessClauses.push('source_tool = ?');
    sessParams.push(sourceTool);
  }

  if (opts.era && opts.era !== 'all') {
    reqClauses.push('era = ?');
    reqParams.push(String(opts.era));
    sessClauses.push('era = ?');
    sessParams.push(String(opts.era));
  }

  const oldAcc = opts.oldAccountId || opts.fromAccountId;
  if (oldAcc && oldAcc !== 'all') {
    reqClauses.push('account_id = ?');
    reqParams.push(String(oldAcc));
    sessClauses.push('account_id = ?');
    sessParams.push(String(oldAcc));
  } else if (opts.onlyUnattributed || opts.scope === 'unattributed') {
    reqClauses.push(`(account_id IN ('unknown', 'legacy_unattributed', '') OR era = 'pre_milestone')`);
    sessClauses.push(`(account_id IN ('unknown', 'legacy_unattributed', '') OR era = 'pre_milestone')`);
  } else if (opts.scope === 'pre_milestone') {
    reqClauses.push(`era = 'pre_milestone'`);
    sessClauses.push(`era = 'pre_milestone'`);
  }

  const sessionId = opts.sessionId || opts.session_id;
  if (sessionId) {
    reqClauses.push('session_id = ?');
    reqParams.push(String(sessionId));
    sessClauses.push('session_id = ?');
    sessParams.push(String(sessionId));
  }

  // If no explicit filter was provided, default to re-tagging pre_milestone or unknown accounts
  if (reqClauses.length === 0 && opts.scope !== 'all') {
    reqClauses.push(`(era = 'pre_milestone' OR account_id IN ('unknown', 'legacy_unattributed', ''))`);
    sessClauses.push(`(era = 'pre_milestone' OR account_id IN ('unknown', 'legacy_unattributed', ''))`);
  }

  const reqWhere = reqClauses.length > 0 ? `WHERE ${reqClauses.join(' AND ')}` : '';
  const sessWhere = sessClauses.length > 0 ? `WHERE ${sessClauses.join(' AND ')}` : '';

  let updatedRequests = 0;
  let updatedSessions = 0;

  db.exec('BEGIN');
  try {
    const reqRes = db
      .prepare(
        `UPDATE requests
         SET account_id = ?,
             account_email = CASE WHEN ? != '' THEN ? ELSE account_email END
         ${reqWhere}`
      )
      .run(targetAccountId, emailOrLabel, emailOrLabel, ...reqParams.slice(2));
    updatedRequests = Number(reqRes.changes || 0);

    const sessRes = db
      .prepare(`UPDATE sessions SET account_id = ? ${sessWhere}`)
      .run(...sessParams);
    updatedSessions = Number(sessRes.changes || 0);

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  return {
    ok: true,
    targetAccountId,
    updatedCount: updatedRequests,
    updatedRequests,
    updatedSessions,
    filters: {
      from: opts.from || null,
      to: opts.to || null,
      workspace: opts.workspace || null,
      sourceTool: sourceTool || null,
      era: opts.era || null,
      scope: opts.scope || null,
      oldAccountId: oldAcc || null,
      sessionId: sessionId || null,
    },
  };
}

export const retagRequests = retagLegacy;
