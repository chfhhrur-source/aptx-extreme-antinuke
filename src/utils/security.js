const { AuditLogEvent, PermissionsBitField, EmbedBuilder, WebhookClient } = require('discord.js');
const { getConfig, safeConfig, isWhitelisted } = require('./db');

const buckets = new Map();
const webhookClient = process.env.ALERT_WEBHOOK_URL && !process.env.ALERT_WEBHOOK_URL.startsWith('PUT_')
  ? new WebhookClient({ url: process.env.ALERT_WEBHOOK_URL })
  : null;

// Returns true only when this event crosses the configured threshold. This prevents
// one burst from repeatedly punishing the same executor on every subsequent event.
function record(guildId, executorId, action, count, windowSec) {
  if (!guildId || !executorId) return false;
  const k = `${guildId}:${executorId}:${action}`;
  const now = Date.now();
  const windowMs = Math.max(1, Number(windowSec)) * 1000;
  const previous = (buckets.get(k) || []).filter(x => now - x < windowMs);
  const before = previous.length;
  previous.push(now);
  const max = Math.max(Number(count) * 3, 100);
  if (previous.length > max) previous.splice(0, previous.length - max);
  buckets.set(k, previous);
  return before < Number(count) && previous.length >= Number(count);
}

async function audit(guild, type, targetId, { minAgeMs = 15000, maxAgeMs = 2500 } = {}) {
  try {
    const types = Array.isArray(type) ? type : [type];
    const now = Date.now();
    const lists = await Promise.all(types.map(t =>
      guild.fetchAuditLogs({ type: t, limit: 10 }).catch(() => null)
    ));
    let best = null;
    for (const l of lists) {
      const entries = l?.entries ? [...l.entries.values()] : [];
      for (const e of entries) {
        const age = now - e.createdTimestamp;
        if (age < -maxAgeMs || age > minAgeMs) continue;
        if (targetId && e.targetId !== targetId) continue;
        if (!best || e.createdTimestamp > best.createdTimestamp) best = e;
      }
    }
    return best;
  } catch {
    return null;
  }
}

async function trusted(guild, id, kind = 'user') {
  if (!id) return true;
  if (id === guild.ownerId) return true;
  if (id === guild.members.me?.id) return true;
  if (process.env.OWNER_ID && !process.env.OWNER_ID.startsWith('PUT_') && id === process.env.OWNER_ID) return true;
  return await isWhitelisted(guild.id, id, kind);
}

async function allowedBotAdder(guild, id) {
  if (!id) return false;
  if (id === guild.ownerId || id === guild.members.me?.id) return true;
  if (process.env.OWNER_ID && !process.env.OWNER_ID.startsWith('PUT_') && id === process.env.OWNER_ID) return true;
  return await isWhitelisted(guild.id, id, 'user');
}

function severityFor(action = '') {
  const a = action.toLowerCase();
  if (a.includes('blocked') || a.includes('unauthorized') || a.includes('escalation') || a.includes('threshold') || a.includes('punish')) return 'CRITICAL';
  if (a.includes('allowed') || a.includes('whitelist')) return 'INFO';
  return 'WARNING';
}
function emojiFor(severity) { return severity === 'CRITICAL' ? '🚨' : severity === 'WARNING' ? '⚠️' : '🛡️'; }

async function sendWebhookAlert(guild, { type = 'security', executorId = null, targetId = null, action, details = '' }) {
  if (!webhookClient) return;
  const severity = severityFor(action);
  const embed = new EmbedBuilder()
    .setTitle(`${emojiFor(severity)} StrangeXUnbypass Security Alert`)
    .setDescription(`**${action}**`)
    .addFields(
      { name: 'Severity', value: `**${severity}**`, inline: true },
      { name: 'Server', value: `${guild.name}\n\`${guild.id}\``, inline: true },
      { name: 'Protection', value: type === 'bot' ? 'Bot Shield' : 'Anti-Nuke', inline: true },
      { name: 'Executor', value: executorId ? `<@${executorId}>\n\`${executorId}\`` : 'Unknown', inline: true },
      { name: 'Target', value: targetId ? `<@${targetId}>\n\`${targetId}\`` : '—', inline: true },
      { name: 'Details', value: String(details || 'No additional details').slice(0, 1024), inline: false },
    ).setFooter({ text: 'StrangeXUnbypass • Automated Security System' }).setTimestamp();
  await webhookClient.send({ username: 'StrangeXUnbypass Security', embeds: [embed], allowedMentions: { parse: [] } }).catch(() => {});
}

async function log(guild, { type = 'security', executorId = null, targetId = null, action, details = '' }) {
  console.log(`[${type}] ${guild.name} ${action} ${details}`);
  if (process.env.DATABASE_URL && !process.env.DATABASE_URL.startsWith('PUT_')) {
    const { prisma } = require('./db');
    await prisma.securityLog.create({ data: { guildId: guild.id, type, executorId, targetId, action, details } }).catch(() => {});
  }
  await sendWebhookAlert(guild, { type, executorId, targetId, action, details });
  const cfg = await safeConfig(guild.id);
  const c = cfg.logChannelId || process.env.LOG_CHANNEL_ID;
  if (c && !String(c).startsWith('PUT_')) {
    const ch = await guild.channels.fetch(c).catch(() => null);
    if (ch?.isTextBased()) await ch.send({ content: `${emojiFor(severityFor(action))} **${action}**\n> **Executor:** ${executorId ? `<@${executorId}>` : 'Unknown'}\n> **Target:** ${targetId ? `<@${targetId}>` : '—'}\n> ${details}`.slice(0, 1900), allowedMentions: { parse: [] } }).catch(() => {});
  }
}

async function punish(guild, member, reason, mode) {
  if (!member || member.id === guild.ownerId || member.id === guild.members.me?.id || !member.manageable) return false;
  try {
    if (mode === 'kick') return await member.kick(reason).then(() => true);
    return await member.ban({ reason, deleteMessageSeconds: 86400 }).then(() => true);
  } catch { return false; }
}
function hasAdministrator(member) { return !!member?.permissions?.has(PermissionsBitField.Flags.Administrator); }

module.exports = { AuditLogEvent, PermissionsBitField, record, audit, trusted, allowedBotAdder, log, punish, hasAdministrator };
