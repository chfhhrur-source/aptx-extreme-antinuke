require('dotenv').config();
const { Client, GatewayIntentBits, Partials } = require('discord.js');
const { registerEvents } = require('./src/events');
const { registerCommands } = require('./src/commands');
const { prisma } = require('./src/utils/db');
if (!process.env.DISCORD_TOKEN) throw new Error('DISCORD_TOKEN is missing');
if (!process.env.DATABASE_URL) console.warn('DATABASE_URL missing: dashboard settings will not sync.');
const client = new Client({ intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMembers,GatewayIntentBits.GuildModeration,GatewayIntentBits.GuildWebhooks,GatewayIntentBits.GuildMessages], partials:[Partials.GuildMember] });
registerEvents(client);
client.once('clientReady', async()=>{
  console.log(`StrangeXUnbypass ONLINE as ${client.user.tag} | ${client.guilds.cache.size} guild(s)`);
  console.log('BotShield checks: GuildMembers intent is enabled in code; also enable Server Members Intent in Discord Developer Portal.');
  for (const guild of client.guilds.cache.values()) {
    const me = guild.members.me;
    const needed = ['KickMembers', 'ViewAuditLog', 'BanMembers'];
    const missing = needed.filter(name => !me?.permissions?.has(name));
    if (missing.length) console.warn(`[BotShield] ${guild.name} (${guild.id}) missing permissions: ${missing.join(', ')}`);
    const botTop = me?.roles?.highest?.position ?? 0;
    const highestTarget = guild.roles.cache.filter(r => r.id !== guild.id).reduce((max, r) => Math.max(max, r.position), 0);
    if (botTop < highestTarget) console.warn(`[BotShield] ${guild.name} (${guild.id}) bot role position=${botTop}; highest server role position=${highestTarget}. The bot cannot moderate roles above its own.`);
  }
  await registerCommands(client);
});
process.on('SIGINT', async()=>{ await prisma.$disconnect().catch(()=>{}); process.exit(0); });
process.on('SIGTERM', async()=>{ await prisma.$disconnect().catch(()=>{}); process.exit(0); });
client.login(process.env.DISCORD_TOKEN);
