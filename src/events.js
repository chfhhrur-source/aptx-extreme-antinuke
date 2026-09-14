const { AuditLogEvent, PermissionsBitField } = require('discord.js');
const { safeConfig, isWhitelisted } = require('./utils/db');
const { record, audit, trusted, allowedBotAdder, log, punish } = require('./utils/security');

const ACTIONS = new Map([
  [AuditLogEvent.ChannelDelete, ['channelDelete','channelDeleteCount','channelDeleteWindow']],
  [AuditLogEvent.ChannelCreate, ['channelCreate','channelCreateCount','channelCreateWindow']],
  [AuditLogEvent.RoleDelete, ['roleDelete','roleDeleteCount','roleDeleteWindow']],
  [AuditLogEvent.RoleCreate, ['roleCreate','roleCreateCount','roleCreateWindow']],
  [AuditLogEvent.MemberBanAdd, ['ban','banCount','banWindow']],
  [AuditLogEvent.MemberKick, ['kick','kickCount','kickWindow']],
]);
const WEBHOOK_ACTIONS = new Set([AuditLogEvent.WebhookCreate, AuditLogEvent.WebhookUpdate, AuditLogEvent.WebhookDelete]);
const auditCache = new Map();
const processed = new Map();
const pendingFallback = new Set();

function cacheKey(entry){ return `${entry.guild?.id || ''}:${entry.action}:${entry.targetId || ''}`; }
function remember(entry){
  if(!entry?.guild?.id) return;
  const key=cacheKey(entry); auditCache.set(key, entry);
  setTimeout(()=>{ if(auditCache.get(key)===entry) auditCache.delete(key); }, 8000).unref?.();
}
function once(entry, ttl=5000){
  const key=`${entry.guild?.id}:${entry.id}`;
  const now=Date.now();
  if(processed.has(key) && now-processed.get(key)<ttl) return false;
  processed.set(key, now);
  setTimeout(()=>processed.delete(key), ttl+1000).unref?.();
  return true;
}

function permissionMask(){
  return [PermissionsBitField.Flags.Administrator,PermissionsBitField.Flags.ManageGuild,PermissionsBitField.Flags.ManageRoles,PermissionsBitField.Flags.ManageWebhooks,PermissionsBitField.Flags.BanMembers,PermissionsBitField.Flags.KickMembers,PermissionsBitField.Flags.ManageChannels];
}
function dangerousRoleChange(entry){
  return !!entry?.changes?.some?.(c => c.key === 'permissions');
}

async function handleAuditEntry(entry, guild){
  if(!entry || !guild || !entry.executorId || !once(entry)) return;
  remember(entry);
  const cfg=await safeConfig(guild.id);
  if(!cfg.antiNuke && entry.action!==AuditLogEvent.BotAdd) return;

  if(entry.action===AuditLogEvent.BotAdd){
    const target=entry.targetId ? await guild.members.fetch(entry.targetId).catch(()=>null) : null;
    if(target?.user?.bot) return botJoin(target, entry);
    return;
  }

  const spec=ACTIONS.get(entry.action);
  if(spec){
    const [key,countKey,windowKey]=spec;
    if(!cfg.antiNuke || await trusted(guild,entry.executorId)) return;
    const count=Math.max(1,Number(cfg[countKey]||3));
    const windowSec=Math.max(1,Number(cfg[windowKey]||10));
    if(!record(guild.id,entry.executorId,key,count,windowSec)) return;
    const member=await guild.members.fetch(entry.executorId).catch(()=>null);
    const ok=await punish(guild,member,`StrangeXUnbypass: ${key} threshold exceeded`,cfg.punishment);
    await log(guild,{executorId:entry.executorId,targetId:entry.targetId||null,action:`Anti-Nuke ${key}`,details:`Threshold ${count}/${windowSec}s exceeded. Punishment: ${ok?cfg.punishment:'failed'}.`});
    return;
  }

  if(entry.action===AuditLogEvent.RoleUpdate){
    const dangerous=dangerousRoleChange(entry);
    const enabled=dangerous ? cfg.permissionChanges!==false : cfg.roleChanges!==false;
    if(!enabled || await trusted(guild,entry.executorId)) return;
    const member=await guild.members.fetch(entry.executorId).catch(()=>null);
    const reason=dangerous?'StrangeXUnbypass: dangerous role permission escalation':'StrangeXUnbypass: unauthorized role update';
    const ok=await punish(guild,member,reason,cfg.punishment);
    await log(guild,{executorId:entry.executorId,targetId:entry.targetId||null,action:dangerous?'Role permission escalation':'Unauthorized role update',details:`Executor punishment=${ok?cfg.punishment:'failed'}.`});
    return;
  }

  if(entry.action===AuditLogEvent.ChannelUpdate){
    if(cfg.channelChanges===false || await trusted(guild,entry.executorId)) return;
    const member=await guild.members.fetch(entry.executorId).catch(()=>null);
    const ok=await punish(guild,member,'StrangeXUnbypass: unauthorized channel update',cfg.punishment);
    await log(guild,{executorId:entry.executorId,targetId:entry.targetId||null,action:'Unauthorized channel update',details:`Executor punishment=${ok?cfg.punishment:'failed'}.`});
    return;
  }

  if(entry.action===AuditLogEvent.GuildUpdate){
    if(cfg.guildChanges===false || await trusted(guild,entry.executorId)) return;
    const member=await guild.members.fetch(entry.executorId).catch(()=>null);
    const ok=await punish(guild,member,'StrangeXUnbypass: unauthorized guild setting change',cfg.punishment);
    await log(guild,{executorId:entry.executorId,targetId:guild.id,action:'Guild setting change',details:`Executor punishment=${ok?cfg.punishment:'failed'}.`});
    return;
  }

  if(WEBHOOK_ACTIONS.has(entry.action)){
    if(!cfg.antiNuke || await trusted(guild,entry.executorId)) return;
    const count=Math.max(1,Number(cfg.webhookCount||3));
    const windowSec=Math.max(1,Number(cfg.webhookWindow||10));
    if(!record(guild.id,entry.executorId,'webhook',count,windowSec)) return;
    const member=await guild.members.fetch(entry.executorId).catch(()=>null);
    const ok=await punish(guild,member,'StrangeXUnbypass: webhook change threshold exceeded',cfg.punishment);
    await log(guild,{executorId:entry.executorId,targetId:entry.targetId||null,action:'Anti-Nuke webhook change',details:`Audit action=${entry.action}. Threshold ${count}/${windowSec}s exceeded. Punishment=${ok?cfg.punishment:'failed'}.`});
  }
}

async function botJoin(member, auditEntry=null){
  if(!member?.user?.bot) return;
  const guild=member.guild;
  const key=`${guild.id}:${member.id}`;
  if(pendingFallback.has(key)) return;
  pendingFallback.add(key);
  setTimeout(()=>pendingFallback.delete(key),8000).unref?.();
  const cfg=await safeConfig(guild.id);
  if(cfg.botProtection===false) return;
  const entry=auditEntry || auditCache.get(`${guild.id}:${AuditLogEvent.BotAdd}:${member.id}`) || await audit(guild,AuditLogEvent.BotAdd,member.id,{minAgeMs:3000,maxAgeMs:500});
  const botAllowed=await isWhitelisted(guild.id,member.id,'bot');
  const inviterId=entry?.executorId||null;
  const inviterAllowed=inviterId ? await allowedBotAdder(guild,inviterId) : false;
  if(botAllowed||inviterAllowed){
    await log(guild,{type:'bot',executorId:inviterId,targetId:member.id,action:'Whitelisted bot allowed',details:botAllowed?'Bot ID is allowlisted.':'Bot was added by an approved member/owner.'});
    return;
  }
  const removed=member.kickable ? await member.kick('StrangeXUnbypass: unauthorized bot addition').then(()=>true).catch(()=>false) : false;
  if(!entry||!inviterId){
    await log(guild,{type:'bot',targetId:member.id,action:removed?'Unauthorized bot blocked':'Unauthorized bot removal failed',details:'Audit-log executor unavailable. No human punishment applied.'});
    return;
  }
  const executor=await guild.members.fetch(inviterId).catch(()=>null);
  const punished=await punish(guild,executor,'StrangeXUnbypass: unauthorized bot addition',cfg.punishment);
  await log(guild,{type:'bot',executorId:inviterId,targetId:member.id,action:'Unauthorized bot blocked',details:`Bot removed=${removed}. Executor punishment=${punished?cfg.punishment:'failed'}.`});
}

async function fallback(guild, action, targetId){
  const k=`${guild.id}:${action}:${targetId||''}`;
  if(pendingFallback.has(k)) return;
  pendingFallback.add(k);
  setTimeout(async()=>{
    pendingFallback.delete(k);
    const entry=auditCache.get(`${guild.id}:${action}:${targetId||''}`) || await audit(guild,action,targetId,{minAgeMs:2500,maxAgeMs:250});
    if(entry) await handleAuditEntry(entry,guild);
  },180).unref?.();
}

async function registerEvents(client){
  client.on('guildAuditLogEntryCreate',(entry,guild)=>handleAuditEntry(entry,guild).catch(console.error));
  client.on('guildMemberAdd',member=>{ if(member.user?.bot) botJoin(member).catch(console.error); });
  client.on('channelDelete',c=>fallback(c.guild,AuditLogEvent.ChannelDelete,c.id));
  client.on('channelCreate',c=>fallback(c.guild,AuditLogEvent.ChannelCreate,c.id));
  client.on('roleDelete',r=>fallback(r.guild,AuditLogEvent.RoleDelete,r.id));
  client.on('roleCreate',r=>fallback(r.guild,AuditLogEvent.RoleCreate,r.id));
  client.on('guildBanAdd',b=>fallback(b.guild,AuditLogEvent.MemberBanAdd,b.user.id));
  client.on('guildMemberRemove',m=>fallback(m.guild,AuditLogEvent.MemberKick,m.id));
  client.on('roleUpdate',(oldRole,newRole)=>fallback(newRole.guild,AuditLogEvent.RoleUpdate,newRole.id));
  client.on('channelUpdate',(oldChannel,newChannel)=>fallback(newChannel.guild,AuditLogEvent.ChannelUpdate,newChannel.id));
  client.on('guildUpdate',g=>fallback(g,AuditLogEvent.GuildUpdate,g.id));
  client.on('webhookUpdate',c=>fallback(c.guild,AuditLogEvent.WebhookUpdate,null));
  client.on('error',console.error);
}
module.exports={registerEvents};
