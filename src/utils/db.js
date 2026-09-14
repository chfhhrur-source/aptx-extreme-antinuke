const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const defaults={antiNuke:true,botProtection:true,punishment:'ban',permissionChanges:true,roleChanges:true,channelChanges:true,guildChanges:true,channelDeleteCount:3,channelDeleteWindow:10,channelCreateCount:6,channelCreateWindow:10,roleDeleteCount:3,roleDeleteWindow:10,roleCreateCount:6,roleCreateWindow:10,banCount:3,banWindow:10,kickCount:3,kickWindow:10,webhookCount:3,webhookWindow:10};

async function getConfig(guildId){
  if(!process.env.DATABASE_URL || process.env.DATABASE_URL.startsWith('PUT_')) return {guildId,...defaults,whitelist:[]};
  return prisma.guildConfig.upsert({where:{guildId},update:{},create:{guildId},include:{whitelist:true}});
}
async function safeConfig(guildId){
  try { return await getConfig(guildId); }
  catch (e) { console.error(`[DB] getConfig failed for ${guildId}:`, e?.message || e); return {guildId,...defaults,whitelist:[]}; }
}
async function isWhitelisted(guildId,userId,kind='user'){
  if(!process.env.DATABASE_URL || process.env.DATABASE_URL.startsWith('PUT_')) return false;
  try { return !!(await prisma.guildWhitelist.findUnique({where:{guildId_userId_kind:{guildId,userId,kind}}})); }
  catch { return false; }
}
module.exports={prisma,defaults,getConfig,safeConfig,isWhitelisted};
