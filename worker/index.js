const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{"Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store", ...headers}});
const now = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const randomToken = (n=32) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const sha = async (s) => b64u(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s)));
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const cors = (req,env) => {
  const origin=req.headers.get("Origin");
  const allowed=env.APP_ORIGIN;
  const h={"Vary":"Origin","Access-Control-Allow-Methods":"GET,POST,PUT,OPTIONS","Access-Control-Allow-Headers":"Content-Type,X-CSRF-Token","Access-Control-Allow-Credentials":"true"};
  if(origin && origin===allowed) h["Access-Control-Allow-Origin"]=origin;
  return h;
};
function cookie(req,name){const raw=req.headers.get("Cookie")||"";const m=raw.match(new RegExp("(?:^|;\\s*)"+name+"=([^;]*)"));return m?decodeURIComponent(m[1]):"";}
function setCookie(token,days){return `dr_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${days*86400}`;}
function clearCookie(){return "dr_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";}
async function body(req){try{return await req.json()}catch{return {}}}
function validEmail(v){return typeof v==="string"&&v.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);}
function text(v,max){return typeof v==="string"?v.trim().slice(0,max):"";}
async function passwordHash(password,salt){const key=await crypto.subtle.importKey("raw",enc(password),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64u(salt),iterations:310000,hash:"SHA-256"},key,256);return b64u(bits);}
async function makePassword(password){const salt=randomToken(16);return {salt,hash:await passwordHash(password,salt)};}
async function verifyPassword(password,user){if(!user.password_hash||!user.password_salt)return false;const actual=await passwordHash(password,user.password_salt);return actual===user.password_hash;}
async function audit(env,user,action,type,id,details=""){await env.DB.prepare("INSERT INTO audit_logs(id,actor_user_id,actor_email,action,object_type,object_id,details,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(uuid(),user?.id||null,user?.email||"System",action,type,id||null,details,now()).run();}
async function sessionUser(req,env){
  const token=cookie(req,"dr_session");if(!token)return null;
  const hash=await sha(token);
  const row=await env.DB.prepare("SELECT s.id AS session_id,s.csrf_hash,s.expires_at,u.id,u.email,u.name,u.role,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?").bind(hash).first();
  if(!row||!row.active||row.expires_at<now())return null;
  return row;
}
async function requireCsrf(req,user){const token=req.headers.get("X-CSRF-Token")||"";return !!token && await sha(token)===user.csrf_hash;}
function requireRole(user,role){const r={viewer:1,editor:2,admin:3};return (r[user.role]||0)>=(r[role]||99);}
async function createSession(req,env,user){
  const token=randomToken(),csrf=randomToken(),days=Math.max(1,Math.min(7,Number(env.SESSION_DAYS)||1));
  await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,csrf_hash,expires_at,created_at,user_agent) VALUES(?,?,?,?,?,?,?)").bind(uuid(),user.id,await sha(token),await sha(csrf),new Date(Date.now()+days*86400000).toISOString(),now(),req.headers.get("User-Agent")||"").run();
  return {token,csrf,days};
}
function userPublic(u){return {id:u.id,email:u.email,name:u.name,role:u.role,active:!!u.active,created_at:u.created_at};}
async function getUser(env,id){return env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();}
async function parseJwt(token){const p=token.split(".");if(p.length!==3)throw Error("Invalid identity token");return JSON.parse(dec(unb64u(p[1])));}
async function verifyJwt(token,issuer,clientId){
  const parts=token.split(".");if(parts.length!==3)throw Error("Invalid identity token");
  const header=JSON.parse(dec(unb64u(parts[0]))),payload=JSON.parse(dec(unb64u(parts[1])));
  if(header.alg!=="RS256"||!header.kid)throw Error("Unsupported identity token");
  const jwks=await fetch(issuer.replace(/\/$/,"")+"/v1/keys",{cf:{cacheTtl:300,cacheEverything:true}});
  if(!jwks.ok)throw Error("Could not retrieve identity keys");
  const keys=(await jwks.json()).keys;const jwk=keys.find(k=>k.kid===header.kid);if(!jwk)throw Error("Unknown signing key");
  const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
  const valid=await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,Uint8Array.from(atob(parts[2].replace(/-/g,"+").replace(/_/g,"/")+"==".slice((parts[2].length+2)%4)),c=>c.charCodeAt(0)),enc(parts[0]+"."+parts[1]));
  if(!valid||payload.iss!==issuer||payload.aud!==clientId||payload.exp<Date.now()/1000||payload.iat>Date.now()/1000+60||!payload.sub)throw Error("Identity token validation failed");
  return payload;
}
async function handle(req,env){
  const url=new URL(req.url),path=url.pathname,method=req.method;
  if(method==="OPTIONS")return new Response(null,{status:204,headers:cors(req,env)});
  const headers=cors(req,env);
  if(path==="/api/health")return json({ok:true,service:"document-registry-api"},200,headers);
  if(path==="/api/setup"&&method==="GET"){
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first();
    if(count.n===0&&env.BOOTSTRAP_ADMIN_EMAIL&&env.BOOTSTRAP_ADMIN_PASSWORD){
      const email=env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase();
      if(validEmail(email)&&env.BOOTSTRAP_ADMIN_PASSWORD.length>=12){
        const p=await makePassword(env.BOOTSTRAP_ADMIN_PASSWORD),t=now();
        await env.DB.prepare("INSERT OR IGNORE INTO users(id,email,name,role,password_hash,password_salt,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)").bind(uuid(),email,"Registry Administrator","admin",p.hash,p.salt,t,t).run();
      }
    }
    return json({ok:true},200,headers);
  }
  if(path==="/api/login"&&method==="POST"){
    const b=await body(req),email=text(b.email,254).toLowerCase(),password=String(b.password||"");
    const recent=await env.DB.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE email_key=? AND attempted_at>datetime('now','-15 minutes')").bind(email).first();
    if(recent.n>=10)return json({error:"Too many sign-in attempts. Try again later."},429,headers);
    const u=await env.DB.prepare("SELECT * FROM users WHERE email=? AND active=1").bind(email).first();
    const ok=u&&await verifyPassword(password,u);
    await env.DB.prepare("INSERT INTO login_attempts(id,email_key,attempted_at,succeeded) VALUES(?,?,?,?)").bind(uuid(),email,now(),ok?1:0).run();
    if(!ok)return json({error:"Email or password is incorrect."},401,headers);
    const s=await createSession(req,env,u);await audit(env,u,"login","user",u.id,"Native password login");
    return json({user:userPublic(u),csrfToken:s.csrf},200,{...headers,"Set-Cookie":setCookie(s.token,s.days)});
  }
  if(path==="/auth/okta"&&method==="GET"){
    if(!env.OKTA_ISSUER||!env.OKTA_CLIENT_ID||!env.OKTA_REDIRECT_URI)return json({error:"Okta is not configured."},503);
    const state=randomToken(24),nonce=randomToken(24),verifier=randomToken(48),challenge=b64u(await crypto.subtle.digest("SHA-256",enc(verifier)));
    const authorize=new URL(env.OKTA_ISSUER.replace(/\/$/,"")+"/v1/authorize");
    authorize.searchParams.set("client_id",env.OKTA_CLIENT_ID);authorize.searchParams.set("response_type","code");authorize.searchParams.set("scope",env.OKTA_SCOPES||"openid profile email");
    authorize.searchParams.set("redirect_uri",env.OKTA_REDIRECT_URI);authorize.searchParams.set("state",state);authorize.searchParams.set("nonce",nonce);
    authorize.searchParams.set("code_challenge",challenge);authorize.searchParams.set("code_challenge_method","S256");
    return new Response(null,{status:302,headers:{"Location":authorize.toString(),"Set-Cookie":[`okta_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,`okta_nonce=${nonce}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,`okta_verifier=${verifier}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`]}});
  }
  if(path==="/auth/okta/callback"&&method==="GET"){
    try{
      const state=cookie(req,"okta_state"),nonce=cookie(req,"okta_nonce"),verifier=cookie(req,"okta_verifier");
      if(!state||state!==url.searchParams.get("state")||!nonce||!verifier)throw Error("Invalid SSO state");
      const form=new URLSearchParams({grant_type:"authorization_code",code:url.searchParams.get("code")||"",redirect_uri:env.OKTA_REDIRECT_URI,client_id:env.OKTA_CLIENT_ID,code_verifier:verifier});
      const tokenRes=await fetch(env.OKTA_ISSUER.replace(/\/$/,"")+"/v1/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",...(env.OKTA_CLIENT_SECRET?{"Authorization":"Basic "+btoa(env.OKTA_CLIENT_ID+":"+env.OKTA_CLIENT_SECRET)}:{})},body:form});
      if(!tokenRes.ok)throw Error("Okta token exchange failed");
      const tokens=await tokenRes.json(),claims=await verifyJwt(tokens.id_token,env.OKTA_ISSUER,env.OKTA_CLIENT_ID);
      if(claims.nonce!==nonce||!claims.email||claims.email_verified!==true)throw Error("Okta email or nonce validation failed");
      const existing=await env.DB.prepare("SELECT u.* FROM users u LEFT JOIN user_identities i ON i.user_id=u.id AND i.provider='okta' WHERE u.email=? AND u.active=1").bind(String(claims.email).toLowerCase()).first();
      if(!existing)throw Error("No active local account is linked to this Okta email. Ask an administrator to create the account first.");
      const linked=await env.DB.prepare("SELECT id FROM user_identities WHERE provider='okta' AND subject=?").bind(claims.sub).first();
      if(linked&&linked.id!==existing.id)throw Error("This Okta identity is linked to another account.");
      await env.DB.prepare("INSERT OR IGNORE INTO user_identities(id,user_id,provider,subject,email,created_at) VALUES(?,?,?,?,?,?)").bind(uuid(),existing.id,"okta",claims.sub,String(claims.email).toLowerCase(),now()).run();
      const s=await createSession(req,env,existing);await audit(env,existing,"login","user",existing.id,"Okta OIDC login");
      return new Response(null,{status:302,headers:{"Location":env.APP_ORIGIN,"Set-Cookie":[setCookie(s.token,s.days),"okta_state=; Path=/; Max-Age=0","okta_nonce=; Path=/; Max-Age=0","okta_verifier=; Path=/; Max-Age=0"]}});
    }catch(e){return new Response(`<h2>Okta sign-in failed</h2><p>${String(e.message).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]))}</p><p><a href="${env.APP_ORIGIN}">Return to sign in</a></p>`,{status:401,headers:{"Content-Type":"text/html; charset=utf-8"}});}
  }
  const user=await sessionUser(req,env);
  if(path==="/api/me"&&method==="GET"){
    if(!user)return json({error:"Not signed in"},401,headers);
    const raw=randomToken(24),hash=await sha(raw);
    await env.DB.prepare("UPDATE sessions SET csrf_hash=? WHERE id=?").bind(hash,user.session_id).run();
    return json({user:{id:user.id,email:user.email,name:user.name,role:user.role},csrfToken:raw},200,headers);
  }
  if(path==="/api/logout"&&method==="POST"){
    if(user){if(!await requireCsrf(req,user))return json({error:"Invalid CSRF token"},403,headers);await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(user.session_id).run();await audit(env,user,"logout","user",user.id);}
    return json({ok:true},200,{...headers,"Set-Cookie":clearCookie()});
  }
  if(!user)return json({error:"Authentication required"},401,headers);
  if(!await requireCsrf(req,user))return json({error:"Invalid CSRF token"},403,headers);
  if(path==="/api/password"&&method==="POST"){
    const b=await body(req),u=await getUser(env,user.id);
    if(!await verifyPassword(String(b.currentPassword||""),u))return json({error:"Current password is incorrect."},400,headers);
    const next=String(b.newPassword||"");if(next.length<12)return json({error:"New password must be at least 12 characters."},400,headers);
    const p=await makePassword(next);await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,updated_at=? WHERE id=?").bind(p.hash,p.salt,now(),u.id).run();
    await audit(env,user,"password_changed","user",u.id);return json({ok:true},200,headers);
  }
  if(path==="/api/groups"&&method==="GET"){
    const result=await env.DB.prepare("SELECT * FROM document_groups ORDER BY archived_at IS NOT NULL,name").all();
    return json({groups:result.results},200,headers);
  }
  if(path==="/api/groups"&&method==="POST"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const b=await body(req),name=text(b.name,100),description=text(b.description,500);
    if(!name)return json({error:"Group name is required"},400,headers);
    const id=uuid();try{await env.DB.prepare("INSERT INTO document_groups(id,name,description,created_at,updated_at,created_by) VALUES(?,?,?,?,?,?)").bind(id,name,description,now(),now(),user.id).run();}catch{return json({error:"A group with that name may already exist."},409,headers);}
    await audit(env,user,"group_created","group",id,name);return json({id},201,headers);
  }
  let m=path.match(/^\/api\/groups\/([^/]+)$/);
  if(m&&method==="PUT"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const b=await body(req),name=text(b.name,100),description=text(b.description,500);if(!name)return json({error:"Group name is required"},400,headers);
    try{await env.DB.prepare("UPDATE document_groups SET name=?,description=?,updated_at=? WHERE id=? AND archived_at IS NULL").bind(name,description,now(),m[1]).run();}catch{return json({error:"Group name already exists."},409,headers);}
    await audit(env,user,"group_updated","group",m[1],name);return json({ok:true},200,headers);
  }
  m=path.match(/^\/api\/groups\/([^/]+)\/archive$/);
  if(m&&method==="POST"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    await env.DB.prepare("UPDATE document_groups SET archived_at=?,updated_at=? WHERE id=?").bind(now(),now(),m[1]).run();
    await audit(env,user,"group_archived","group",m[1]);return json({ok:true},200,headers);
  }
  if(path==="/api/documents"&&method==="GET"){
    const status=url.searchParams.get("status")||"active";
    let sql="SELECT d.*,u.email AS created_by_email FROM documents d LEFT JOIN users u ON u.id=d.created_by";
    if(status==="active")sql+=" WHERE d.archived_at IS NULL";else if(status==="archived")sql+=" WHERE d.archived_at IS NOT NULL";
    sql+=" ORDER BY d.created_at DESC LIMIT 1000";
    const result=await env.DB.prepare(sql).all();return json({documents:result.results},200,headers);
  }
  if(path==="/api/documents"&&method==="POST"){
    if(!requireRole(user,"editor"))return json({error:"Editor permission required"},403,headers);
    const b=await body(req),name=text(b.name,240),author=text(b.author,160),group=text(b.group_id,64),notes=text(b.notes,5000);
    if(!name||!author||!group)return json({error:"Document name, author and group are required."},400,headers);
    const g=await env.DB.prepare("SELECT id FROM document_groups WHERE id=? AND archived_at IS NULL").bind(group).first();if(!g)return json({error:"Select an active group."},400,headers);
    const year=new Date().getUTCFullYear(),prefix=text(env.ID_PREFIX||"DOC",12).replace(/[^A-Za-z0-9_-]/g,"")||"DOC";
    // D1 batch executes the sequence allocation and insert as one transaction.
    const current=await env.DB.prepare("SELECT last_value FROM id_sequences WHERE year=?").bind(year).first();
    const next=(current?.last_value||0)+1;
    const docId=`${prefix}-${year}-${String(next).padStart(6,"0")}`,id=uuid(),t=now();
    try{
      await env.DB.batch([
        env.DB.prepare("INSERT INTO id_sequences(year,last_value) VALUES(?,?) ON CONFLICT(year) DO UPDATE SET last_value=excluded.last_value").bind(year,next),
        env.DB.prepare("INSERT INTO documents(id,document_id,sequence_year,sequence_number,name,author,group_id,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)").bind(id,docId,year,next,name,author,group,notes,user.id,t,t)
      ]);
    }catch(e){return json({error:"Could not allocate a document ID. Please retry."},409,headers);}
    await audit(env,user,"document_created","document",id,docId);return json({id,document_id:docId},201,headers);
  }
  m=path.match(/^\/api\/documents\/([^/]+)$/);
  if(m&&method==="GET"){
    const d=await env.DB.prepare("SELECT d.*,u.email AS created_by_email FROM documents d LEFT JOIN users u ON u.id=d.created_by WHERE d.id=?").bind(m[1]).first();
    return d?json({document:d},200,headers):json({error:"Document not found"},404,headers);
  }
  if(m&&method==="PUT"){
    if(!requireRole(user,"editor"))return json({error:"Editor permission required"},403,headers);
    const b=await body(req),name=text(b.name,240),author=text(b.author,160),group=text(b.group_id,64),notes=text(b.notes,5000);
    if(!name||!author||!group)return json({error:"Document name, author and group are required."},400,headers);
    const g=await env.DB.prepare("SELECT id FROM document_groups WHERE id=? AND archived_at IS NULL").bind(group).first();if(!g)return json({error:"Select an active group."},400,headers);
    await env.DB.prepare("UPDATE documents SET name=?,author=?,group_id=?,notes=?,updated_at=? WHERE id=? AND archived_at IS NULL").bind(name,author,group,notes,now(),m[1]).run();
    await audit(env,user,"document_updated","document",m[1]);return json({ok:true},200,headers);
  }
  m=path.match(/^\/api\/documents\/([^/]+)\/(archive|restore)$/);
  if(m&&method==="POST"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const archived=m[2]==="archive"?now():null;
    await env.DB.prepare("UPDATE documents SET archived_at=?,updated_at=? WHERE id=?").bind(archived,now(),m[1]).run();
    await audit(env,user,archived?"document_archived":"document_restored","document",m[1]);return json({ok:true},200,headers);
  }
  if(path==="/api/users"&&method==="GET"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const result=await env.DB.prepare("SELECT u.id,u.email,u.name,u.role,u.active,u.created_at,EXISTS(SELECT 1 FROM user_identities i WHERE i.user_id=u.id AND i.provider='okta') AS has_okta FROM users u ORDER BY u.created_at").all();
    return json({users:result.results.map(u=>({...u,active:!!u.active,has_okta:!!u.has_okta}))},200,headers);
  }
  if(path==="/api/users"&&method==="POST"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const b=await body(req),email=text(b.email,254).toLowerCase(),name=text(b.name,120),password=String(b.password||""),role=b.role;
    if(!validEmail(email)||!name||password.length<12||!["admin","editor","viewer"].includes(role))return json({error:"Provide a valid email, name, role and password of at least 12 characters."},400,headers);
    const p=await makePassword(password),id=uuid(),t=now();
    try{await env.DB.prepare("INSERT INTO users(id,email,name,role,password_hash,password_salt,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)").bind(id,email,name,role,p.hash,p.salt,t,t).run();}catch{return json({error:"An account with that email already exists."},409,headers);}
    await audit(env,user,"user_created","user",id,email);return json({id},201,headers);
  }
  m=path.match(/^\/api\/users\/([^/]+)$/);
  if(m&&method==="PUT"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const b=await body(req);if(m[1]===user.id&&b.active===false)return json({error:"You cannot disable your own account."},400,headers);
    if(typeof b.active!=="boolean")return json({error:"An active boolean is required."},400,headers);
    await env.DB.prepare("UPDATE users SET active=?,updated_at=? WHERE id=?").bind(b.active?1:0,now(),m[1]).run();
    if(!b.active)await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(m[1]).run();
    await audit(env,user,b.active?"user_enabled":"user_disabled","user",m[1]);return json({ok:true},200,headers);
  }
  if(path==="/api/audit"&&method==="GET"){
    if(!requireRole(user,"admin"))return json({error:"Admin permission required"},403,headers);
    const result=await env.DB.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500").all();return json({logs:result.results},200,headers);
  }
  return json({error:"Not found"},404,headers);
}
export default {async fetch(req,env){try{
  if(!env.APP_ORIGIN)return json({error:"APP_ORIGIN is not configured"},500);
  const origin=req.headers.get("Origin");
  if(origin&&origin!==env.APP_ORIGIN)return json({error:"Origin not allowed"},403);
  return await handle(req,env);
}catch(e){return json({error:"Internal server error",detail:env.ENVIRONMENT==="development"?String(e.stack||e):undefined},500,cors(req,env));}}};
