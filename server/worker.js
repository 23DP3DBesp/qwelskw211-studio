import {passwordMode,passwordIdentity,authRoute} from './password-auth.js';
import seed from './seed.json';
import adminHTML from '../admin/index.html?raw';
import defaults from './default-settings.json';
import copyDefaults from '../assets/copy-defaults.json';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const fail=(message,status=400,field)=>{throw Object.assign(new Error(message),{status,field});};
const stmt=(env,sql,...args)=>env.DB.prepare(sql).bind(...args);
const now=()=>new Date().toISOString();
const idPattern=/^[a-z0-9][a-z0-9-]{0,79}$/;
function text(value,max=5000){if(typeof value!=='string'||value.length>max)fail('Invalid text / Некорректный текст');return value.trim();}
function bilingual(value,max){return {en:text(value?.en??'',max),ru:text(value?.ru??'',max)};}
export function safeURL(value,{image=false,video=false}={}){
  value=text(value??'',2000);if(!value)return '';
  if(image){if(/^\/(assets\/images\/[a-zA-Z0-9._-]+|media\/[a-z0-9-]+)$/.test(value))return value;fail('Upload an image / Загрузите изображение');}
  let u;try{u=new URL(value);}catch{fail('Invalid URL / Некорректная ссылка');}
  if(u.protocol!=='https:'||u.username||u.password)fail('Use an HTTPS link / Используйте HTTPS');
  if(video&&!['youtube.com','www.youtube.com','youtu.be','vimeo.com','www.vimeo.com'].includes(u.hostname))fail('Use a YouTube or Vimeo link');
  return u.href;
}
export function validateProject(value){
 if(typeof value.id!=='string'||!idPattern.test(value.id.trim()))fail('Адрес работы: используйте от 1 до 80 строчных латинских букв, цифр и дефисов. Начните с буквы или цифры. Например: my-project.',400,'id');
 if(!['web','design','video'].includes(value.category))fail('Выберите категорию: Web, Design / Photo или Video.',400,'category');
 if(!['draft','published','hidden'].includes(value.status))fail('Выберите статус: черновик, опубликован или скрыт.',400,'status');
 if(!['number','string'].includes(typeof value.position)||String(value.position).trim()===''||!Number.isInteger(Number(value.position))||Number(value.position)<0||Number(value.position)>10000)fail('Порядок: укажите целое число от 0 до 10000, например 0.',400,'position');
 const p={id:text(value.id,80),category:text(value.category,16),status:text(value.status,16),position:Number(value.position),title:bilingual(value.title,160),description:bilingual(value.description,500),result:bilingual(value.result,6000),cover:safeURL(value.cover,{image:true}),gallery:[],video:safeURL(value.video,{video:true}),link:safeURL(value.link),tech:text(value.tech??'',300),concept:value.concept===true};
 if(!Array.isArray(value.gallery)||value.gallery.length>24)fail('Maximum 24 gallery images');p.gallery=value.gallery.map(x=>safeURL(x,{image:true}));
 if(p.status==='published'&&(!p.title.en||!p.title.ru||!p.cover||(!p.result.en&&!p.video&&!p.gallery.length)))fail('Publishing requires EN/RU titles, a cover and a result / Для публикации нужны названия EN/RU, обложка и результат');
 return p;
}
async function init(env){
 if(await stmt(env,'SELECT id FROM settings WHERE id=1').first())return;
 const operations=seed.map(p=>stmt(env,"INSERT OR IGNORE INTO projects (id,data,status,position,revision,updated) SELECT ?,?,?,?,1,? WHERE NOT EXISTS (SELECT 1 FROM settings WHERE id=1)",p.id,JSON.stringify(p),p.status,p.position,now()));
 operations.push(stmt(env,'INSERT OR IGNORE INTO settings (id,data,revision) VALUES (1,?,1)',JSON.stringify(defaults)));
 await env.DB.batch(operations);
}
async function identity(request,env){
 if(passwordMode(env))return passwordIdentity(request,env);
 const id=request.headers.get('oai-authenticated-user-id'),email=request.headers.get('oai-authenticated-user-email');
 if(!id||!email)return null;
 const existing=await stmt(env,'SELECT user_id FROM owner WHERE id=1').first();
 if(existing)return existing.user_id===id?{id,email}:null;
 // One-time enrollment is limited to the verified owner email supplied through Sites.
 // Once enrolled, authorization uses the stable, site-scoped ID, not the email.
 if(!env.ADMIN_OWNER_EMAIL||email.toLowerCase()!==env.ADMIN_OWNER_EMAIL.toLowerCase())return null;
 await stmt(env,'INSERT OR IGNORE INTO owner (id,user_id) VALUES (1,?)',id).run();
 const row=await stmt(env,'SELECT user_id FROM owner WHERE id=1').first();
 return row?.user_id===id?{id,email}:null;
}
function sameOrigin(request){const origin=request.headers.get('Origin');if(origin!==new URL(request.url).origin)fail('Origin rejected',403);if(request.headers.get('Sec-Fetch-Site')==='cross-site')fail('Cross-site request rejected',403);}
async function body(request,max=100000){
 if(Number(request.headers.get('Content-Length'))>max)fail('Request too large',413);
 const reader=request.body?.getReader();if(!reader)fail('Missing body');
 const chunks=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>max){await reader.cancel();fail('Request too large',413);}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
 let value;try{value=JSON.parse(new TextDecoder().decode(bytes));}catch{fail('Invalid JSON');}
 if(!value||Array.isArray(value)||typeof value!=='object')fail('Expected a JSON object');return value;
}
async function upload(request,env){
 const type=request.headers.get('Content-Type')?.split(';')[0];
 if(!['image/jpeg','image/png','image/webp'].includes(type))fail('JPEG, PNG or WebP only');
 if(Number(request.headers.get('Content-Length'))>10*1024*1024)fail('Image limit: 10 MB',413);
 const reader=request.body?.getReader();if(!reader)fail('Empty image');let total=0,chunks=[];
 while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>10*1024*1024){await reader.cancel();fail('Image limit: 10 MB',413);}chunks.push(value);}
 const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
 const png=bytes[0]===137&&bytes[1]===80&&bytes[2]===78&&bytes[3]===71;
 const jpg=bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
 const webp=new TextDecoder().decode(bytes.slice(0,4))==='RIFF'&&new TextDecoder().decode(bytes.slice(8,12))==='WEBP';
 if(!(type==='image/png'&&png||type==='image/jpeg'&&jpg||type==='image/webp'&&webp))fail('File content does not match image type');
 const id=crypto.randomUUID();await env.MEDIA.put(id,bytes,{httpMetadata:{contentType:type}});
 try{await stmt(env,'INSERT INTO media (id,type,name,created) VALUES (?,?,?,?)',id,type,'image',now()).run();}catch(e){await env.MEDIA.delete(id);throw e;}
 return json({url:`/media/${id}`},201);
}
async function inquiry(request,env){
 sameOrigin(request);const value=await body(request,12000);
 if(value.website)return json({ok:true});
 const service=text(value.service,50),description=text(value.description,4000),contact=text(value.contact,300);
 if(!['web','design','filming','editing','photo'].includes(service)||description.length<10||contact.length<3)fail('Complete all fields / Заполните все поля');
 const date=new Date().toISOString().slice(0,10),ip=request.headers.get('CF-Connecting-IP')||'unknown';
 const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(`${date}:${ip}`));const key=Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,'0')).join('');
 const limit=await stmt(env,'INSERT INTO rate_limits (key,count,expires) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count',key,Date.now()+86400000).first();
 if(limit.count>5)fail('Please try tomorrow / Попробуйте завтра',429);
 await env.DB.batch([stmt(env,'INSERT INTO inquiries (id,service,description,contact,status,created) VALUES (?,?,?,?,?,?)',crypto.randomUUID(),service,description,contact,'new',now()),stmt(env,'DELETE FROM rate_limits WHERE expires < ?',Date.now())]);
 return json({ok:true},201);
}
async function handle(request,env){
 const url=new URL(request.url),path=url.pathname,method=request.method;
 if(path.startsWith('/api/')||path.startsWith('/media/')||path==='/admin'||path.startsWith('/admin/')){
 if(!env.DB)fail('Database is unavailable',503);await init(env);
 }
 const authResponse=await authRoute(request,env,{json,fail,body,sameOrigin});if(authResponse)return authResponse;
 if(path==='/api/content'&&method==='GET'){
 const result=await stmt(env,"SELECT data FROM projects WHERE status='published' ORDER BY position,id").all();
 const settings=await stmt(env,'SELECT data FROM settings WHERE id=1').first();return json({projects:result.results.map(r=>JSON.parse(r.data)),settings:JSON.parse(settings.data)});
 }
 if(path==='/api/inquiries'&&method==='POST')return inquiry(request,env);
 if(path.startsWith('/media/')&&method==='GET'){
 const key=path.slice(7);if(!/^[a-f0-9-]{36}$/.test(key))fail('Not found',404);
 const published=await stmt(env,"SELECT data FROM projects WHERE status='published'").all();
 const visible=published.results.some(r=>{const p=JSON.parse(r.data);return p.cover===path||p.gallery?.includes(path);});
 if(!visible&&!await identity(request,env))fail('Not found',404);
 const object=await env.MEDIA.get(key);if(!object)fail('Not found',404);
 return new Response(object.body,{headers:{'Content-Type':object.httpMetadata?.contentType||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
 }
 if(path==='/admin'||path==='/admin/'||path.startsWith('/api/admin')){
 const user=await identity(request,env);
 if(!user){if(path.startsWith('/api/'))return json({error:'Owner access required / Доступ только владельцу'},request.headers.get('oai-authenticated-user-id')?403:401);
 if(passwordMode(env))return Response.redirect(`${url.origin}/admin/login`,302);
 if(!request.headers.get('oai-authenticated-user-id'))return Response.redirect(`${url.origin}/signin-with-chatgpt?return_to=%2Fadmin`,302);
 return new Response('Доступ только владельцу сайта. Войдите в свой аккаунт ChatGPT.',{status:403,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}});}
 if(path==='/admin'||path==='/admin/'){
 const [rows,setting]=await Promise.all([stmt(env,'SELECT * FROM projects ORDER BY position,id').all(),stmt(env,'SELECT * FROM settings WHERE id=1').first()]);
 const bootstrap=JSON.stringify({session:{email:user.email,passwordAuth:passwordMode(env)},projects:rows.results.map(r=>({...JSON.parse(r.data),revision:r.revision})),settings:{...JSON.parse(setting.data),revision:setting.revision},copyDefaults}).replace(/</g,'\\u003c');
 const page=passwordMode(env)?adminHTML.replace('/signin-with-chatgpt?return_to=%2Fadmin','/admin/login').replace('<a href="/signout-with-chatgpt?return_to=/">Выйти</a>','<form action="/api/auth/logout" method="post" class="logout-form"><button type="submit">Выйти</button></form>'):adminHTML;
 return new Response(page.replace('<!--ADMIN_BOOTSTRAP-->',()=>`<script type="application/json" id="admin-bootstrap">${bootstrap}</script>`),{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"}});
 }
 if(method!=='GET')sameOrigin(request);
 if(path==='/api/admin/copy-defaults'&&method==='GET')return json(copyDefaults);
 if(path==='/api/admin/session')return json({email:user.email});
 if(path==='/api/admin/projects'&&method==='GET'){const r=await stmt(env,'SELECT * FROM projects ORDER BY position,id').all();return json(r.results.map(r=>({...JSON.parse(r.data),revision:r.revision})));}
 if(path==='/api/admin/projects'&&method==='DELETE'){
 const value=await body(request,1000),id=text(value.id,80);
 if(!idPattern.test(id)||!Number.isInteger(value.revision)||value.revision<1)fail('Некорректные данные проекта');
 const prior=await stmt(env,'SELECT revision FROM projects WHERE id=?',id).first();
 if(!prior)fail('Работа уже удалена. Обновите список.',404);
 if(prior.revision!==value.revision)fail('Работа изменена в другой вкладке. Обновите страницу перед удалением.',409);
 const deleted=await stmt(env,'DELETE FROM projects WHERE id=? AND revision=?',id,value.revision).run();
 if(!deleted.meta.changes)fail('Работа изменилась. Обновите страницу перед удалением.',409);
 return json({ok:true});
 }
 if(path==='/api/admin/projects'&&method==='POST'){
 const value=await body(request),p=validateProject(value);const prior=await stmt(env,'SELECT revision FROM projects WHERE id=?',p.id).first();
 if(prior){if(value.revision!==prior.revision)fail('Changed in another tab. Reload first. / Изменено в другой вкладке. Обновите страницу.',409);
 const r=await stmt(env,'UPDATE projects SET data=?,status=?,position=?,revision=revision+1,updated=? WHERE id=? AND revision=?',JSON.stringify(p),p.status,p.position,now(),p.id,value.revision).run();if(!r.meta.changes)fail('Conflict / Конфликт изменений',409);
 }else{if(value.revision)fail('Project missing',409);await stmt(env,'INSERT INTO projects (id,data,status,position,revision,updated) VALUES (?,?,?,?,1,?)',p.id,JSON.stringify(p),p.status,p.position,now()).run();}
 return json({ok:true});
 }
 if(path==='/api/admin/settings'&&method==='GET'){const r=await stmt(env,'SELECT * FROM settings WHERE id=1').first();return json({...JSON.parse(r.data),revision:r.revision});}
 if(path==='/api/admin/settings'&&method==='POST'){
 const value=await body(request,250000);const contacts={};for(const key of ['telegram','instagram','github'])contacts[key]=safeURL(value.contacts?.[key]);
 contacts.email=text(value.contacts?.email??'',254);if(contacts.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contacts.email))fail('Invalid email');
 const copy={};if(!value.copy||Array.isArray(value.copy)||typeof value.copy!=='object'||Object.keys(value.copy).length>300)fail('Invalid copy');
 for(const [key,val] of Object.entries(value.copy)){if(key.length>7000||['__proto__','constructor','prototype'].includes(key))fail('Invalid key');copy[key]=bilingual(val,7000);}
 const r=await stmt(env,'UPDATE settings SET data=?,revision=revision+1 WHERE id=1 AND revision=?',JSON.stringify({contacts,copy}),Number(value.revision)).run();if(!r.meta.changes)fail('Settings changed. Reload first. / Настройки изменились. Обновите страницу.',409);return json({ok:true});
 }
 if(path==='/api/admin/upload'&&method==='POST')return upload(request,env);
 if(path==='/api/admin/inquiries'&&method==='GET'){const r=await stmt(env,'SELECT * FROM inquiries ORDER BY created DESC LIMIT 300').all();return json(r.results);}
 if(path==='/api/admin/inquiries'&&method==='POST'){const value=await body(request);if(!['new','read','done'].includes(value.status))fail('Invalid status');await stmt(env,'UPDATE inquiries SET status=? WHERE id=?',value.status,text(value.id,80)).run();return json({ok:true});}
 if(path.startsWith('/api/admin/projects/')&&method==='GET'){
 const r=await stmt(env,'SELECT data FROM projects WHERE id=?',path.split('/').pop()).first();if(!r)fail('Not found',404);return json(JSON.parse(r.data));}
 fail('Not found',404);
 }
 if(path.startsWith('/api/'))fail('Not found',404);
 if(path==='/work'||path==='/work/')return asset(request,env,'/work/index.html');
 // Deny serving source and raw admin HTML through the asset binding.
 if(path.startsWith('/admin/'))fail('Not found',404);
 return asset(request,env,path==='/'?'/index.html':path);
}
async function asset(request,env,path,privatePage=false){
 if(!env.ASSETS)fail('Assets unavailable',503);
 const url=new URL(request.url);url.pathname=path;url.search='';const response=await env.ASSETS.fetch(new Request(url,request));
 const result=new Response(response.body,response);if(privatePage)result.headers.set('Cache-Control','no-store');return result;
}
export default {async fetch(request,env){try{const raw=await handle(request,env);const response=new Response(raw.body,raw);response.headers.set('X-Content-Type-Options','nosniff');response.headers.set('Referrer-Policy','strict-origin-when-cross-origin');return response;}catch(error){return json({error:error.status?error.message:'Server error / Ошибка сервера',...(error.status&&error.field?{field:error.field}:{})},error.status||500);}}};
