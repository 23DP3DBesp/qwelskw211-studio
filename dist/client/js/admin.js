'use strict';
const $=s=>document.querySelector(s),esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let projects=[],settings,copyDefaults={},editing=null,gallery=[],dirty=false,settingsDirty=false,uploading=0;
const statusLabels={draft:'Черновик',published:'Опубликован',hidden:'Скрыт'};
const api=(path,options={})=>portfolioAPI('/api/admin/'+path,options);
const notify=message=>$('#status').textContent=message;
function field(name){return $('#project-form').elements.namedItem(name);}
async function loadProjects(data){projects=data??await api('projects');$('#project-list').innerHTML=projects.length?projects.map(p=>`<article class="project-row"><img src="${esc(p.cover)}" alt=""><div><h3>${esc(p.title.ru||p.title.en||p.id)}</h3><small>${esc(p.category)} · порядок ${p.position}</small> <span class="badge">${statusLabels[p.status]}</span></div><div class="project-actions"><button data-edit="${esc(p.id)}">Редактировать</button><button type="button" class="danger" data-delete="${esc(p.id)}" aria-label="Удалить ${esc(p.title.ru||p.title.en||p.id)}">Удалить</button></div></article>`).join(''):'<p>Добавьте первую работу.</p>';}
function showGallery(){$('#gallery-editor').innerHTML=gallery.map((url,i)=>`<div class="gallery-item"><img src="${esc(url)}" alt="Фото ${i+1}"><button type="button" data-remove="${i}">Убрать</button>${i?`<button type="button" data-up="${i}" aria-label="Переместить фото ${i+1} раньше">←</button>`:''}</div>`).join('');}
function openEditor(p){editing=p||null;$('#project-form').reset();gallery=[...(p?.gallery||[])];for(const name of ['id','category','status','position','cover','video','link','tech'])field(name).value=p?.[name]??({category:'web',status:'draft',position:projects.length}[name]??'');for(const name of ['title','description','result'])for(const lang of ['en','ru'])field(`${name}_${lang}`).value=p?.[name]?.[lang]||'';field('concept').checked=!!p?.concept;field('id').readOnly=!!p;$('#editor-title').textContent=p?'Редактировать проект':'Новый проект';$('#cover-preview').hidden=!p?.cover;$('#cover-preview').src=p?.cover||'';$('#editor-status').textContent='';$('#preview-project').hidden=!p;$('#preview-project').href=p?`/work/?id=${encodeURIComponent(p.id)}&preview=1&lang=ru`:'#';showGallery();dirty=false;$('#editor').showModal();}
$('#new-project').onclick=()=>openEditor();
$('#project-list').onclick=async e=>{
 const remove=e.target.closest('[data-delete]');
 if(remove){
  if(remove.disabled)return;
  const project=projects.find(p=>p.id===remove.dataset.delete);if(!project)return;
  const title=project.title.ru||project.title.en||project.id;
  if(!confirm(`Удалить работу «${title}»? Она исчезнет с сайта и из списка проектов. Это действие нельзя отменить.`))return;
  remove.disabled=true;remove.setAttribute('aria-busy','true');
  try{
   const result=await api('projects',{method:'DELETE',body:JSON.stringify({id:project.id,revision:project.revision})});
   if(result.ok!==true)throw new Error('Сервер не подтвердил удаление. Обновите список.');
   await loadProjects(projects.filter(p=>p.id!==project.id));notify(`Работа «${title}» удалена.`);
  }catch(error){notify(error.message);}
  finally{remove.disabled=false;remove.removeAttribute('aria-busy');}
  return;
 }
 const edit=e.target.closest('[data-edit]');if(edit)openEditor(projects.find(p=>p.id===edit.dataset.edit));
};
function closeEditor(){if(uploading){$('#editor-status').textContent='Дождитесь загрузки файлов.';return;}if(dirty&&!confirm('Закрыть без сохранения изменений?'))return;$('#editor').close();}
$('#close-editor').onclick=closeEditor;$('#editor').addEventListener('cancel',e=>{e.preventDefault();closeEditor();});$('#project-form').addEventListener('input',()=>dirty=true);
$('#gallery-editor').onclick=e=>{const r=e.target.closest('[data-remove]'),u=e.target.closest('[data-up]');if(r)gallery.splice(Number(r.dataset.remove),1);if(u){const i=Number(u.dataset.up);[gallery[i-1],gallery[i]]=[gallery[i],gallery[i-1]];}if(r||u){dirty=true;showGallery();}};
async function upload(file){if(file.size>10*1024*1024)throw new Error('Максимум 10 МБ на изображение');return (await api('upload',{method:'POST',headers:{'Content-Type':file.type},body:file})).url;}
async function uploadFiles(input,isCover){uploading++;$('#save-project').disabled=true;$('#editor-status').textContent='Загружаю изображения…';try{const files=[...input.files];if(!isCover&&gallery.length+files.length>24)throw new Error('В галерее максимум 24 фотографии');for(const file of files){const url=await upload(file);if(isCover){field('cover').value=url;$('#cover-preview').src=url;$('#cover-preview').hidden=false;}else gallery.push(url);dirty=true;}showGallery();$('#editor-status').textContent='Изображения загружены. Сохраните проект.';}catch(e){$('#editor-status').textContent=e.message;}finally{input.value='';uploading--;$('#save-project').disabled=uploading>0;}}
$('#cover-upload').onchange=e=>uploadFiles(e.target,true);$('#gallery-upload').onchange=e=>uploadFiles(e.target,false);
$('#project-form').onsubmit=async e=>{e.preventDefault();if(uploading)return;if(!editing)field('id').value=field('id').value.trim().toLowerCase();if(!$('#project-form').reportValidity())return;const data={};for(const name of ['id','category','status','cover','video','link','tech'])data[name]=field(name).value;data.position=Number(field('position').value);data.revision=editing?.revision;data.gallery=gallery;data.concept=field('concept').checked;for(const name of ['title','description','result'])data[name]={en:field(`${name}_en`).value,ru:field(`${name}_ru`).value};$('#save-project').disabled=true;try{await api('projects',{method:'POST',body:JSON.stringify(data)});dirty=false;await loadProjects();editing=projects.find(p=>p.id===data.id);field('id').readOnly=true;$('#editor-status').textContent='Сохранено. '+(data.status==='published'?'Работа доступна на сайте.':'Работа видна только вам.');$('#preview-project').hidden=false;$('#preview-project').href=`/work/?id=${encodeURIComponent(data.id)}&preview=1&lang=ru`;}catch(error){$('#editor-status').textContent=error.message;if(error.field)field(error.field)?.focus();}finally{$('#save-project').disabled=false;}};
async function loadSettings(data,copy){settings=data??await api('settings');copyDefaults=copy??await api('copy-defaults');$('#contact-fields').innerHTML=['telegram','instagram','github','email'].map(key=>`<label>${key.toUpperCase()}<input data-contact="${key}" type="${key==='email'?'email':'url'}" value="${esc(settings.contacts[key])}"></label>`).join('');$('#copy-fields').innerHTML=Object.entries(copyDefaults).map(([en,ru],i)=>`<div class="copy-row" data-copy-row="${i}"><p>${esc(en)}</p><div class="field-grid"><label>EN<textarea data-copy="${i}" data-copy-lang="en" rows="2">${esc(settings.copy[en]?.en??en)}</textarea></label><label>RU<textarea data-copy="${i}" data-copy-lang="ru" rows="2">${esc(settings.copy[en]?.ru??ru)}</textarea></label></div></div>`).join('');settingsDirty=false;}
$('#copy-search').oninput=e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('.copy-row').forEach(row=>row.hidden=![row.textContent,...[...row.querySelectorAll('textarea')].map(t=>t.value)].join(' ').toLowerCase().includes(q));};
$('#settings-form').addEventListener('input',e=>{if(e.target.id!=='copy-search')settingsDirty=true;});
$('#settings-form').onsubmit=async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const contacts={},copy={};document.querySelectorAll('[data-contact]').forEach(input=>contacts[input.dataset.contact]=input.value);const keys=Object.keys(copyDefaults);document.querySelectorAll('[data-copy]').forEach(input=>{const key=keys[input.dataset.copy];copy[key]??={};copy[key][input.dataset.copyLang]=input.value;});await api('settings',{method:'POST',body:JSON.stringify({contacts,copy,revision:settings.revision})});settings=await api('settings');settingsDirty=false;notify('Тексты, услуги и контакты сохранены.');}catch(error){notify(error.message);}finally{button.disabled=false;}};
async function loadInquiries(){const rows=await api('inquiries');const labels={web:'Сайт',design:'Дизайн',filming:'Видеосъёмка',editing:'Видеомонтаж',photo:'Фотоуслуги'};$('#inquiry-list').innerHTML=rows.length?rows.map(r=>`<article class="inquiry-row"><div><span class="label">${labels[r.service]} · ${esc(new Date(r.created).toLocaleString('ru'))}</span><p>${esc(r.description)}</p><strong>${esc(r.contact)}</strong></div><label>Статус<select data-inquiry="${r.id}">${Object.entries({new:'Новая',read:'Прочитана',done:'Обработана'}).map(([v,l])=>`<option value="${v}" ${v===r.status?'selected':''}>${l}</option>`).join('')}</select></label></article>`).join(''):'<p>Заявок пока нет.</p>';}
$('#inquiry-list').onchange=async e=>{if(!e.target.dataset.inquiry)return;e.target.disabled=true;try{await api('inquiries',{method:'POST',body:JSON.stringify({id:e.target.dataset.inquiry,status:e.target.value})});notify('Статус заявки сохранён.');}catch(error){notify(error.message);await loadInquiries();}finally{e.target.disabled=false;}};
document.querySelectorAll('[data-tab]').forEach(button=>button.onclick=async()=>{document.querySelectorAll('[data-tab]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));for(const name of ['projects','settings','inquiries'])$('#'+name+'-panel').hidden=name!==button.dataset.tab;try{if(button.dataset.tab==='inquiries')await loadInquiries();}catch(error){notify(error.message);}});
window.addEventListener('beforeunload',e=>{if(dirty||settingsDirty){e.preventDefault();e.returnValue='';}});
async function initializeAdmin(useBootstrap=false){
 const retry=$('#retry-load');retry.disabled=true;retry.setAttribute('aria-busy','true');$('#load-recovery').hidden=true;
 try{
  const bootstrap=useBootstrap?JSON.parse($('#admin-bootstrap')?.textContent||'null'):null;
  const session=bootstrap?.session??await api('session');$('#account').textContent=session.email;
  const results=await Promise.allSettled([loadProjects(bootstrap?.projects),loadSettings(bootstrap?.settings,bootstrap?.copyDefaults)]);
  const errors=results.filter(r=>r.status==='rejected').map(r=>r.reason.message);
  notify(errors.join('\n'));$('#load-recovery').hidden=!errors.length;
 }catch(error){notify(error.message);$('#load-recovery').hidden=false;}
 finally{retry.disabled=false;retry.removeAttribute('aria-busy');}
}
$('#retry-load').onclick=()=>initializeAdmin();
initializeAdmin(true);
