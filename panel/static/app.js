const cookie=name=>document.cookie.split('; ').find(x=>x.startsWith(name+'='))?.split('=').slice(1).join('=');
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon=name=>{const shapes={status:'<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/>',key:'<path d="M14 7a5 5 0 1 0 3 9l4-4-3-3-2 2-2-2"/>',activity:'<path d="M4 13h4l2-5 4 9 2-5h4"/>',transfer:'<path d="m8 7 4-4 4 4M12 3v14m4 0-4 4-4-4"/>',check:'<path d="m6 12 4 4 8-9"/>',plus:'<path d="M12 5v14M5 12h14"/>',manage:'<path d="M5 7h14M8 12h8M10 17h4"/>',refresh:'<path d="M20 7v5h-5M19 12a7 7 0 1 0-2 5"/>'};return `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true">${shapes[name]||''}</svg>`};
const state={view:'dashboard',me:null,users:[],admins:[],audit:[],filter:'all',query:''};

async function api(url,options={}){
  options.headers={...options.headers,'X-CSRF-Token':cookie('panel_csrf')||''};
  if(options.body&&!options.headers['content-type']) options.headers['content-type']='application/json';
  const response=await fetch(url,options);
  if(response.status===401){location='/login';throw new Error('Сессия завершена')}
  if(!response.ok){let detail='Не удалось выполнить действие';try{detail=(await response.json()).detail||detail}catch{}throw new Error(detail)}
  return response.status===204?null:response.json();
}

const loginForm=document.querySelector('#login');
if(loginForm) loginForm.addEventListener('submit',async event=>{
  event.preventDefault();
  const button=loginForm.querySelector('button');
  const error=document.querySelector('#error');
  error.textContent='';
  try{
    setBusy(button,true,'Входим…');
    await api('/api/auth/login',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(loginForm)))});
    location='/';
  }catch(exception){
    error.textContent=exception.message;
    setBusy(button,false);
  }
});

const view=document.querySelector('#view');
const titles={dashboard:['Обзор','Состояние прокси и активные подключения'],users:['Подключения','Пользователи, ссылки и ключи доступа'],admins:['Администраторы','Роли и доступ к панели'],audit:['Журнал действий','Изменения, входы и операции с ключами']};
const roleNames={owner:'Владелец',admin:'Администратор',viewer:'Наблюдатель'};
const actionNames={'auth.login':'Вход в панель','auth.logout':'Выход','user.create':'Создан доступ','user.access':'Открыта ссылка','user.enable':'Доступ включён','user.disable':'Доступ заблокирован','user.rotate':'Ключ обновлён','user.delete':'Доступ удалён','admin.create':'Создан администратор','admin.update':'Изменён администратор','admin.delete':'Удалён администратор'};

function toast(message,type='ok'){
  const node=document.createElement('div');node.className='toast '+(type==='error'?'error':'');node.textContent=message;
  document.querySelector('#toast-region').append(node);setTimeout(()=>node.remove(),3200);
}
function setBusy(button,busy,label='Подождите…'){if(!button)return;if(busy){button.dataset.label=button.textContent;button.textContent=label;button.disabled=true}else{button.textContent=button.dataset.label||button.textContent;button.disabled=false}}
function initials(name){return String(name||'?').slice(0,2).toUpperCase()}
function number(value){return new Intl.NumberFormat('ru-RU').format(Number(value)||0)}
function bytes(value){let n=Number(value)||0;for(const unit of ['Б','КБ','МБ','ГБ','ТБ']){if(n<1024)return `${n<10&&unit!=='Б'?n.toFixed(1):Math.round(n)} ${unit}`;n/=1024}return `${n.toFixed(1)} ПБ`}
function date(value){if(!value)return '—';const n=Number(value);const d=new Date(n?(n<1e12?n*1000:n):value);return Number.isNaN(d.valueOf())?'—':d.toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'})}
function skeleton(){view.innerHTML='<div class="skeleton-grid"><i></i><i></i><i></i><i></i></div>'}
function errorState(error){view.innerHTML=`<div class="empty-state"><span>!</span><h3>Не удалось загрузить данные</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`}

async function navigate(name){
  state.view=name;const [title,subtitle]=titles[name];document.querySelector('#title').textContent=title;document.querySelector('#subtitle').textContent=subtitle;
  document.querySelectorAll('[data-view]').forEach(button=>button.classList.toggle('active',button.dataset.view===name));
  const canCreate=state.me?.role!=='viewer'&&(name==='users'||(name==='admins'&&state.me?.role==='owner'));
  const add=document.querySelector('#add');add.hidden=!canCreate;document.querySelector('#add-label').textContent=name==='admins'?'Администратора':'Подключение';
  skeleton();try{if(name==='dashboard')await renderDashboard();if(name==='users')await renderUsers();if(name==='admins')await renderAdmins();if(name==='audit')await renderAudit()}catch(error){errorState(error)}
}

async function refreshUsers(){const data=await api('/api/users');state.users=data.items||[];document.querySelector('#users-count').textContent=state.users.length;return state.users}
async function renderDashboard(){
  const [data,users]=await Promise.all([api('/api/dashboard'),refreshUsers()]);
  const ready=data.health?.ready===true,active=users.filter(x=>x.enabled!==false).length,blocked=users.length-active,connections=data.connections?.active??data.stats?.connections??0,totalBytes=data.stats?.bytes??data.stats?.total_bytes??0;
  const system=document.querySelector('.system-mini');system.classList.toggle('degraded',!ready);system.querySelector('b').textContent=ready?'Telemt работает':'Telemt недоступен';system.querySelector('small').textContent=ready?'Приватный control API':'Проверьте состояние сервиса';
  view.innerHTML=`<div class="metric-grid">
    <article class="metric-card"><div class="metric-head"><span>Состояние</span><span class="metric-icon">${icon('status')}</span></div><strong>${ready?'Работает':'Недоступен'}</strong><p>${ready?'Telemt принимает подключения':'Control API не отвечает'}</p></article>
    <article class="metric-card"><div class="metric-head"><span>Активные доступы</span><span class="metric-icon">${icon('key')}</span></div><strong>${number(active)}</strong><p>${blocked?`${blocked} заблокировано`:'Все доступны'}</p></article>
    <article class="metric-card"><div class="metric-head"><span>Соединения сейчас</span><span class="metric-icon">${icon('activity')}</span></div><strong>${number(connections)}</strong><p>${number(data.active_ips?.length||0)} активных IP</p></article>
    <article class="metric-card"><div class="metric-head"><span>Передано данных</span><span class="metric-icon">${icon('transfer')}</span></div><strong>${bytes(totalBytes)}</strong><p>По данным Telemt</p></article>
  </div><div class="dashboard-grid">
    <section class="panel-card"><div class="panel-head"><h2>Состояние системы</h2><span>обновлено сейчас</span></div><div class="health-hero ${ready?'':'degraded'}"><span class="health-orb">${ready?icon('check'):'!'}</span><span><b>${ready?'Прокси доступен':'Прокси недоступен'}</b><small>${ready?'Control API закрыт внутри Docker-сети':'Telemt health check не пройден'}</small></span></div><div class="service-list"><div class="service-row ${ready?'':'degraded'}"><i></i><span><b>Telemt proxy</b><small>MTProto / FakeTLS</small></span><em>${ready?'healthy':'unavailable'}</em></div><div class="service-row"><i></i><span><b>Web-панель</b><small>${location.protocol==='https:'?'HTTPS · защищённая сессия':'Защищённая сессия'}</small></span><em>online</em></div><div class="service-row"><i></i><span><b>Пользователи</b><small>${active} активных ключей</small></span><em>${blocked?'есть блокировки':'норма'}</em></div></div></section>
    <section class="panel-card"><div class="panel-head"><h2>Быстрые действия</h2><span>управление</span></div><div class="quick-actions">${state.me.role!=='viewer'?`<button class="quick-action" data-quick="add"><span>${icon('plus')}</span><span><b>Новый доступ</b><small>Ссылка и QR-код</small></span></button>`:''}<button class="quick-action" data-quick="users"><span>${icon('manage')}</span><span><b>${state.me.role==='viewer'?'Просмотреть подключения':'Управление ключами'}</b><small>${state.me.role==='viewer'?'Статусы и соединения':'Блокировка и ротация'}</small></span></button><button class="quick-action" data-quick="refresh"><span>${icon('refresh')}</span><span><b>Обновить состояние</b><small>Получить свежую статистику</small></span></button></div></section>
  </div>`;
}

function filteredUsers(){const q=state.query.toLowerCase();return state.users.filter(user=>(state.filter==='all'||(state.filter==='active'&&user.enabled!==false)||(state.filter==='blocked'&&user.enabled===false))&&String(user.username).toLowerCase().includes(q))}
function userRow(user){const enabled=user.enabled!==false;const connections=user.current_connections??user.active_connections??0;return `<div class="data-row" data-name="${esc(user.username)}"><div class="identity"><span class="user-glyph">${esc(initials(user.username))}</span><span><b>${esc(user.username)}</b><small>MTProto · FakeTLS</small></span></div><div class="cell"><span class="status-pill ${enabled?'active':'blocked'}"><i></i>${enabled?'Активен':'Заблокирован'}</span></div><div class="cell"><b>${number(connections)}</b><small> соединений</small></div><div class="row-actions">${state.me.role!=='viewer'?`<button class="action-button share" data-action="share" data-user="${esc(user.username)}">QR и ссылка</button><button class="action-button" data-action="${enabled?'disable':'enable'}" data-user="${esc(user.username)}">${enabled?'Блокировать':'Разблокировать'}</button><button class="action-button" data-action="rotate" data-user="${esc(user.username)}">Новый ключ</button><button class="action-button danger-text" data-action="delete" data-user="${esc(user.username)}">Удалить</button>`:'<span class="cell">Только просмотр</span>'}</div></div>`}
function paintUsers(){const items=filteredUsers();const container=document.querySelector('#user-list');if(!container)return;container.innerHTML=items.length?items.map(userRow).join(''):`<div class="empty-state"><span>◇</span><h3>Подключений не найдено</h3><p>Измените поиск или создайте новый доступ.</p></div>`}
async function renderUsers(){
  await refreshUsers();view.innerHTML=`<div class="toolbar"><div class="search"><input id="user-search" type="search" value="${esc(state.query)}" placeholder="Поиск по имени" aria-label="Поиск пользователей"></div><div class="filter-pills"><button class="filter-pill ${state.filter==='all'?'active':''}" data-filter="all">Все · ${state.users.length}</button><button class="filter-pill ${state.filter==='active'?'active':''}" data-filter="active">Активные</button><button class="filter-pill ${state.filter==='blocked'?'active':''}" data-filter="blocked">Заблокированные</button></div></div><section class="data-panel"><div class="data-head"><span>Пользователь</span><span>Статус</span><span>Сейчас</span><span class="align-right">Действия</span></div><div id="user-list"></div></section>`;paintUsers();
}

async function renderAdmins(){
  const data=await api('/api/admins');state.admins=data.items||[];const activeOwners=state.admins.filter(x=>x.role==='owner'&&x.active).length;view.innerHTML=`<section class="data-panel"><div class="data-head admin-grid"><span>Администратор</span><span>Роль</span><span>Статус</span><span class="align-right">Действия</span></div>${state.admins.map(admin=>{const lastOwner=admin.role==='owner'&&admin.active&&activeOwners===1;return `<div class="data-row admin-grid"><div class="identity"><span class="user-glyph">${esc(initials(admin.username))}</span><span><b>${esc(admin.username)}</b><small>Создан ${date(admin.created_at)}</small></span></div><div class="cell">${esc(roleNames[admin.role]||admin.role)}</div><div class="cell"><span class="status-pill ${admin.active?'active':'blocked'}"><i></i>${admin.active?'Активен':'Отключён'}</span></div><div class="row-actions"><button class="action-button" data-action="edit-admin" data-id="${admin.id}">Настроить</button><button class="action-button" data-action="toggle-admin" data-id="${admin.id}" ${lastOwner?'disabled title="Последнего владельца нельзя отключить"':''}>${admin.active?'Отключить':'Включить'}</button></div></div>`}).join('')}</section>`;
}
async function renderAudit(){const data=await api('/api/audit');state.audit=data.items||[];view.innerHTML=`<section class="data-panel"><div class="audit-list">${state.audit.length?state.audit.map(item=>`<div class="audit-row"><span>${date(item.happened_at)}</span><span>${esc(item.actor_username||'system')}</span><span class="audit-action">${esc(actionNames[item.action]||item.action)}</span><span>${esc(item.target||'—')}</span></div>`).join(''):'<div class="empty-state"><span>≡</span><h3>Журнал пока пуст</h3><p>Здесь появятся действия администраторов.</p></div>'}</div></section>`}

function openUserModal(){document.querySelector('#user-form').reset();document.querySelector('#user-error').textContent='';document.querySelector('#user-modal').showModal();setTimeout(()=>document.querySelector('#new-user').focus(),50)}
function openAdminModal(admin=null){const lastOwner=admin?.role==='owner'&&admin?.active&&state.admins.filter(x=>x.role==='owner'&&x.active).length===1;document.querySelector('#admin-form').reset();document.querySelector('#admin-id').value=admin?.id||'';document.querySelector('#admin-user').value=admin?.username||'';document.querySelector('#admin-user').disabled=Boolean(admin);document.querySelector('#admin-role').value=admin?.role||'viewer';document.querySelector('#admin-role').disabled=lastOwner;document.querySelector('#admin-modal-title').textContent=admin?'Настроить администратора':'Новый администратор';document.querySelector('#password-hint').textContent=admin?'Оставьте пустым, чтобы не менять':'Обязателен для нового администратора';document.querySelector('#delete-admin').hidden=!admin||lastOwner;document.querySelector('#admin-error').textContent=lastOwner?'Последнего активного владельца нельзя отключить, понизить или удалить.':'';document.querySelector('#admin-modal').showModal()}
function confirmed(title,text,button='Продолжить'){const dialog=document.querySelector('#confirm');document.querySelector('#confirm-title').textContent=title;document.querySelector('#confirm-text').textContent=text;document.querySelector('#confirm-ok').textContent=button;dialog.showModal();return new Promise(resolve=>dialog.addEventListener('close',()=>resolve(dialog.returnValue==='default'),{once:true}))}
function showAccess(data,username){document.querySelector('#access-title').textContent=`Доступ · ${username}`;document.querySelector('#access-link').value=data.link;document.querySelector('#qr-image').src=data.qr;document.querySelector('#open-telegram').href=data.link;document.querySelector('#download-qr').href=data.qr;document.querySelector('#download-qr').download=`mtproxy-${username}.svg`;document.querySelector('#access-modal').showModal()}
async function revealToken(token,username){const data=await api('/api/reveal/'+encodeURIComponent(token));showAccess(data,username)}

async function userAction(action,username,button){
  try{
    if(action==='share'){setBusy(button,true,'Загрузка…');const data=await api(`/api/users/${encodeURIComponent(username)}/access`,{method:'POST'});showAccess(data,username);return}
    if(action==='disable'&&!await confirmed('Заблокировать доступ?',`${username} будет отключён, активные соединения будут закрыты.`,`Заблокировать`))return;
    if(action==='enable'&&!await confirmed('Разблокировать доступ?',`${username} снова сможет подключаться к прокси.`,`Разблокировать`))return;
    if(action==='rotate'&&!await confirmed('Создать новый ключ?',`Старая ссылка ${username} перестанет работать. Сохраните новый QR-код после ротации.`,`Обновить ключ`))return;
    if(action==='delete'&&!await confirmed('Удалить подключение?',`${username} будет удалён без возможности восстановления.`,`Удалить`))return;
    setBusy(button,true);
    if(action==='delete')await api(`/api/users/${encodeURIComponent(username)}`,{method:'DELETE'});else{const data=await api(`/api/users/${encodeURIComponent(username)}/${action}`,{method:'POST'});if(action==='rotate')await revealToken(data.reveal_token,username)}
    toast(action==='delete'?'Подключение удалено':action==='disable'?'Доступ заблокирован':action==='enable'?'Доступ разблокирован':'Ключ обновлён');await renderUsers();
  }catch(error){toast(error.message,'error')}finally{setBusy(button,false)}
}

async function init(){
  try{state.me=await api('/api/auth/me');document.querySelector('#profile-name').textContent=state.me.username;document.querySelector('#profile-role').textContent=roleNames[state.me.role]||state.me.role;document.querySelector('#avatar').textContent=initials(state.me.username);document.querySelectorAll('.owner-only').forEach(x=>x.hidden=state.me.role!=='owner');document.querySelectorAll('.audit-nav').forEach(x=>x.hidden=state.me.role==='viewer');await navigate('dashboard')}catch(error){errorState(error)}
}

if(view){
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>navigate(button.dataset.view)));
document.querySelector('#add').addEventListener('click',()=>state.view==='admins'?openAdminModal():openUserModal());
document.querySelector('#refresh').addEventListener('click',event=>{setBusy(event.currentTarget,true,'…');navigate(state.view).finally(()=>setBusy(event.currentTarget,false))});
document.querySelector('#logout').addEventListener('click',async()=>{try{await api('/api/auth/logout',{method:'POST'});location='/login'}catch(error){toast(error.message,'error')}});
document.querySelector('#profile-button').addEventListener('click',()=>toast(`${state.me.username} · ${roleNames[state.me.role]}`));
document.querySelector('#create-user').addEventListener('click',async event=>{const input=document.querySelector('#new-user'),error=document.querySelector('#user-error');error.textContent='';if(!input.reportValidity())return;try{setBusy(event.currentTarget,true,'Создаём…');const data=await api('/api/users',{method:'POST',body:JSON.stringify({username:input.value})});document.querySelector('#user-modal').close();await revealToken(data.reveal_token,input.value);toast('Доступ создан');await refreshUsers();paintUsers()}catch(e){error.textContent=e.message}finally{setBusy(event.currentTarget,false)}});
document.querySelector('#save-admin').addEventListener('click',async event=>{const id=document.querySelector('#admin-id').value,password=document.querySelector('#admin-password').value,error=document.querySelector('#admin-error');error.textContent='';const payload={role:document.querySelector('#admin-role').value};if(password)payload.password=password;if(!id){payload.username=document.querySelector('#admin-user').value;payload.password=password}if(!id&&password.length<12){error.textContent='Пароль должен содержать не менее 12 символов';return}try{setBusy(event.currentTarget,true);await api(id?`/api/admins/${id}`:'/api/admins',{method:id?'PATCH':'POST',body:JSON.stringify(payload)});document.querySelector('#admin-modal').close();toast('Администратор сохранён');await renderAdmins()}catch(e){error.textContent=e.message}finally{setBusy(event.currentTarget,false)}});
document.querySelector('#delete-admin').addEventListener('click',async()=>{const id=document.querySelector('#admin-id').value,admin=state.admins.find(x=>String(x.id)===id);if(!admin||!await confirmed('Удалить администратора?',`${admin.username} потеряет доступ к панели.`,`Удалить`))return;try{await api(`/api/admins/${id}`,{method:'DELETE'});document.querySelector('#admin-modal').close();toast('Администратор удалён');await renderAdmins()}catch(e){toast(e.message,'error')}});
document.querySelector('#copy-link').addEventListener('click',async()=>{const input=document.querySelector('#access-link');try{await navigator.clipboard.writeText(input.value)}catch{input.select();document.execCommand('copy')}toast('Ссылка скопирована')});
document.querySelector('#access-modal').addEventListener('close',()=>{document.querySelector('#access-link').value='';document.querySelector('#qr-image').removeAttribute('src');document.querySelector('#open-telegram').removeAttribute('href');document.querySelector('#download-qr').removeAttribute('href')});

document.querySelector('#view').addEventListener('input',event=>{if(event.target.id==='user-search'){state.query=event.target.value;paintUsers()}});
document.querySelector('#view').addEventListener('click',async event=>{
  const button=event.target.closest('button');if(!button)return;
  if(button.dataset.filter){state.filter=button.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x===button));paintUsers();return}
  if(button.dataset.action==='retry'){navigate(state.view);return}
  if(button.dataset.action&&button.dataset.user){await userAction(button.dataset.action,button.dataset.user,button);return}
  if(button.dataset.action==='edit-admin'){openAdminModal(state.admins.find(x=>String(x.id)===button.dataset.id));return}
  if(button.dataset.action==='toggle-admin'){const admin=state.admins.find(x=>String(x.id)===button.dataset.id);if(!admin||button.disabled||!await confirmed(admin.active?'Отключить администратора?':'Включить администратора?',admin.active?`${admin.username} потеряет доступ, активные сессии будут закрыты.`:`${admin.username} снова сможет войти в панель.`,admin.active?'Отключить':'Включить'))return;try{setBusy(button,true);await api(`/api/admins/${admin.id}`,{method:'PATCH',body:JSON.stringify({active:!admin.active})});toast(admin.active?'Администратор отключён':'Администратор включён');await renderAdmins()}catch(e){toast(e.message,'error')}finally{setBusy(button,false)}return}
  if(button.dataset.quick==='add'){openUserModal();return}if(button.dataset.quick==='users'){navigate('users');return}if(button.dataset.quick==='refresh'){navigate('dashboard')}
});

init();
}

document.querySelector('#mobile-logout')?.addEventListener('click',()=>document.querySelector('#logout').click());
