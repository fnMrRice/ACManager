(function () {
  'use strict';
  window.acDisconnectTerminal=function(vm,row){
    if(document.getElementById('ac-terminal-disconnect'))return;
    function node(p,tag,text){var n=document.createElement(tag);if(text!==undefined)n.textContent=text;p.appendChild(n);return n;}
    var d=node(document.body,'dialog');d.id='ac-terminal-disconnect';
    Object.assign(d.style,{width:'480px',maxWidth:'90vw',padding:'26px',border:'1px solid #bdcdd5',borderRadius:'6px'});
    node(d,'h2','断开终端');node(d,'p',(row.name||row.mac)+' · '+row.mac);
    node(d,'p','将断开此终端当前的 Wi-Fi 连接。终端仍可重新连接；需要禁止接入时，请使用黑名单。');
    var status=node(d,'p',''),cancel=node(d,'button','取消'),save=node(d,'button','断开');status.setAttribute('role','status');
    [cancel,save].forEach(function(b){Object.assign(b.style,{padding:'8px 18px',margin:'16px 12px 0 0'});});
    var busy=false;function close(){if(!busy){d.close();d.remove();}}
    cancel.onclick=close;d.addEventListener('cancel',function(e){e.preventDefault();close();});
    save.onclick=async function(){busy=true;save.disabled=cancel.disabled=true;status.textContent='等待 AP 确认…';
      try{var r=await fetch('/api/terminals/disconnect',{method:'POST',headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify({macs:[row.mac]})});
        var data=await r.json();if(!r.ok||data.error)throw Error(data.error||'断开失败');
        status.textContent='AP 已确认断开请求。';busy=false;cancel.disabled=false;cancel.textContent='关闭';vm.$refs.grid.refreshData();
      }catch(e){status.textContent=e.message;busy=false;cancel.disabled=false;vm.$refs.grid.refreshData();}
    };d.showModal();
  };
  async function admissionApi(path,body){
    var r=await fetch('/api/blacklist/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body||{})});
    var data=await r.json();if(!r.ok||data.error)throw Error(data.error||'操作失败');return data;
  }
  window.acLoadAdmission=async function(vm){try{vm.admissionAps=(await admissionApi('status')).aps;}catch(e){vm.admissionMessage=e.message;}};
  window.acAdmissionPanel=function(vm,h){
    return h('div',{style:{marginBottom:'20px',padding:'14px',background:'#f3f8fa'}},[
      h('p',['黑名单用于向本 AC 请求接入许可的 AP。为目标 AP 开启接入检查后生效。']),
      h('details',[h('summary',['AP 接入检查状态']),h('div',vm.admissionAps.map(function(ap){return h('label',{style:{display:'block',padding:'6px'}},[
        h('input',{attrs:{type:'checkbox',disabled:!ap.online||vm.admissionBusy,'aria-label':'检查 '+ap.ip},domProps:{checked:vm.admissionSelected.includes(ap.mac)},on:{change:function(e){vm.admissionSelected=e.target.checked?vm.admissionSelected.concat(ap.mac):vm.admissionSelected.filter(function(m){return m!==ap.mac;});}}}),
        ' '+ap.name+' / '+ap.ip+' · '+({acknowledged:'AP 已确认',waiting_rejoin:'等待重新下发',not_configured:'未开启'}[ap.status]||ap.status)+(ap.online?'':' · 离线')+' · 接入请求 '+ap.requests+' / 已拒绝 '+ap.denials
      ]);}))]),
      h('button',{attrs:{type:'button',disabled:vm.admissionBusy||!vm.admissionSelected.length},on:{click:async function(){vm.admissionBusy=true;vm.admissionMessage='正在开启接入检查…';
        try{await admissionApi('enable-admission',{macs:vm.admissionSelected});vm.admissionMessage='所选 AP 已确认接入检查。';}
        catch(e){vm.admissionMessage=e.message;}finally{vm.admissionBusy=false;window.acLoadAdmission(vm);}
      }}},['为所选 AP 开启接入检查']),h('p',{attrs:{role:'status'}},[vm.admissionMessage])
    ]);
  };
  window.acExportBlacklist=function(){
    var link=document.createElement('a');
    link.href='/stok='+encodeURIComponent(sessionStorage.getItem('stok'))+'/admin/host_management/sta_blacklist_backup';
    link.download='blacklist.csv';document.body.appendChild(link);link.click();link.remove();
  };
  window.acImportBlacklist=function(vm){
    if(document.getElementById('ac-blacklist-import'))return;
    function node(p,tag,text){var n=document.createElement(tag);if(text!==undefined)n.textContent=text;p.appendChild(n);return n;}
    async function api(path,body){var r=await fetch('/api/blacklist/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body)});var data=await r.json();if(!r.ok||data.error)throw Error(data.error||'操作失败');return data;}
    var d=node(document.body,'dialog');d.id='ac-blacklist-import';
    Object.assign(d.style,{width:'620px',maxWidth:'90vw',padding:'26px',border:'1px solid #bdcdd5',borderRadius:'6px'});
    node(d,'h2','导入终端黑名单');node(d,'p','导入的 MAC 将禁止接入已开启接入检查的 AP；已连接到受管 AP 的终端会被断开。');
    var template=node(d,'a','下载 CSV 模板');template.href='/stok='+encodeURIComponent(sessionStorage.getItem('stok'))+'/admin/host_management/export_blacklist_template';template.download='blacklist-template.csv';
    var file=node(d,'input');file.type='file';file.accept='.csv,text/csv';file.setAttribute('aria-label','黑名单 CSV');file.style.display='block';file.style.marginTop='16px';
    var status=node(d,'p','选择文件后预览'),list=node(d,'ul');status.setAttribute('role','status');
    var cancel=node(d,'button','取消'),save=node(d,'button','确认导入');save.disabled=true;
    [cancel,save].forEach(function(b){Object.assign(b.style,{padding:'8px 18px',margin:'16px 12px 0 0'});});
    var csv='',busy=false,version=0;
    function close(){if(!busy){d.close();d.remove();}}
    cancel.onclick=close;d.addEventListener('cancel',function(e){e.preventDefault();close();});
    file.onchange=async function(){var current=++version;save.disabled=true;list.replaceChildren();
      try{if(!file.files[0])return;if(file.files[0].size>131072)throw Error('文件不能超过 128 KB');
        var text=await file.files[0].text(),data=await api('import-preview',{csv:text});if(current!==version)return;csv=text;
        data.items.forEach(function(r){node(list,'li',r.mac+' · '+r.hostname);});status.textContent='共 '+data.items.length+' 条规则';save.disabled=false;
      }catch(e){if(current===version)status.textContent=e.message;}
    };
    save.onclick=async function(){busy=true;save.disabled=cancel.disabled=file.disabled=true;status.textContent='正在生效并处理在线终端…';
      try{await api('import',{csv:csv});busy=false;close();vm.$refs.grid.refreshData();}
      catch(e){status.textContent=e.message;busy=false;cancel.disabled=file.disabled=false;vm.$refs.grid.refreshData();}
    };d.showModal();
  };
  window.acExportTerminals = function () {
    var link = document.createElement('a');
    link.href = '/stok=' + encodeURIComponent(sessionStorage.getItem('stok')) + '/admin/host_management/host_info_backup';
    link.download = 'terminals.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
  };
  window.acLoadTopology = async function (vm) {
    if (vm._acMonitorBusy) return;
    vm._acMonitorBusy = true;
    vm.loading = true;
    vm.monitorError = '';
    var controller = new AbortController();
    vm._acMonitorAbort = controller;
    var timeout = setTimeout(function () { controller.abort(); }, 12000);
    try {
      var response = await fetch('/api/topology', {
        method:'POST', credentials:'same-origin', signal:controller.signal,
        headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},
        body:JSON.stringify({dev_type:vm.devType})
      });
      if (response.status === 401) { location.assign('/login'); return; }
      var data = await response.json();
      if (!response.ok || data.error) throw new Error(data.error || '读取失败');
      if (vm._acMonitorDisposed) return;
      // The firmware canvas skips drawing while its loading prop is true.
      // Flush that prop before init schedules its own nextTick callback.
      vm.loading = false;
      await vm.$nextTick();
      if (vm._acMonitorDisposed) return;
      vm.$refs.topo.init({getTopology:data});
      await vm.$nextTick();
      if (vm._acMonitorDisposed) return;
      vm.$refs.topo.spreadTypeChange();
      vm.refreshTime = new Date().toLocaleString();
      vm.monitorSummary = data.ap_count + ' 台 AP · ' + data.client_count + ' 台在线终端';
    } catch (error) {
      if (!vm._acMonitorDisposed) vm.monitorError = '拓扑刷新失败：' + (error.name === 'AbortError' ? '请求超时，请重试' : error.message);
    } finally {
      clearTimeout(timeout);
      vm._acMonitorBusy = false;
      if (!vm._acMonitorDisposed) vm.loading = false;
    }
  };
})();
