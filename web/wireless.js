(function () {
  'use strict';
  async function api(path,body) {
    var r=await fetch('/api/wireless/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body||{})});
    var v=await r.json();if(!r.ok||v.error)throw Error(v.error||'操作失败');return v;
  }
  function node(p,tag,text){var n=document.createElement(tag);if(text!==undefined)n.textContent=text;p.appendChild(n);return n;}
  function button(p,text,click){var b=node(p,'button',text);b.type='button';b.onclick=click;Object.assign(b.style,{padding:'7px 14px',margin:'8px 8px 8px 0',cursor:'pointer'});return b;}
  function dialog(title,onClose){
    var d=node(document.body,'dialog');Object.assign(d.style,{width:'900px',maxWidth:'92vw',maxHeight:'85vh',overflow:'auto',padding:'24px',border:'1px solid #bdcdd5',borderRadius:'6px',color:'#243746'});
    node(d,'h2',title);var s=node(d,'p','读取中…');s.setAttribute('role','status');
    var content=node(d,'div'),busy=false;
    function close(){if(!busy){d.close();d.remove();if(onClose)onClose();}}
    var cancel=button(d,'关闭',close);d.addEventListener('cancel',function(e){e.preventDefault();close();});d.showModal();
    return {d:d,status:s,content:content,close:close,busy:function(v){busy=v;cancel.disabled=v;}};
  }
  function targets(p,rows){var list=node(p,'ul');rows.forEach(function(r){node(list,'li',r.ap_name+' · '+r.ip+' · '+r.mac+' · 射频 '+r.radio+' / WLAN '+r.wlan+' / VLAN '+r.vlan);});}
  window.acWirelessInventory=async function(entryId){
    var box=dialog('AP 现有 SSID / 密码');
    button(box.d,'刷新清单',load);
    async function load(){
      try {
        var v=await api('inventory',entryId?{entry_id:String(entryId)}:{});
        box.status.textContent='选择“从 AP 读取”可读取该 AP 当前的 SSID 和密码；读取后可修改指定服务。刷新清单不会下发修改。';
        box.content.replaceChildren();var table=node(box.content,'table');table.style.width='100%';table.style.borderCollapse='collapse';
        var head=node(table,'tr');['AP / IP','频段','SSID','配置来源','密码','操作'].forEach(function(t){node(head,'th',t);});
        v.items.forEach(function(row){
          var tr=node(table,'tr');[row.ap_name+' / '+row.ip+(row.status==='1'?'':'（离线，历史记录）'),row.freq_name,row.ssid,row.source_label,row.password_state].forEach(function(t){var td=node(tr,'td',t);Object.assign(td.style,{padding:'10px 6px',borderBottom:'1px solid #e2e8eb'});});
          var td=node(tr,'td');var read=button(td,'从 AP 读取',function(){window.acReadApWireless(row.mac);});read.disabled=row.status!=='1';
          if(row.source==='controller_saved'&&row.editable)button(td,'编辑共享服务',function(){window.acEditWireless(row.serv_id,load);});
        });
        if(!v.items.length)node(box.content,'p','尚未收到无线服务清单。');
      }catch(e){box.status.textContent=e.message;}
    }
    await load();
  };
  window.acSyncWireless=async function(vm){
    var box=dialog('同步 AP 原有服务');box.busy(true);var done=0,failed=[];
    try{
      var inventory=await api('inventory'),aps=inventory.aps.filter(function(a){return a.online;});
      for(var ap of aps){
        box.status.textContent='读取 '+ap.ip+'（'+(done+failed.length+1)+' / '+aps.length+'）…';
        try{await api('read-ap',{mac:ap.mac});done++;}
        catch(e){failed.push(ap.ip+'：'+e.message);}
        vm.$refs.grid.refreshData();
      }
      box.status.textContent='已同步 '+done+' 台 AP；同步未下发任何配置。'+(failed.length?' '+failed.length+' 台读取失败，保留上次记录。':'');
      failed.forEach(function(s){node(box.content,'p',s);});
    }catch(e){box.status.textContent=e.message;}
    box.busy(false);
  };
  window.acReadApWireless=async function(mac,section,onClose){
    var box=dialog('AP 无线配置',onClose),refresh=button(box.d,'重新读取',load);
    var security={'0':'开放网络','1':'WPA-PSK / WPA2-PSK','2':'WPA / WPA2 企业认证','3':'WPA2-PSK / WPA3-SAE'};
    function render(v){
      box.content.replaceChildren();box.status.textContent=v.ap_name+' · '+v.ip+' · '+v.mac+'；以下名称、密码及安全配置均从此 AP 读取。';
      var items=section?v.items.filter(function(row){return row.section===section;}):v.items;
      if(!items.length)node(box.content,'p','此服务已不在 AP 当前配置中，请关闭后刷新列表。');
      items.forEach(function(row){
        var card=node(box.content,'section');Object.assign(card.style,{padding:'14px',margin:'12px 0',border:'1px solid #dbe5ea'});
        node(card,'h3',row.ssid);node(card,'p','射频 '+row.radio+' · '+(security[row.encryption]||'未知安全模式')+' · VLAN '+row.vlan+' · '+(row.hidden?'隐藏 SSID':'广播 SSID')+' · '+(row.enable==='on'?'启用':'停用'));
        if(['1','3'].includes(String(row.encryption))){
          var key=node(card,'input');key.type='password';key.value=row.key;key.readOnly=true;key.setAttribute('aria-label',row.ssid+' 当前密码');key.style.padding='8px';
          var label=node(card,'label'),show=node(label,'input');show.type='checkbox';node(label,'span',' 显示密码');show.onchange=function(){key.type=show.checked?'text':'password';};
        }
        var edit=button(card,'修改此服务',function(){editRow(v,row);});edit.disabled=!row.editable;
        if(row.reason)node(card,'p',row.reason);
      });
    }
    async function load(){
      refresh.disabled=true;box.busy(true);box.status.textContent='正在从 AP 读取配置…';
      try{render(await api('read-ap',{mac:mac}));}catch(e){box.status.textContent=e.message;}
      box.busy(false);refresh.disabled=false;
    }
    function editRow(v,row){
      var edit=dialog('修改 '+row.ssid);edit.status.textContent=v.ip+' · '+v.mac+' · 射频 '+row.radio+'；仅修改下面改动的字段，保留加密方式、VLAN、MLO 及其他服务。';
      function field(title,value,type){var l=node(edit.content,'label',title);Object.assign(l.style,{display:'block',margin:'16px 0'});var f=node(l,'input');f.type=type;f.value=value;Object.assign(f.style,{display:'block',padding:'8px',width:'100%'});return f;}
      var ssid=field('SSID',row.ssid,'text'),key=field('密码',row.key,'password');key.disabled=!['1','3'].includes(String(row.encryption));
      if(!key.disabled){var l=node(edit.content,'label'),show=node(l,'input');show.type='checkbox';node(l,'span',' 显示密码');show.onchange=function(){key.type=show.checked?'text':'password';};}
      node(edit.content,'p','更改 SSID 或密码会让此服务的终端重新连接。保存前会备份原配置，保存后会重新读取并核对。');
      var save=button(edit.d,'保存到此 AP',async function(){
        var changes={};if(ssid.value!==row.ssid)changes.ssid=ssid.value;if(!key.disabled&&key.value!==row.key)changes.key=key.value;
        if(!Object.keys(changes).length){edit.status.textContent='没有修改，未下发配置。';return;}
        edit.busy(true);save.disabled=ssid.disabled=key.disabled=true;edit.status.textContent='重新核对原配置并保存，等待 AP 回读确认…';
        try{var result=await api('edit-ap',{mac:mac,section:row.section,revision:v.revision,changes:changes});edit.status.textContent=result.message;if(result.current)render(result.current);}
        catch(e){edit.status.textContent=e.message+'；请关闭后重新读取。';}
        edit.busy(false);
      });
    }
    await load();
  };
  window.acEditWireless=async function(servId,refresh){
    var box=dialog('查看 / 修改无线服务');
    try {
      var v=await api('profile',{serv_id:String(servId)}),p=v.profile;
      box.status.textContent=v.source==='ap_readback'?'配置来源：AP 回读合并；保存会逐个核对并更新下面的已有射频绑定。':'配置来源：本控制器保存。此处的密码并非从 AP 回读。';
      function field(label,value,type){var l=node(box.content,'label',label);Object.assign(l.style,{display:'block',margin:'14px 0'});var input=node(l,'input');input.type=type||'text';input.value=value;Object.assign(input.style,{display:'block',width:'100%',padding:'8px',marginTop:'6px'});return input;}
      var ssid=field('SSID',p.ssid),key=field('密码',p.key||'','password');
      var isOpen=String(p.encryption)==='0',hasKey=['1','3'].includes(String(p.encryption));key.disabled=!hasKey;
      if(isOpen)node(box.content,'p','开放网络；加密方式请在无线服务编辑页面设置。');
      else if(hasKey) {var l=node(box.content,'label'),check=node(l,'input');check.type='checkbox';node(l,'span',' 显示已保存密码');check.onchange=function(){key.type=check.checked?'text':'password';};}
      node(box.content,'p',v.targets.length?'保存将更新以下绑定；其他 SSID 保持不变。修改名称或密码会让此服务的终端重新连接。':'尚未绑定 AP；保存后可从无线服务的“射频绑定”批量选择目标。');
      targets(box.content,v.targets);
      var save=button(box.d,'保存并下发',async function(){
        var changes={};if(ssid.value!==p.ssid)changes.ssid=ssid.value;
        if(hasKey&&key.value!==(p.key||''))changes.key=key.value;
        if(!Object.keys(changes).length){box.status.textContent='没有修改，未下发配置。';return;}
        box.busy(true);save.disabled=ssid.disabled=key.disabled=true;box.status.textContent='保存中，等待 AP 确认…';
        try{var result=await api('edit',{serv_id:String(servId),revision:v.revision,changes:changes});box.status.textContent=result.message;box.busy(false);if(refresh)refresh();}
        catch(e){box.status.textContent=e.message+'；请关闭后重新读取。';box.busy(false);if(refresh)refresh();}
      });
    }catch(e){box.status.textContent=e.message;}
  };
  window.acBindWireless=async function(vm,request){
    var box=dialog('预览射频绑定',function(){vm.$refs.grid.refreshData();});
    try {
      var plan=await api('bind-preview',{request:request});
      box.status.textContent='SSID：'+plan.ssid+'；共 '+plan.items.length+' 个射频。'+(plan.enabled?'新增使用空闲 WLAN 编号，保留原有服务。':'仅解除所列 AP 上本服务的绑定。');
      targets(box.content,plan.items);var list=node(box.content,'ul');plan.items.forEach(function(r){node(list,'li',r.ip+' / 射频 '+r.radio+'：'+r.action);});
      if(!plan.items.length)return;
      var save=button(box.d,'确认'+(plan.enabled?'绑定':'解绑'),async function(){
        box.busy(true);save.disabled=true;box.status.textContent='逐项下发，等待 AP 确认…';
        try{await api('bind',{request:request,revision:plan.revision});box.status.textContent='AP 已确认所选绑定操作。';}
        catch(e){box.status.textContent=e.message+'；请关闭并刷新列表，核对各 AP 的实际结果。';}
        box.busy(false);vm.$refs.grid.refreshData();
      });
    }catch(e){box.status.textContent=e.message;vm.$refs.grid.refreshData();}
  };
})();
