(function () {
  'use strict';
  async function api(path,body) {
    var response=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json',
      'X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body||{})});
    if(response.status===401){location.assign('/login');throw Error('请重新登录');}
    var data=await response.json();if(!response.ok||data.error)throw Error(data.error||'操作失败');return data;
  }
  function node(parent,tag,text) {
    var e=document.createElement(tag);if(text!==undefined)e.textContent=text;parent.appendChild(e);return e;
  }
  window.acRadioColumns=[
    {label:'AP 名称',name:'apName',minWidth:150}, {label:'分组',name:'groupName',minWidth:100},
    {label:'频段',name:'freqName',minWidth:90},{label:'信道',name:'channel',minWidth:70},
    {label:'带宽',name:'bandwidth',minWidth:90,format:function(v){return {'0':'20 MHz','1':'40 MHz','2':'自动','3':'80 MHz','4':'80+80 MHz','5':'160 MHz','6':'240 MHz'}[v]||'未读取';}},
    {label:'信道占用',name:'channelLoad',minWidth:85,format:function(v){return v==null?'—':v+'%';}},
    {label:'已设功率',name:'powerDbm',minWidth:90,format:function(v){return v==null?'—':v+' dBm';}},
    {label:'状态',name:'apStatus',minWidth:75,format:function(v){return v==='1'?'在线':'离线';}},
    {label:'射频开关',name:'rfState',minWidth:85,filterAble:false}
  ];
  window.acExportRadios=function(){
    var a=node(document.body,'a');a.href='/stok='+encodeURIComponent(sessionStorage.getItem('stok'))+'/admin/apmng_rf/backup_rf';
    a.download='radios.csv';a.click();a.remove();
  };
  window.acImportRadios=function(vm){
    if(document.getElementById('ac-radio-import'))return;
    var d=node(document.body,'dialog');d.id='ac-radio-import';
    Object.assign(d.style,{width:'650px',maxWidth:'90vw',padding:'26px',border:'1px solid #bdcdd5',borderRadius:'6px'});
    node(d,'h2','导入射频配置');node(d,'p','使用导出的 CSV 文件；空白参数保持不变。');
    var file=node(d,'input');file.type='file';file.accept='.csv,text/csv';file.setAttribute('aria-label','射频配置 CSV');
    var status=node(d,'p','选择文件后预览');status.setAttribute('role','status');var preview=node(d,'div');
    var cancel=node(d,'button','取消'),save=node(d,'button','确认下发');save.disabled=true;
    [cancel,save].forEach(function(b){Object.assign(b.style,{padding:'8px 18px',margin:'16px 12px 0 0'});});
    var text='',busy=false;
    function close(){if(!busy){d.close();d.remove();}}
    cancel.onclick=close;d.addEventListener('cancel',function(e){e.preventDefault();close();});
    file.onchange=async function(){save.disabled=true;preview.replaceChildren();text='';
      try {
        if(!file.files[0])return;if(file.files[0].size>65536)throw Error('文件不能超过 64 KB');
        text=await file.files[0].text();var result=await api('radios/import-preview',{csv:text});
        var list=node(preview,'ul');result.items.forEach(function(item){node(list,'li',item.ap_name+' · '+item.ip+' · 射频 '+item.radio+'：'+Object.entries(item.changes).map(function(kv){return ({channel:'信道',power_dbm:'功率(dBm)',rf_state:'开关'}[kv[0]]||kv[0])+'='+kv[1];}).join('，'));});
        status.textContent='共 '+result.items.length+' 项待下发';save.disabled=false;
      }catch(error){status.textContent=error.message;}
    };
    save.onclick=async function(){busy=true;save.disabled=cancel.disabled=file.disabled=true;status.textContent='正在逐项下发并核对…';
      try{await api('radios/import',{csv:text});busy=false;close();vm.$refs.grid.refreshData();}
      catch(error){status.textContent=error.message;busy=false;cancel.disabled=file.disabled=false;vm.$refs.grid.refreshData();}
    };d.showModal();
  };
  window.acEditRadio=async function(rows,refresh) {
    if(!rows.length||document.getElementById('ac-radio-editor'))return;
    var dialog=document.createElement('dialog');dialog.id='ac-radio-editor';
    Object.assign(dialog.style,{width:'480px',maxWidth:'90vw',padding:'26px',border:'1px solid #bdcdd5',borderRadius:'6px',color:'#243746'});
    document.body.appendChild(dialog);dialog.showModal();
    node(dialog,'h2',rows.length===1?'射频设置':'批量射频设置');
    var status=node(dialog,'p','读取配置…');status.setAttribute('role','status');var busy=false;
    function close(){if(!busy){dialog.close();dialog.remove();}}
    dialog.addEventListener('cancel',function(e){e.preventDefault();close();});
    try {
      var data=await api('radios'),ids=rows.map(function(r){return String(r.rfId);});
      var selected=ids.map(function(id){return data.radios.find(function(r){return r.rf_id===id;});});
      if(selected.some(function(r){return !r||!r.online;}))throw Error('所选射频包含离线 AP，请重新选择');
      status.textContent=selected.map(function(r){return r.ap_name+' · '+r.freq_name;}).join('、');
      var form=node(dialog,'form');
      function field(title,tag){var l=node(form,'label',title);Object.assign(l.style,{display:'block',margin:'16px 0'});var e=node(l,tag);Object.assign(e.style,{display:'block',width:'100%',padding:'9px',marginTop:'6px'});return e;}
      var channel=field('信道','select');node(channel,'option','保持当前信道').value='';
      var channels=selected[0].channels.filter(function(n){return selected.every(function(r){return r.channels.includes(n);});});
      channels.forEach(function(n){node(channel,'option',String(n)).value=n;});
      var lo=Math.max.apply(null,selected.map(function(r){return r.min_power==null?1000:r.min_power;}));
      var hi=Math.min.apply(null,selected.map(function(r){return r.max_power==null?-1:r.max_power;}));
      var power=field('发射功率'+(lo<=hi?'（'+lo+'–'+hi+' dBm）':''),'input');power.type='number';power.min=lo;power.max=hi;power.step=1;
      power.placeholder='保持当前功率';power.disabled=lo>hi;
      var state=field('射频开关','select');[['','保持当前状态'],['on','开启'],['off','关闭']].forEach(function(v){node(state,'option',v[1]).value=v[0];});
      var cancel=node(form,'button','取消');cancel.type='button';cancel.onclick=close;
      var save=node(form,'button','保存并下发');save.type='submit';
      [cancel,save].forEach(function(b){Object.assign(b.style,{padding:'8px 18px',marginRight:'12px',cursor:'pointer'});});
      form.onsubmit=async function(e){e.preventDefault();var changes={};
        if(channel.value!=='')changes.channel=Number(channel.value);
        if(power.value!=='')changes.power_dbm=Number(power.value);
        if(state.value!=='')changes.rf_state=state.value;
        if(!Object.keys(changes).length){status.textContent='请选择需要修改的参数';return;}
        busy=true;save.disabled=cancel.disabled=true;status.textContent='正在下发，等待 AP 确认…';
        try {await api('radios/save',{ids:ids,changes:changes});busy=false;close();refresh();}
        catch(error){status.textContent=error.message;busy=false;save.disabled=cancel.disabled=false;refresh();}
      };
    } catch(error){status.textContent=error.message;node(dialog,'button','关闭').onclick=close;}
  };
})();
