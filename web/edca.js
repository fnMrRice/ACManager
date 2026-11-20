(function(){
  'use strict';
  async function api(path,body){var r=await fetch('/api/edca'+path,{method:'POST',headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body||{})});var data=await r.json();if(!r.ok||data.error)throw Error(data.error||'操作失败');return data;}
  function node(p,tag,text){var n=document.createElement(tag);if(text!==undefined)n.textContent=text;p.appendChild(n);return n;}
  function dialog(title){var d=node(document.body,'dialog');d.id='ac-edca-editor';Object.assign(d.style,{width:'780px',maxWidth:'92vw',maxHeight:'90vh',padding:'24px',border:'1px solid #bdcdd5',borderRadius:'6px'});node(d,'h2',title);d.showModal();return d;}
  window.acEdcaColumns=[{label:'规则名称',name:'edcaRuleName',minWidth:120},
    {label:'目标射频',name:'targetText',minWidth:250},{label:'开关',name:'enable',format:function(v){return v==='on'?'开启':'关闭';}},
    {label:'下发状态',name:'deployment',minWidth:120}];
  window.acEditEdca=async function(vm,id){
    if(document.getElementById('ac-edca-editor'))return;
    var d=dialog(id?'编辑静态 EDCA 规则':'新增静态 EDCA 规则'),status=node(d,'p','读取射频…'),busy=false;
    status.setAttribute('role','status');function close(){if(!busy){d.close();d.remove();}}
    d.addEventListener('cancel',function(e){e.preventDefault();close();});
    try{
      var data=await api(''),old=id?data.rules.find(function(r){return r.id===String(id);}):null;
      if(id&&!old)throw Error('规则不存在，请刷新列表');
      status.textContent='选择目标射频并填写参数；保存后逐项显示 AP 应答结果。';
      var form=node(d,'form'),label=node(form,'label','规则名称 '),name=node(label,'input');name.required=true;name.value=old?old.edca_rule_name:'';name.maxLength=64;name.style.padding='7px';
      var enabledLabel=node(form,'label',' 启用规则 '),enabled=node(enabledLabel,'input');enabled.type='checkbox';enabled.checked=!old||old.enable==='on';
      var targets=node(form,'fieldset');node(targets,'legend','目标射频');var selection=[];
      data.radios.forEach(function(r){var l=node(targets,'label');Object.assign(l.style,{display:'block',padding:'5px'});var c=node(l,'input');c.type='checkbox';
        c.checked=!!(old&&old.targets.some(function(t){return t.mac===r.mac&&t.radio===r.radio;}));c.disabled=!!old||!r.online;
        node(l,'span',' '+r.ap_name+' / '+r.ip+' / '+r.freq_name+(r.online?'':'（离线）'));
        selection.push({input:c,mac:r.mac,radio:r.radio});
      });
      if(old)node(targets,'p','需要更换目标时，请先删除原规则，再新建规则。');
      var table=node(form,'table');Object.assign(table.style,{width:'100%',marginTop:'14px'});
      var head=node(table,'tr');['队列','AIFSN','CWmin','CWmax','TXOP Limit'].forEach(function(v){node(head,'th',v);});
      var params=old?old.parameters:data.defaults,inputs={};
      [['ap_vo','AP 语音'],['ap_vi','AP 视频'],['ap_be','AP 尽力而为'],['ap_bk','AP 后台'],['sta_vo','终端语音'],['sta_vi','终端视频'],['sta_be','终端尽力而为'],['sta_bk','终端后台']].forEach(function(q){
        var row=node(table,'tr');node(row,'td',q[1]);inputs[q[0]]=[];
        params[q[0]].forEach(function(v,i){var cell=node(row,'td'),input=node(cell,i===1||i===2?'select':'input');
          if(i===1||i===2){for(var k=1;k<=10;k++){var option=node(input,'option',String(Math.pow(2,k)-1));option.value=k;}}
          else{input.type='number';input.min=i===0?1:0;input.max=i===0?15:8191;input.step=1;input.required=true;}
          input.value=v;input.setAttribute('aria-label',q[1]+' '+['AIFSN','CWmin','CWmax','TXOP Limit'][i]);Object.assign(input.style,{width:'105px',padding:'5px'});inputs[q[0]].push(input);
        });
      });
      var cancel=node(form,'button','取消');cancel.type='button';cancel.onclick=close;var save=node(form,'button','保存并下发');save.type='submit';
      [cancel,save].forEach(function(b){Object.assign(b.style,{padding:'8px 18px',margin:'18px 12px 0 0'});});
      form.onsubmit=async function(e){e.preventDefault();var selected=selection.filter(function(r){return r.input.checked;}).map(function(r){return {mac:r.mac,radio:r.radio};});
        if(!selected.length){status.textContent='请选择目标射频';return;}
        var rows={};Object.keys(inputs).forEach(function(q){rows[q]=inputs[q].map(function(i){return i.value;});});
        busy=true;save.disabled=cancel.disabled=true;status.textContent='正在下发，请稍候…';
        try{await api('/save',{id:id||null,name:name.value,enable:enabled.checked?'on':'off',targets:selected,parameters:rows});busy=false;close();vm.$refs.grid.refreshData();}
        catch(error){status.textContent=error.message;busy=false;save.disabled=cancel.disabled=false;vm.$refs.grid.refreshData();}
      };
    }catch(e){status.textContent=e.message;node(d,'button','关闭').onclick=close;}
  };
  window.acDeleteEdca=function(vm,row){
    var rows=row?[row]:vm.$refs.grid.getSelectedRows();if(!rows.length||document.getElementById('ac-edca-editor'))return;
    var d=dialog('删除 EDCA 规则'),busy=false;node(d,'p','将停用所选规则的自定义 EDCA，并在 AP 确认后删除规则。');
    rows.forEach(function(r){node(d,'p',r.edcaRuleName+' · '+r.targetText);});var status=node(d,'p');status.setAttribute('role','status');
    function close(){if(!busy){d.close();d.remove();}}
    d.addEventListener('cancel',function(e){e.preventDefault();close();});var cancel=node(d,'button','取消'),save=node(d,'button','确认删除');cancel.onclick=close;
    save.onclick=async function(){busy=true;save.disabled=cancel.disabled=true;try{await api('/delete',{ids:rows.map(function(r){return String(r.edcaRuleId);})});busy=false;close();vm.$refs.grid.refreshData();}
      catch(e){status.textContent=e.message;busy=false;save.disabled=cancel.disabled=false;vm.$refs.grid.refreshData();}};
  };
})();
