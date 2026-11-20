/* AP list controls share the original firmware grid and authenticated API. */
(function () {
  'use strict';
  window.acExportAps=function(){
    var link=document.createElement('a');link.href='/stok='+encodeURIComponent(sessionStorage.getItem('stok'))+'/admin/apmng_status/export_ap_list';
    link.download='aps.csv';document.body.appendChild(link);link.click();link.remove();
  };
  async function api(path,body) {
    var response=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json',
      'X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body||{})});
    if(response.status===401){location.assign('/login');throw Error('请重新登录');}
    var result=await response.json();
    if(!response.ok||result.error)throw Error(result.error||result.error_msg||'操作失败');
    return result;
  }
  function node(parent,tag,text) {
    var element=document.createElement(tag);if(text!==undefined)element.textContent=text;
    parent.appendChild(element);return element;
  }
  window.acLoadAdoption=async function(vm) {
    try {var state=await api('ap-settings');vm.autoAdopt=state.auto_adopt;vm.adoptionSubnets=state.adopt_subnets;vm.adoptionReady=true;}
    catch(error){vm.adoptionReady=false;window.alert(error.message);}
  };
  window.acSetAdoption=async function(vm,input) {
    var previous=vm.autoAdopt,desired=input.checked;vm.adoptionReady=false;
    try {await api('ap-settings/save',{auto_adopt:desired});vm.autoAdopt=desired;vm.$refs.grid.gotoFirstPage();}
    catch(error){input.checked=previous;vm.autoAdopt=previous;window.alert(error.message);}
    finally{vm.adoptionReady=true;}
  };
  window.acEditAp=async function(mac,refresh) {
    if(document.getElementById('ac-ap-editor'))return;
    var dialog=document.createElement('dialog');dialog.id='ac-ap-editor';
    Object.assign(dialog.style,{width:'490px',maxWidth:'90vw',padding:'26px',border:'1px solid #bdcdd5',borderRadius:'6px',color:'#243746',boxShadow:'0 12px 45px #0004'});
    document.body.appendChild(dialog);dialog.showModal();
    var heading=node(dialog,'h2','AP 设置');heading.style.marginTop='0';
    var status=node(dialog,'p','读取配置…');status.setAttribute('role','status');
    var close=function(){dialog.close();dialog.remove();};
    dialog.addEventListener('cancel',function(event){event.preventDefault();close();});
    try {
      var state=await api('ap-settings'),ap=state.aps.find(function(row){return row.mac===mac;});
      if(!ap)throw Error('未找到该 AP，请刷新列表');
      status.textContent=ap.ip+' · '+ap.mac+' · '+ap.management_label;
      var form=node(dialog,'form');
      function field(title,tag){var label=node(form,'label',title);Object.assign(label.style,{display:'block',margin:'16px 0'});var input=node(label,tag);Object.assign(input.style,{display:'block',width:'100%',padding:'9px',marginTop:'6px',border:'1px solid #b8c9d0',borderRadius:'4px'});return input;}
      var name=field('AP 名称','input');name.maxLength=64;name.value=ap.entry_name===ap.mac?'':ap.entry_name;name.placeholder='如：客厅 AP';
      var remark=field('备注','input');remark.maxLength=256;remark.value=ap.remark||'';
      var mode=field('接管方式','select');[['default','跟随默认'],['allow','接管'],['block','不接管']].forEach(function(item){node(mode,'option',item[1]).value=item[0];});mode.value=ap.adoption;
      node(form,'p','名称、备注和接管方式按 MAC 保存。不接管时也可以修改名称和备注。');
      var buttons=node(form,'div');buttons.style.textAlign='right';
      var cancel=node(buttons,'button','取消');cancel.type='button';cancel.onclick=close;
      var save=node(buttons,'button','保存');save.type='submit';
      [cancel,save].forEach(function(button){Object.assign(button.style,{padding:'8px 20px',marginLeft:'10px',border:'1px solid #9aafb9',borderRadius:'4px',cursor:'pointer'});});
      Object.assign(save.style,{background:'#007c91',color:'white'});
      form.onsubmit=async function(event){event.preventDefault();save.disabled=true;cancel.disabled=true;
        try {await api('ap-settings/save',{mac:mac,name:name.value.trim(),remark:remark.value.trim(),adoption:mode.value});close();refresh();}
        catch(error){status.textContent=error.message;save.disabled=false;cancel.disabled=false;}
      };
      name.focus();
    } catch(error){status.textContent=error.message;node(dialog,'button','关闭').onclick=close;}
  };
})();
