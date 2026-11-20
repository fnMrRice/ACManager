(function(){
  'use strict';
  async function api(path,body){
    var r=await fetch('/api/features/band-navigation'+path,{method:'POST',headers:{'Content-Type':'application/json','X-AC-Token':sessionStorage.getItem('stok')},body:JSON.stringify(body||{})});
    var result=await r.json();if(!r.ok||result.error)throw Error(result.error||'操作失败');return result;
  }
  function model(settings){return {enable:settings.enable,'5gThreshold':settings['5g_threshold'],difThreshold:settings.dif_threshold,maxFailNum:settings.max_fail_num};}
  window.acLoadBandNavigation=async function(vm){
    vm.featureBusy=true;
    try{var result=await api('');vm.featureAps=result.aps;vm.model=model(result.settings);vm.backupModel=Object.assign({},vm.model);vm.featureMessage='先选择 AP，再保存下发；表格显示每台 AP 的下发状态。';}
    catch(e){vm.featureMessage=e.message;}finally{vm.featureBusy=false;}
  };
  window.acBandTargets=function(vm,h){
    var labels={not_configured:'未配置',waiting_rejoin:'等待重新下发',acknowledged:'AP 已确认',retry_failed:'下发未确认'};
    return h('div',{style:{marginBottom:'24px'}},[
      h('p',{attrs:{role:'status'}},[vm.featureMessage]),
      h('table',{style:{width:'100%',borderCollapse:'collapse'}},[
        h('thead',[h('tr',['选择','AP 名称 / IP','已设开关','下发状态','操作'].map(function(v){return h('th',{style:{textAlign:'left',padding:'8px'}},[v]);}))]),
        h('tbody',vm.featureAps.map(function(ap){
          function cell(v){return h('td',{style:{padding:'10px',borderTop:'1px solid #e4ecef'}},Array.isArray(v)?v:[v]);}
          return h('tr',{key:ap.mac},[
            cell([h('input',{attrs:{type:'checkbox',disabled:vm.featureBusy||!ap.online||!ap.supported,'aria-label':'选择 '+ap.ip},domProps:{checked:vm.featureSelected.includes(ap.mac)},on:{change:function(e){vm.featureSelected=e.target.checked?vm.featureSelected.concat(ap.mac):vm.featureSelected.filter(function(m){return m!==ap.mac;});}}})]),
            cell(ap.name+' / '+ap.ip),cell(ap.settings?(ap.settings.enable==='on'?'开启':'关闭'):'未配置'),
            cell((ap.online?'':'离线 · ')+(labels[ap.status]||ap.status)),
            cell(ap.settings?[h('button',{attrs:{type:'button',disabled:vm.featureBusy},on:{click:function(){vm.model=model(ap.settings);vm.backupModel=Object.assign({},vm.model);}}},['载入此配置'])]:[])
          ]);
        }))
      ])
    ]);
  };
  window.acSaveBandNavigation=async function(vm){
    if(vm.featureBusy)return;
    vm.featureBusy=true;vm.featureMessage='正在逐台下发，等待 AP 确认…';
    try{var p=vm.model;await api('/save',{macs:vm.featureSelected,settings:{enable:p.enable,'5g_threshold':p['5gThreshold'],dif_threshold:p.difThreshold,max_fail_num:p.maxFailNum}});
      vm.featureAps=(await api('')).aps;vm.backupModel=Object.assign({},vm.model);vm.featureMessage='所选 AP 已确认配置。';
    }catch(e){vm.featureMessage=e.message;try{vm.featureAps=(await api('')).aps;}catch(_){} }
    finally{vm.featureBusy=false;}
  };
})();
