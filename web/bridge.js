/* Minimal local-host bridge; firmware application bundles remain unchanged. */
(function () {
  'use strict';
  function redirectOverview() {
    var routes = {
      homePage:'/systemState/homeApStatus',
      apStatus:'/systemState/homeApStatus',
      apSsidList:'/systemState/homeApStatus/homeSsidList',
      apTimingReboot:'/systemState/homeApStatus/timingReboot',
      homeLogList:'/systemSetting/logList',
      authUser:'/advancedFunction/authentication/authentication/user',
      authSessionUser:'/advancedFunction/authentication/authentication/sessionUser'
    };
    var hash=location.hash.slice(1),index=hash.indexOf('?');
    var path=index<0?hash:hash.slice(0,index),query=index<0?'':hash.slice(index);
    var target=routes[path.split('/').filter(Boolean).pop()];
    if(target) location.replace('#'+target+query);
  }
  redirectOverview();
  window.addEventListener('hashchange',redirectOverview);
  function notice(text) {
    var box = document.getElementById('local-ac-message');
    if (!box) {
      box = document.createElement('div'); box.id = 'local-ac-message';
      Object.assign(box.style, { position:'fixed',bottom:'42px',right:'24px',maxWidth:'580px',
        padding:'14px 20px',background:'#fff4de',border:'1px solid #d8a746',color:'#553a0a',
        zIndex:2147483647,font:'14px sans-serif',borderRadius:'5px',boxShadow:'0 3px 18px #0002' });
      box.onclick = function () { box.remove(); }; document.body.appendChild(box);
    }
    box.textContent = text;
  }
  var open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function () {
    this.addEventListener('load', function () {
      if (this.status === 401 && window.acLoginRequired) { location.assign('/login'); return; }
      try {
        var response = this.responseType === 'json' ? this.response : JSON.parse(this.responseText);
        if (response.logged_out) { sessionStorage.removeItem('stok'); localStorage.removeItem('_tid_'); location.assign('/login'); return; }
        if (response.error_msg) notice(response.error_msg);
        else if (response.message) notice(response.message);
      } catch (_) {}
    });
    return open.apply(this,arguments);
  };
  document.addEventListener('DOMContentLoaded', function () {
    var bar = document.createElement('div');
    Object.assign(bar.style,{position:'fixed',bottom:'0',left:'0',right:'0',height:'30px',
      padding:'5px 18px',boxSizing:'border-box',background:'#173a49',color:'#fff',display:'flex',alignItems:'center',gap:'16px',
      zIndex:2147483646,font:'13px sans-serif'});
    bar.appendChild(document.createTextNode('TP-LINK AC · '));
    var crumbs = document.createElement('nav'); crumbs.setAttribute('aria-label','面包屑导航');
    Object.assign(crumbs.style,{flex:'1',overflow:'hidden',whiteSpace:'nowrap',textOverflow:'ellipsis'});
    bar.appendChild(crumbs);
    var routes = {};
    function showPath() {
      var parts = location.hash.replace(/^#\/?/,'').split('?')[0].split('/').filter(Boolean);
      var trail = routes[parts[parts.length-1]];
      crumbs.textContent = trail ? trail.join(' › ') : '当前位置';
    }
    fetch('/navigation.json?v=4').then(function(r){return r.json();}).then(function(data){routes=data;showPath();}).catch(function(){showPath();});
    window.addEventListener('hashchange',showPath); showPath();
    var link = document.createElement('a'); link.href='/setup'; link.textContent='测试页面';
    Object.assign(link.style,{color:'#8ef0ef',marginLeft:'auto',flexShrink:'0'}); bar.appendChild(link);
    document.body.appendChild(bar);
  });
})();
