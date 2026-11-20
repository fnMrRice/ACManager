// Verify reading/revealing/cancelling never writes and an SSID edit omits the key.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
class Element {
  constructor(tag){this.tag=tag;this.children=[];this.style={};this.textContent='';this.value='';this.disabled=false;}
  appendChild(e){this.children.push(e);e.parent=this;}
  replaceChildren(){this.children=[];}
  setAttribute(){} addEventListener(){} showModal(){} close(){}
  remove(){this.parent.children=this.parent.children.filter(e=>e!==this);}
}
const body=new Element('body'),calls=[],window={},original={mac:'02:00:00:00:00:01',ip:'192.0.2.155',ap_name:'Test AP',revision:'snapshot',items:[{section:'wlan_serv_1',radio:1,ssid:'Original',key:'secret-password',encryption:'3',vlan:'12',hidden:true,enable:'on',editable:true}]};
function all(e){return [e,...e.children.flatMap(all)];}
function button(e,name){return all(e).find(n=>n.tag==='button'&&n.textContent===name);}
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../web/wireless.js'),'utf8'),{window,document:{body,createElement:t=>new Element(t)},sessionStorage:{getItem:()=> 'session'},fetch:async(url,opts)=>{
  const request=JSON.parse(opts.body);calls.push({url,request});
  return {ok:true,json:async()=>url.endsWith('read-ap')?structuredClone(original):{message:'verified',current:structuredClone(original)}};
}});
(async()=>{
  await window.acReadApWireless(original.mac);
  assert.deepEqual(calls.map(x=>x.url),['/api/wireless/read-ap']);
  const first=body.children[0],key=all(first).find(e=>e.tag==='input'&&e.type==='password');
  assert.equal(key.value,'secret-password');assert(key.readOnly);
  const show=all(first).find(e=>e.tag==='input'&&e.type==='checkbox');show.checked=true;show.onchange();assert.equal(key.type,'text');assert.equal(calls.length,1);
  button(first,'修改此服务').onclick();let edit=body.children[1];
  await button(edit,'保存到此 AP').onclick();assert.equal(calls.length,1);
  button(edit,'关闭').onclick();assert.equal(calls.length,1);
  button(first,'修改此服务').onclick();edit=body.children[1];
  all(edit).find(e=>e.tag==='input'&&e.type==='text').value='Renamed';
  await button(edit,'保存到此 AP').onclick();
  assert.equal(calls[1].url,'/api/wireless/edit-ap');
  assert.deepEqual(calls[1].request,{mac:original.mac,section:'wlan_serv_1',revision:'snapshot',changes:{ssid:'Renamed'}});
  console.log('AP wireless UI: read-only view/reveal/cancel and selected-field save PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
