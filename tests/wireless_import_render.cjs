// Execute the real patched Vue render; imported rows must bypass legacy writes.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.join(__dirname,'../web/overrides/js');
const file=fs.readdirSync(root).find(x=>x.startsWith('apManagement-wirelessService-ac-index-vue.'));
const chunks=[],calls=[];let refreshed=false;
vm.runInNewContext(fs.readFileSync(path.join(root,file),'utf8'),{
  self:{webpackChunkdmui:chunks},window:{acEditWireless:(servId,refresh)=>{calls.push({servId});refresh();}}
});
const exported={},req=()=>({});req.r=()=>{};
req.d=(t,defs)=>{for(const [key,get] of Object.entries(defs))Object.defineProperty(t,key,{get});};
chunks[0][1][86580]({},exported,req);
const create=(tag,options,children)=>Array.isArray(options)?{tag,options:{},children:options}:{tag,options:options||{},children:children||[]};
const component={$createElement:create,_self:{_c:create},_e:()=>null,_v:x=>({text:String(x)}),_s:String,
  _u:x=>x,_l:(rows,fn)=>(rows||[]).map(fn),_t:()=>null,_m:()=>null,
  $refs:{grid:{refreshData(){refreshed=true;}}},columns:[],params:{},gotoRfBind(row){calls.push({binding:row.servId});}};
const tree=exported.render.call(component);
function all(n){return n?[n,...(n.children||[]).flatMap(all)]:[];}
function validate(n){if(n==null)return;assert.equal(typeof n,'object');(Array.isArray(n)?n:n.children||[]).forEach(validate);}
validate(tree);
const grid=all(tree).find(n=>n.tag==='tp-grid'),slots=grid.options.scopedSlots;
const row={source:'ap_import',servId:'1'};
const imported=slots.find(s=>s.key==='operation').fn({rows:row});validate(imported);
assert.equal(imported.children.length,2);
assert.equal(imported.children[0].children[0].text,'射频绑定');
assert.equal(imported.children[1].children[0].text,'SSID / 密码');
imported.children[0].options.on.click();imported.children[1].options.on.click();assert(refreshed);
assert.deepEqual(calls,[{binding:'1'},{servId:'1'}]);
const enable=slots.find(s=>s.key==='enable').fn({rows:row,value:'on'});
assert.equal(enable.children[0].options.attrs.disabled,true);
const normal=slots.find(s=>s.key==='operation').fn({rows:{source:'controller_saved',servId:'1'}});validate(normal);
assert.equal(normal.children.length,4);
const rfFile=fs.readdirSync(root).find(x=>x.startsWith('apManagement-wirelessService-rfBind-ac-index-vue.'));
vm.runInNewContext(fs.readFileSync(path.join(root,rfFile),'utf8'),{self:{webpackChunkdmui:chunks}});
const rf={};chunks[1][1][22066]({},rf,req);
component.imported=true;component.editAble=true;component.groupList=[];
component.tdClass=()=>({});component.tdHeight=()=>({});component.formatVlanId=()=>'10';
const rfTree=rf.render.call(component);validate(rfTree);
const form=all(rfTree).find(n=>n.tag==='auto-bind-form');assert.equal(form.options.style.display,'none');
const rfGrid=all(rfTree).find(n=>n.tag==='tp-grid');
const bound=rfGrid.options.scopedSlots.find(s=>s.key==='bindStatus').fn({rows:{rfEntry:[{bindStatus:'1'}]}});
const sw=all(bound).find(n=>n.tag==='tp-switch');assert.equal(sw.options.attrs.disabled,true);assert.equal(sw.options.model.value,'1');
console.log('Shared imported services: binding navigation, shared editor, preserved registered bindings PASS');
