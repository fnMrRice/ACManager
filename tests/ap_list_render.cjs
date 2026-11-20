// Execute the patched firmware's render function without a browser or devices.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const path=require('path');
process.chdir(path.join(__dirname,'..'));
const file=fs.readdirSync('web/overrides/js').find(x=>x.startsWith('apManagement-apSetting-status-ac-index-vue.'));
const chunks=[];let called,refreshed=false;
vm.runInNewContext(fs.readFileSync('web/overrides/js/'+file,'utf8'),{
  self:{webpackChunkdmui:chunks},window:{acEditAp:(mac,refresh)=>{called=mac;refresh();}}
});
const exported={},requireStub=()=>({});
requireStub.r=()=>{};
requireStub.d=(target,defs)=>{for(const [key,get]of Object.entries(defs))Object.defineProperty(target,key,{get});};
chunks[0][1][78161]({},exported,requireStub);
const create=(tag,options,children)=>Array.isArray(options)
  ? {tag,options:{},children:options}
  : {tag,options:options||{},children:children||[]};
const component={
  $createElement:create,_self:{_c:create},_e:()=>null,_v:x=>({text:String(x)}),_s:String,
  _u:x=>x,_l:(rows,fn)=>(rows||[]).map(fn),_t:()=>null,_m:()=>null,isMesh:()=>false,
  $refs:{grid:{gotoFirstPage(){refreshed=true;}}},
  autoAdopt:true,adoptionReady:true,adoptionSubnets:['192.0.2.0/24'],columns:[],params:{}
};
try {
  const tree=exported.render.call(component),grid=tree.children.find(n=>n&&n.tag==='tp-grid');
  function validate(node){
    if(node==null)return;
    assert.strictEqual(typeof node,'object','Compiled Vue render children must be VNodes, never raw strings');
    (Array.isArray(node)?node:(node.children||[])).forEach(validate);
  }
  validate(tree);
  assert(grid);
  const operation=grid.options.scopedSlots.find(x=>x.key==='operation').fn({rows:{mac:'02:00:00:00:00:01'}});
  validate(operation);
  operation.children[0].options.on.click();
  assert.strictEqual(called,'02:00:00:00:00:01');assert(refreshed);
  const checkbox=tree.children[0].children[0].children[0];
  assert.strictEqual(checkbox.options.domProps.checked,true);
  console.log('Native AP list render: inline settings and adoption checkbox PASS');
} catch(error) {console.error(error.message);process.exitCode=1;}
