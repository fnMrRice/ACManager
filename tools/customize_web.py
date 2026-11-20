"""Build small UI overrides without modifying the extracted firmware assets."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'web/web-static/js'
TARGET = ROOT/'web/overrides/js'
TARGET.mkdir(parents=True,exist_ok=True)

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Firmware UI changed; expected one matching customization target')
    return text.replace(old,new,1)

def js_object(value):
    return re.sub(r'"([a-zA-Z_]\w*)":',r'\1:',json.dumps(value,ensure_ascii=False,separators=(',',':'))).replace(':true',':!0').replace(':false',':!1')

# Host networking and maintenance belong to OpenWrt. AP VLAN assignment,
# wireless security and AP diagnostics remain controller responsibilities.
HOST_PATHS = {'networkSetting','multicast','localSetting','factoryReset',
              'importConfig','timeSetting','webAccount','webAccountManage',
              'webService','testTools','fault','homePage'}

# Keep unimplemented AC features. Only consolidate duplicate entry points.
DUPLICATE_PATHS = {'apStatus','homeLogList','authUser','authSessionUser'}

def controller_menu(items):
    result = []
    for original in items:
        if original.get('path') in HOST_PATHS | DUPLICATE_PATHS: continue
        item = dict(original)
        for key in ('title','label'):
            if item.get(key)=='AP状态': item[key]='AP列表'
        if item.get('path') in ('homeApStatus','apStatus'):
            for key in ('title','label'):
                if key in item: item[key]='AP列表'
        children = [key for key in ('subMenu','tabs') if key in item]
        for key in children: item[key] = controller_menu(item[key])
        if children and not any(item[key] for key in children) and not item.get('component'): continue
        if [tab.get('path') for tab in item.get('tabs',[])] == ['authorizeDevice']:
            item['title'] = '待授权设备'
        if item.get('title') == '系统诊断': item['title'] = 'AP诊断'
        if item.get('title') == '系统日志': item['title'] = '控制器日志'
        if item.get('path') == 'logList': item['label'] = '控制器日志'
        result.append(item)
    return result

p = next(SOURCE.glob('app.*.js'))
text = p.read_text(encoding='utf8')
original_menu = json.JSONDecoder().raw_decode(text,text.index('"menu":[')+7)[0]
menu = controller_menu(original_menu)
text = replace_once(text,'{"icon":"user","func":"goToAccountManage","title":"用户"},','')
text = replace_once(text,'{"component":"saveConfig"},','')
text = replace_once(text,'{"icon":"smb","func":"goToCloud","title":"前往商云"},','')
for serialize in (lambda v:json.dumps(v,ensure_ascii=False,separators=(',',':')),js_object):
    text = replace_once(text,serialize(original_menu),serialize(menu))
text = replace_once(text,'"defaultPath":"homePage"','"defaultPath":"homeApStatus"')
text = replace_once(text,'defaultPath||"homePage"','defaultPath||"homeApStatus"')
# Lazy-loaded modified chunks must not reuse the firmware's browser cache key.
text = text.replace('random=20260817190248','random=ac-ui-22')
(TARGET/p.name).write_text(text,encoding='utf8')
navigation = {}
def walk(items,parents):
    for item in items:
        label = item.get('title',item.get('label'))
        trail = parents+([label] if label and (not parents or parents[-1]!=label) else [])
        if item.get('path') and trail: navigation[item['path']] = trail
        for key in ('subMenu','tabs'): walk(item.get(key,[]),trail)
walk(menu,[])
(ROOT/'web/navigation.json').write_text(json.dumps(navigation,ensure_ascii=False),encoding='utf8')

# Existing AP services are automatically read, without enrolling in deployment.
p = next(SOURCE.glob('apManagement-apSetting-status-ssid-index-vue.*.js'))
text = p.read_text(encoding='utf8')
text = replace_once(text,'return a("div",[','return a("div",[a("button",{style:{margin:"16px",padding:"8px 16px"},on:{click:function(){window.acWirelessInventory(t.entryId)}}},[t._v("查看 SSID / 密码及修改")]),')
(TARGET/p.name).write_text(text,encoding='utf8')
p = next(SOURCE.glob('apManagement-wirelessService-ac-index-vue.*.js'))
text = p.read_text(encoding='utf8')
text = replace_once(text,'return n("div",{staticClass:"a-p-lg"},[',
    'return n("div",{staticClass:"a-p-lg"},[n("button",{style:{padding:"8px 16px",marginBottom:"12px"},on:{click:function(){window.acSyncWireless(t)}}},[t._v("同步 AP 原有服务")]),n("p",[t._v("同名、同密码且安全设置一致的原有服务自动合并，并登记已有射频绑定。批量新增：新建无线服务 → 射频绑定 → 勾选 AP → 批量绑定。")]),')
text = replace_once(text,'columns:o.columns,params:o.params',
    'columns:o.columns.concat([{label:"来源",name:"sourceLabel",filterAble:!1},{label:"射频绑定",name:"bindingLabel",filterAble:!1,minWidth:200}]),params:o.params')
# Imported service controls use AP partial edits. The old full editor and
# delete/recreate path must never be used for these rows, including batch actions.
text = replace_once(text,'{key:"operation",fn:function(e){var i=e.rows;return',
    '{key:"operation",fn:function(e){var i=e.rows;if(i.source==="ap_import")return n("div",[n("tp-button",{attrs:{type:"text"},on:{click:function(){t.gotoRfBind(i)}}},[t._v("射频绑定")]),n("tp-button",{attrs:{type:"text"},on:{click:function(){window.acEditWireless(i.servId,function(){t.$refs.grid.refreshData()})}}},[t._v("SSID / 密码")])]);return')
text = replace_once(text,'"data-test":"ac_value",value:a,','"data-test":"ac_value",disabled:i.source==="ap_import",value:a,')
text = replace_once(text,'var i="确定删除该SSID吗？";',
    'if(e.some(function(t){return t.source==="ap_import"})){r.kC.error("AP 原有服务请使用该行的 SSID / 密码；未删除任何服务");return}var i="确定删除该SSID吗？";')
text = replace_once(text,'toggleEnable:function(t,e){var n=this;',
    'toggleEnable:function(t,e){if(t.some(function(t){return t.source==="ap_import"})){r.kC.error("AP 原有服务请使用该行的 SSID / 密码；未更改任何服务");return}var n=this;')
# Keep the original full editor available for security/VLAN and other settings.
text = replace_once(text,'n("tp-button",{attrs:{"data-test":"ac_handleEditClickrows"',
    'n("tp-button",{attrs:{type:"text"},on:{click:function(){window.acEditWireless(i.servId,function(){t.$refs.grid.refreshData()})}}},[t._v("SSID / 密码")]),n("tp-button",{attrs:{"data-test":"ac_handleEditClickrows"')
text = replace_once(text,'query:{servId:e,ssid:n,autoBind:i,','query:{imported:t.source==="ap_import"?"1":"0",servId:e,ssid:n,autoBind:i,')
(TARGET/p.name).write_text(text,encoding='utf8')
p = next(SOURCE.glob('apManagement-wirelessService-rfBind-ac-index-vue.*.js'))
text = p.read_text(encoding='utf8')
text = replace_once(text,'return{ssid:"",servId:"",','return{imported:!1,ssid:"",servId:"",')
text = replace_once(text,'this.servId=e,this.ssid=n,','this.imported=t.imported==="1",this.servId=e,this.ssid=n,')
text = re.sub(r't\.editAble(?![=])','(t.editAble&&!t.imported)',text)
text = replace_once(text,'n("auto-bind-form",{ref:"autoBindForm",','t.imported?n("p",[t._v("以下绑定来自 AP 现有配置；可返回无线服务统一修改名称或密码。")]):t._e(),n("auto-bind-form",{style:{display:t.imported?"none":""},ref:"autoBindForm",')
start=text.index('handleBindStatusChange:function(');end=text.index('handleBindStatusMultiChange:function(',start)
text=text[:start]+'''handleBindStatusChange:function(t,e){var a=this,r=[],n;t?(r=[t],n=t.bindStatus):(n=e,this.$refs.grid.getSelectedRows().forEach(function(t){t.rfEntry.forEach(function(t){("1"===n&&"1"!==t.bindStatus||"0"===n)&&r.push(t)})}));if(!r.length)return;window.acBindWireless(this,{table:"radio_bind_list",filter:[{servId:this.servId}],para:{radioId:r.map(function(t){return t.radioId}),bindStatus:n,bindVlanType:"single_vlan",vlanId:r.map(function(t){return t.vlanId||"0"})}})},'''+text[end:]
# The preview itself is the confirmation, including target AP identities.
start=text.index('handleBindStatusMultiChange:function(');end=text.index('}}}},12678:',start)
text=text[:start]+'handleBindStatusMultiChange:function(t){this.handleBindStatusChange(null,t)'+text[end:]
(TARGET/p.name).write_text(text,encoding='utf8')

p = next(SOURCE.glob('apManagement-apSetting-status-ac-index-vue.*.js'))
text = p.read_text(encoding='utf8')
start=text.index('handelExportClick:function(){');end=text.index('exportApStatus:function(){',start)
text=text[:start]+'handelExportClick:function(){window.acExportAps()},'+text[end:]
text = replace_once(text,'class:"2"!==a.linkStatus?"a-bg-success":"a-bg-error"',
    'class:a.managementState==="discovered"?"a-bg-warning":("2"!==a.linkStatus?"a-bg-success":"a-bg-error")')
text = replace_once(text,'t._s("2"===a.linkStatus?"离线":"在线")','t._s(a.managementLabel||("2"===a.linkStatus?"离线":"在线"))')
text = replace_once(text,'{key:"operation",fn:function(e){var a=e.rows;return n("div",{},[',
    '{key:"operation",fn:function(e){var a=e.rows;return n("div",{},[n("tp-button",{attrs:{type:"text"},on:{click:function(){window.acEditAp(a.mac,function(){t.$refs.grid.gotoFirstPage()})}}},[t._v("设置")]),')
text = replace_once(text,'currentGroup:[],groupList:[]','autoAdopt:!1,adoptionReady:!1,adoptionSubnets:[],currentGroup:[],groupList:[]')
text = replace_once(text,'beforeMount:function(){var t=this;this.getAcCalibrateCapability()',
    'beforeMount:function(){var t=this;window.acLoadAdoption(t);this.getAcCalibrateCapability()')
text = replace_once(text,'return(0,h.columns)(t,this.groupList,this.apList,this.allModelList,this.isAcSuppGetCalibrate)',
    'var r=(0,h.columns)(t,this.groupList,this.apList,this.allModelList,this.isAcSuppGetCalibrate);return [r[0],{label:"备注",name:"remark",minWidth:100,filterAble:!1,format:function(v){return v||"—"}},{label:"接管方式",name:"adoption",minWidth:80,filterAble:!1,format:function(v){return {default:"跟随默认",allow:"接管",block:"不接管"}[v]||"跟随默认"}}].concat(r.slice(1))')
text = replace_once(text,'return n("div",{staticClass:"a-p-lg"},[',
    'return n("div",{staticClass:"a-p-lg"},[n("div",{style:{marginBottom:"18px",padding:"12px",background:"#f3f8fa"}},[n("label",[n("input",{attrs:{type:"checkbox",disabled:!t.adoptionReady},domProps:{checked:t.autoAdopt},on:{change:function(e){window.acSetAdoption(t,e.target)}}}),t._v(" 默认接管")]),n("span",{style:{marginLeft:"20px",color:"#637782"}},[t._v("范围："+t.adoptionSubnets.join(", ")+"；单台 AP 设置优先")])]),')
(TARGET/p.name).write_text(text,encoding='utf8')
p = next(SOURCE.glob('homePage-ac-index-vue.*.js'))
text = p.read_text(encoding='utf8')
for component,ref in (('system-info','systemInfo'),('performance','performance')):
    text = replace_once(text,',e("div",{staticClass:"col l4 m12 s12 right-col"},[e("'+component+'",{ref:"'+ref+'"})],1)','')
    text = replace_once(text,'this.$refs.'+ref+'.getData(),','')
text = text.replace('staticClass:"col l4 m12 s12 left-col"','staticClass:"col l6 m12 s12 left-col"')
text = replace_once(text,'t.total=(Number(n.onlineNum)||0)+(Number(n.offlineNum)||0),t.curSeriesData=[{value:n.onlineNum,name:"在线"},{value:n.offlineNum,name:"离线"}]',
    't.total=(Number(n.onlineNum)||0)+(Number(n.offlineNum)||0)+(Number(n.discoveredNum)||0),t.curSeriesData=[{value:n.onlineNum,name:"已接管"},{value:n.discoveredNum||0,name:"待接管"},{value:n.offlineNum,name:"离线"}]')
(TARGET/p.name).write_text(text,encoding='utf8')
common = next(SOURCE.glob('common.*.js'))
text = common.read_text(encoding='utf8')
text = replace_once(text,'beforeMount:function(){var e=this;a.get({cloud_config:{name:"ui_notify_info"}},(function(t){t&&t.cloudConfig&&t.cloudConfig.uiNotifyInfo&&t.cloudConfig.uiNotifyInfo.topBarNotifyAgain&&(e.showCloudNotice="1"===t.cloudConfig.uiNotifyInfo.topBarNotifyAgain)}))}',
    'beforeMount:function(){this.showCloudNotice=!1}')
text = text.replace('autoBind:"on"','autoBind:"off"')
text = replace_once(text,'encryption:"0",radiusVlanEnable:"off",radiusAuthChannel:"ap",auth:"3"',
    'encryption:"1",radiusVlanEnable:"off",radiusAuthChannel:"ap",auth:"2"')
text = replace_once(text,'encryption:"0",auth:"3",cipher:"2",keyUpdateIntv:"86400",key:"",radiusIp:',
    'encryption:"1",auth:"2",cipher:"2",keyUpdateIntv:"86400",key:"",radiusIp:')
(TARGET/common.name).write_text(text,encoding='utf8')

# Terminal status uses the original grid/dialog, backed by live AP reports.
start=text.index('1543:function(');end=text.index('34054:function(',start)
section=text[start:end]
section=replace_once(section,'s={no_auth:', 's={unknown:"未读取",no_auth:')
section=replace_once(section,'return t.apName?"在线":"离线"','return t.onlineStatus==="1"?"在线":"离线"')
text=text[:start]+section+text[end:]
# The network terminal view has a separate formatter from System Status.
start=text.index('36076:function(');match=re.search(r'},\d+:function\(',text[start:]);end=start+match.start()+1
section=text[start:end]
section=replace_once(section,'r={no_auth:', 'r={unknown:"未读取",no_auth:')
section=replace_once(section,'return t.apName?"在线":"离线"','return t.onlineStatus==="1"?"在线":"离线"')
section=replace_once(section,'return i.apName?e.find((function(e){return e.groupId===t.find((function(e){return e.entryName===i.apName})).groupId})).name:"---"',
    'var g=e.find(function(g){return g.groupId===i.groupId});return g?g.name:"---"')
text=text[:start]+section+text[end:]
# The deployed controller keeps its original default group ID (1).
for module_id in (43784,):
    start=text.index(str(module_id)+':function(')
    match=re.search(r'},\d+:function\(',text[start:])
    end=start+match.start()+1
    section=text[start:end].replace('"0"===','"1"===')
    text=text[:start]+section+text[end:]
(TARGET/common.name).write_text(text,encoding='utf8')

for pattern in ('apManagement-apSetting-group-ac-index-vue.*.js','apManagement-apSetting-list-ac-index-vue.*.js'):
    p=next(SOURCE.glob(pattern))
    text=p.read_text(encoding='utf8')
    # Only group identity comparisons; unrelated status values stay unchanged.
    text=re.sub(r'"0"===([a-z]\.groupId|this\.groupId)',r'"1"===\1',text)
    (TARGET/p.name).write_text(text,encoding='utf8')

p=next(SOURCE.glob('terminalList-ac-index-vue.*.js'))
text=p.read_text(encoding='utf8')
start=text.index('handleExportTerminalList:function(){');end=text.index('exportTerminalList:function(){',start)
text=text[:start]+'handleExportTerminalList:function(){window.acExportTerminals()},'+text[end:]
text=replace_once(text,'t._s(e.rssi+"dBm"||0)','t._s(e.rssi==null?"—":e.rssi+" dBm")')
text=replace_once(text,'{key:"operation",fn:function(e){var r=e.rows;return n("div",{},[',
    '{key:"operation",fn:function(e){var r=e.rows;return n("div",{},[n("tp-button",{attrs:{type:"text",disabled:r.onlineStatus!=="1"},on:{click:function(){window.acDisconnectTerminal(t,r)}}},[t._v("断开")]),')
(TARGET/p.name).write_text(text,encoding='utf8')

p=next(SOURCE.glob('tmManagement-list-index-vue.*.js'))
text=p.read_text(encoding='utf8')
start=text.index('handleSelectChange:function(t){');end=text.index('handleDelete:function(t){',start)
text=text[:start]+('handleSelectChange:function(t){this.emptySelect=!t||!t.length;this.hasOnline=!!t&&t.some(function(r){return r.onlineStatus==="1"})},'
    'handleDisconnect:function(){var t=this;i.Z.confirm({title:"断开终端",content:"所选终端将断开当前 Wi-Fi 连接，仍可重新连接。确定断开吗？",okText:"断开",cancelText:"取消",confirm:function(){t.disconnect()}})},')+text[end:]
text=replace_once(text,'t.hasOnline?n("span",[t._v("断开连接")]):n("span",[t._v("清除配置")])','n("span",[t._v("断开连接")])')
(TARGET/p.name).write_text(text,encoding='utf8')

p=next(SOURCE.glob('routerTopo-ac-index-vue.*.js'))
text=p.read_text(encoding='utf8')
text=replace_once(text,'loading:!0,refreshTime:', 'monitorError:"",monitorSummary:"",loading:!0,refreshTime:')
text=replace_once(text,'devTypeList:p.devTypeList',
    'devTypeList:[{label:"全部 AP",value:"all"},{label:"在线 AP",value:"online"},{label:"离线 AP",value:"offline"}]')
text=replace_once(text,'spreadType:""','spreadType:3')
text=replace_once(text,'spreadTypeList:p.spreadTypeList',
    'spreadTypeList:[{value:0,label:"展开所有终端"},{value:3,label:"展开到 AP"},{value:2,label:"展开到分组"}]')
text=replace_once(text,'mounted:function(){this.$refs.topo.deviceInfo.port=!1,this.getData()},',
    'mounted:function(){this.$refs.topo.deviceInfo.port=!1;this.getData()},beforeDestroy:function(){this._acMonitorDisposed=!0;if(this._acMonitorAbort)this._acMonitorAbort.abort()},')
start=text.index('getData:function(){');end=text.index('getMainDeviceInfo:function(){',start)
text=text[:start]+'getData:function(){return window.acLoadTopology(this)},'+text[end:]
text=replace_once(text,'n("div",{staticClass:"body"},[',
    'n("p",{staticStyle:{margin:"12px 24px",color:"#637782"}},[t._v("管理关系图：AC 到 AP 的连线不代表实际交换机端口；AP 到终端来自实时关联上报。 "+t.monitorSummary)]),t.monitorError?n("p",{attrs:{role:"alert"},staticStyle:{margin:"12px 24px",color:"#b42318"}},[t._v(t.monitorError)]):t._e(),n("div",{staticClass:"body"},[')
text=replace_once(text,'"legend-visible":""','"legend-visible":!1')
(TARGET/p.name).write_text(text,encoding='utf8')

p=next(SOURCE.glob('blackList-ac-index-vue.*.js'))
text=p.read_text(encoding='utf8')
text=replace_once(text,'data:function(){return{dlgVisible:',
    'beforeMount:function(){window.acLoadAdmission(this)},data:function(){return{admissionAps:[],admissionSelected:[],admissionBusy:!1,admissionMessage:"",dlgVisible:')
text=replace_once(text,'return s("div",{staticClass:"a-p-lg"},[',
    'return s("div",{staticClass:"a-p-lg"},[window.acAdmissionPanel(t,s),')
text=replace_once(text,'on:{click:function(e){t.importDlgVisible=!0}}',
    'on:{click:function(e){window.acImportBlacklist(t)}}')
start=text.index('handleExportBlackList:function(){');end=text.index('exportBlackList:function(){',start)
text=text[:start]+'handleExportBlackList:function(){window.acExportBlacklist()},'+text[end:]
(TARGET/p.name).write_text(text,encoding='utf8')
p=next(SOURCE.glob('apManagement-radioFrequency-setting-ac-index-vue.*.js'))
text=p.read_text(encoding='utf8')
text=replace_once(text,'columns:o.columns,','columns:window.acRadioColumns,')
text=replace_once(text,'on:{click:function(e){t.importDlgVisible=!0}}',
    'on:{click:function(e){window.acImportRadios(t)}}')
start=text.index('handelExportClick:function(){');end=text.index('exportRfEntry:function(){',start)
text=text[:start]+'handelExportClick:function(){window.acExportRadios()},'+text[end:]
text=replace_once(text,'on:{click:t.handelExportClick}},[t._v("导出")])',
    'on:{click:t.handelExportClick}},[t._v("导出")]),n("tp-button",{attrs:{icon:"refresh"},on:{click:function(){t.$refs.grid.refreshData()}}},[t._v("刷新")])')
start=text.index('handleEditClick:function(t){')
end=text.index('this.dlgVisible=!0',start)+len('this.dlgVisible=!0')
text=text[:start]+'handleEditClick:function(t){var vm=this;window.acEditRadio(t?[t]:this.$refs.grid.getSelectedRows(),function(){vm.$refs.grid.refreshData()})'+text[end:]
# Unknown switch states must not be rendered as an affirmative off state.
text=replace_once(text,'return n("div",{},[n("tp-switch",',
    'return n("div",{},[a!=="on"&&a!=="off"?n("span",[t._v("未读取")]):n("tp-switch",')
(TARGET/p.name).write_text(text,encoding='utf8')

p=next(SOURCE.glob('apManagement-radioFrequency-navigation-index-vue.*.js'))
text=p.read_text(encoding='utf8')
text=replace_once(text,'data:function(){return{model:',
    'data:function(){return{featureAps:[],featureSelected:[],featureBusy:!1,featureMessage:"读取中…",model:')
old='getData:function(){var t=this;o.get({apmng_band_navigation:{name:"settings"}},(function(e){t.model=e.apmngBandNavigation.settings,Object.assign(t.backupModel,t.model)}))}'
text=replace_once(text,old,'getData:function(){window.acLoadBandNavigation(this)}')
text=replace_once(text,'return a("div",{staticClass:"a-p-lg"},[',
    'return a("div",{staticClass:"a-p-lg"},[window.acBandTargets(t,a),')
text=replace_once(text,'loading:t.loading,disabled:!t.hasChange},on:{click:t.save}',
    'loading:t.featureBusy,disabled:t.featureBusy||!t.featureSelected.length},on:{click:function(){window.acSaveBandNavigation(t)}}')
(TARGET/p.name).write_text(text,encoding='utf8')
p=next(SOURCE.glob('apManagement-radioFrequency-edca-index-vue.*.js'))
text=p.read_text(encoding='utf8')
text=replace_once(text,'return(0,s.columns)(this.groupList,this.apList)','return window.acEdcaColumns')
text=replace_once(text,'methods:{getApGroupList:',
    'methods:{handleAddClick:function(){window.acEditEdca(this)},handleEditClick:function(row){window.acEditEdca(this,row.edcaRuleId)},handleDelete:function(row){window.acDeleteEdca(this,row)},getApGroupList:')
text=replace_once(text,',n("edit-dia",{attrs:{visible:t.dlgVisible,"is-edit":t.isEdit,"current-row":t.currentRow},on:{"update:visible":function(e){t.dlgVisible=e},"save-success":t.handleSaveSuccess}})','')
(TARGET/p.name).write_text(text,encoding='utf8')
p=next(SOURCE.glob('apManagement-apSetting-balance-ac-index-vue.*.js'))
text=p.read_text(encoding='utf8')
text=replace_once(text,'return(0,c.columns)(this.groupList,this.apList)',
    'return (0,c.columns)(this.groupList,this.apList).concat([{label:"下发状态",name:"applyStatus",minWidth:120}])')
text=replace_once(text,'return n("div",{staticClass:"a-p-lg"},[',
    'return n("div",{staticClass:"a-p-lg"},[n("p",{style:{marginBottom:"16px",color:"#637782"}},[t._v("请选择具体 AP 设备，并确保其提供相同 SSID。规则仅在终端被其他可用 AP 探测到时参与接入判断；达到最大拒绝次数后放行。当前支持普通单链路终端。")]),')
(TARGET/p.name).write_text(text,encoding='utf8')
print('Created UI overrides and breadcrumb map; extracted assets unchanged')
