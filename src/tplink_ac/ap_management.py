"""Native AP list maintenance operations and exports."""
import csv
import io


def control(app,ids,action):
    if action not in ('reboot','factory_reset','led_on','led_off'): raise ValueError('无效 AP 操作')
    if not isinstance(ids,list) or not ids or len(ids)>64 or len(set(ids))!=len(ids):
        raise ValueError('请选择 AP')
    rows={a['entry_id']:a for a in app.ap_rows()}
    targets=[]
    for ident in ids:
        ap=rows.get(str(ident))
        if not ap or ap['management_state']!='managed': raise ValueError('所选 AP 包含未接管或离线设备')
        targets.append(ap)
    completed=[]
    for ap in targets:
        try: app.confirm_action(ap['ip'],action)
        except (ValueError,RuntimeError,OSError) as error:
            raise ValueError(ap['ip']+' 的操作尚未确认；已完成 '+str(len(completed))+' 台。'+str(error)) from error
        if action=='factory_reset':
            # Do not immediately restore the controller's old WLAN after reset.
            app.bindings={k:v for k,v in app.bindings.items() if v['mac']!=ap['mac']}
            app.wireless.save()
            app.radios.settings.pop(ap['mac'],None);app.radios.save()
            app.features.targets.pop(ap['mac'],None);app.features.save()
            app.edca.forget_ap(ap['mac'])
            app.balance.forget_ap(ap['mac'])
            app.station_policy.admission_aps.pop(ap['mac'],None);app.station_policy.commit(app.station_policy.rules)
        completed.append(ap['mac'])
    return {'status':'acknowledged','completed':completed,'message':'所选 AP 已确认指令'}


def export_csv(app):
    stream=io.StringIO(newline='');writer=csv.writer(stream)
    writer.writerow(['AP名称','备注','MAC地址','IP地址','型号','分组','接管方式','状态','终端数'])
    for ap in app.ap_rows():
        row=[ap.get(k,'') for k in ('entry_name','remark','mac','ip','model_name','group_name','adoption','management_label','client_num')]
        writer.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for v in row])
    return ('\ufeff'+stream.getvalue()).encode('utf8')
