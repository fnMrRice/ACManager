'use strict';
'require view';
'require form';
'require uci';
'require rpc';

var getLAN = rpc.declare({ object: 'network.interface.lan', method: 'status', expect: {} });

return view.extend({
    load: function() { return Promise.all([uci.load('tplink_ac'), getLAN()]); },
    render: function(data) {
        var m = new form.Map('tplink_ac', 'TP-LINK AC',
            '使用独立的 AC 管理网页。此处只设置网页访问账号和端口。');
        var s = m.section(form.NamedSection, 'main', 'service', 'AP管理');
        var o = s.option(form.Flag, 'enabled', '启用');
        o.rmempty = false;
        o = s.option(form.Value, 'port', '后台端口');
        o.datatype = 'port'; o.default = '8765'; o.rmempty = false;
        o = s.option(form.Value, 'username', '用户名');
        o.datatype = 'and(minlength(1),maxlength(64))'; o.rmempty = false;
        o = s.option(form.Value, 'password', '密码');
        o.password = true; o.rmempty = false;
        o.validate = function(section, value) {
            if (!value && s.children[0].formvalue(section) !== '1') return true;
            return value && value.length >= 12 && value.length <= 256 ? true : '请输入 12 至 256 个字符的密码';
        };
        var addresses = data[1]['ipv4-address'] || [];
        var host = addresses.length ? addresses[0].address : null;
        var port = uci.get('tplink_ac', 'main', 'port');
        var enabled = uci.get('tplink_ac', 'main', 'enabled') === '1';
        var entry = E('p');
        if (enabled && host && /^\d+\.\d+\.\d+\.\d+$/.test(host) && /^\d+$/.test(port)) {
            entry.appendChild(E('button', { 'class': 'cbi-button cbi-button-action', type: 'button',
                click: function() {
                    // Submit saved credentials to the new tab, never in its URL.
                    var login = E('form', { method: 'post',
                        action: 'http://' + host + ':' + port + '/login/luci',
                        target: '_blank', rel: 'noopener', style: 'display:none' });
                    ['username', 'password'].forEach(function(name) {
                        login.appendChild(E('input', { type: 'hidden', name: name,
                            value: uci.get('tplink_ac', 'main', name) || '' }));
                    });
                    document.body.appendChild(login);
                    try { login.submit(); } finally {
                        window.setTimeout(function() { login.remove(); }, 1000);
                    }
                }
            }, '打开 AC 管理页面'));
        }
        return m.render().then(function(node) { node.appendChild(entry); return node; });
    }
});
