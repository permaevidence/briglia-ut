#!/usr/bin/env python3
"""Execute subscription-page JavaScript handlers with an isolated fake bridge."""
from pathlib import Path
import json
import subprocess
root = Path(__file__).resolve().parents[1]
source = (root / 'qml/pages/SubscriptionPage.qml').read_text()
# Functions here have balanced braces; strings do not contain brace delimiters.
def function(name):
    start = source.index('    function ' + name + '(')
    opening = source.index('{', start)
    depth = 1
    pos = opening + 1
    while depth:
        depth += (source[pos] == '{') - (source[pos] == '}')
        pos += 1
    return source[start:pos]
js = r'''
const assert = require('assert');
String.prototype.arg = function(s) { return this.replace('%1', s); };
const i18n = {tr:s=>s};
let busy=false, alive=true, pending='', generation='scope-A', loginCode='', message='', signedIn=false;
let calls=[], response={ok:true}, modelField={text:'gpt-5.6-luna'}, effortField={text:'high'};
let poll={interval:0,start(){},stop(){}};
let app={apiSubscription(req, cb){calls.push(req);cb(response)},describeError(r){return 'failed'},refresh(){}};
let page = new Proxy({}, {get(_,k) { return eval(k) }, set(_,k,v) { eval(k+'=v'); return true }});
'''
js += '\n'.join(function(n) for n in ['call', 'status', 'start', 'check', 'cancel', 'save'])
js += r'''
response={ok:false}; save();
assert.equal(calls.length,1); assert.equal(calls[0].action,'probe'); assert.equal(busy,false);
calls=[]; app.apiSubscription=(r, cb)=>{ calls.push(r);cb({ok:true,generation:'scope-A'}); };
save(); assert.equal(calls.length,2); assert.deepEqual(calls[1],{action:'select',model:'gpt-5.6-luna',effort:'high',generation:'scope-A',activate:true});
calls=[]; pending='handle'; cancel(); assert.equal(calls[0].pending,'handle'); assert.equal(calls[0].action,'cancel');
alive=false; busy=true; call({action:'start'},()=>{throw Error('dead page callback')});
page=null; call({action:'status'},()=>{throw Error('destroyed page callback')});
console.log('Subscription QML handlers: failed probe, exact selection, cancellation and destroyed page PASS');
'''
subprocess.run(['node', '-e', js], check=True)
assert 'textFormat: Text.PlainText; text: page.loginCode' in source
assert 'https://auth.openai.com/codex/device' in source
assert 'access_token' not in source and 'refresh_token' not in source
quick = (root / 'qml/pages/QuickSetupPage.qml').read_text()
assert 'if (!useSubscription && rowState("main")' in quick
assert 'app.pushPage("SubscriptionPage.qml", {})' in quick
provider = (root / 'qml/pages/ProviderPage.qml').read_text()
assert 'ChatGPT subscription' in provider and 'OpenAI API (separate billing)' in provider
assert 'subscription_setup.supported === true' in provider
assert 'visible: !page.wizardMode && page.profileId !== \"chatgpt\"' in provider
print('Subscription UI capability gating, API/provider separation and Quick Setup integration PASS')
