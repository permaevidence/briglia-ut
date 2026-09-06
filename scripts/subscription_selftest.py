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
let retryableFailures=0;
let calls=[], response={ok:true}, modelField={text:'gpt-5.6-luna'}, effortField={text:'high'};
let starts=0, stops=0; let poll={interval:0,start(){starts++},stop(){stops++}};
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
// Both error handlers release the handle and refresh account state; status
// failure must not recurse or disable a fresh login.
for (const action of ['poll','cancel']) {
  pending='old-handle'; loginCode='OLD'; calls=[];
  app.apiSubscription=(r, cb)=>{ calls.push(r); cb({ok:false}); };
  call({action:action,pending:pending},()=>{throw Error('error callback')});
  assert.equal(pending,''); assert.equal(loginCode,''); assert.equal(busy,false);
  assert.deepEqual(calls.map(r=>r.action),[action,'status']);
  app.apiSubscription=(r, cb)=>{ calls.push(r); cb({ok:true,pending:'new',code:'NEW',interval:1}); };
  start(); assert.equal(pending,'new'); assert.equal(loginCode,'NEW');
}
// A transient poll failure preserves the already approved code and retries;
// success resets the budget, while a bounded run of failures permits recovery.
pending='approved-handle'; loginCode='APPROVED'; calls=[]; poll.interval=5000;
app.apiSubscription=(r,cb)=>{ calls.push(r); cb({ok:false,error:{retryable:true}}); };
let retryStarts=starts;
check(); assert.equal(pending,'approved-handle'); assert.equal(loginCode,'APPROVED');
assert.equal(starts,retryStarts+1); assert.equal(retryableFailures,1); assert.equal(busy,false);
assert.deepEqual(calls.map(r=>r.action),['poll']); assert.equal(poll.interval,5000);
app.apiSubscription=(r,cb)=>{ cb({ok:true,state:'pending',interval:2}); };
check(); assert.equal(retryableFailures,0); assert.equal(pending,'approved-handle');
app.apiSubscription=(r,cb)=>{ cb({ok:false,error:{retryable:true}}); };
for (let i=0;i<6;i++) { check(); assert.equal(pending,'approved-handle'); }
check(); assert.equal(pending,''); assert.equal(loginCode,''); assert.equal(busy,false);
app.apiSubscription=(r,cb)=>{ cb({ok:true,pending:'replacement',code:'NEW',interval:1}); };
start(); assert.equal(retryableFailures,0); assert.equal(pending,'replacement');
app.apiSubscription=(r,cb)=>{ cb({ok:true,state:'signed_in',generation:'scope-B'}); };
check(); assert.equal(pending,''); assert.equal(loginCode,''); assert.equal(signedIn,true);
busy=true; pending='valid'; const before=starts; const beforeCalls=calls.length;
check(); assert.equal(starts,before+1); assert.equal(calls.length,beforeCalls);
busy=false; pending=''; check(); assert.equal(starts,before+1);
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

# Run the real API provider save handler, including model-specific Responses
# verification, and verify hidden scanned keys cannot block subscription setup.
source = provider
provider_js = r'''
const assert = require('assert');
const i18n={tr:s=>s}; String.prototype.arg=function(s){return this.replace('%1',s)};
let profileId='openai', catalog=[], wizardMode=true, stored=null, working=false;
let resultText='', resultIsError=false, keyInjected='old', savedOnce=false;
let modelField={text:'gpt-5.6-luna'}, keyField={text:'synthetic'}, baseUrlField={text:''};
let probes=[], applies=[], finished=null, modelSelector={selectedIndex:0};
let app={scannedKeys:{chatgpt:'forged-key'}, apiProbe(r,cb){probes.push(r);cb({ok:false})}, apiApply(r,cb){applies.push(r)}, describeError(){return 'bad model'}};
let page={app:app, fail(s){working=false}, buildApply(){return {}}};
'''
provider_js += '\n'.join(function(n) for n in ['save','syncScannedKey'])
provider_js += r'''
save(ok=>finished=ok);
assert.deepEqual(probes,[{kind:'responses',api_key:'synthetic',model:'gpt-5.6-luna'}]);
assert.equal(applies.length,0);assert.equal(finished,false);
profileId='chatgpt';syncScannedKey();assert.equal(keyField.text,'');assert.equal(keyInjected,'');
console.log('Provider handlers: Responses model probe, refusal before apply and hidden-key reset PASS');
'''
subprocess.run(['node','-e',provider_js],check=True)
