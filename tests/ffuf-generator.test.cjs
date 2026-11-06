'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const g = require('../assets/js/ffuf-generator.js');
const build = overrides => g.buildCommand({ ...g.defaults(), ...overrides });
function valid(state) { const r = build(state); assert.deepEqual(r.errors, []); assert.ok(r.command); return r; }
function has(r, flag, value) { const i = r.args.indexOf(flag); assert.notEqual(i, -1); if (value !== undefined) assert.equal(r.args[i+1], value); }
function invalid(state, field) { const r = build(state); assert.equal(r.command, ''); assert.ok(r.errors.some(e => e.field === field), JSON.stringify(r.errors)); }
test('basic directory command omits optional performance flags', () => {
 assert.equal(valid({}).command, "ffuf -u 'https://example.com/FUZZ' -w 'common.txt'");
});
test('verified medium wordlist and editable path', () => {
 const p = g.profileChanges('deep',true); assert.equal(p.wordlist,g.WORDLISTS[1].path);
 assert.match(p.wordlist,/DirBuster-2007_directory-list-2\.3-medium\.txt$/); has(valid(p),'-w',p.wordlist);
 has(valid({...p,wordlist:'/My Lists/Medium.txt'}),'-w','/My Lists/Medium.txt');
});
test('parameter name and parameter value fuzzing', () => {
 has(valid(g.profileChanges('param-names',false)),'-u','https://example.com/?FUZZ=test');
 valid({scanType:'query',url:'https://example.com/?name=FUZZ&keep=yes'});
});
test('header and vhost fuzzing with multiple headers', () => {
 const r=valid({scanType:'headers',url:'https://example.com/',headers:['X-Test: FUZZ','Accept: application/json']});
 assert.equal(r.args.filter(v=>v==='-H').length,2);
 has(valid(g.profileChanges('vhost',false)),'-H','Host: FUZZ.example.com');
});
test('POST and JSON body preserve single and double quotes', () => {
 const body=`{"name":"FUZZ", "note":"it's a $value; $(no)"}`;
 const r=valid({scanType:'form',url:'https://example.com/',method:'POST',body,headers:['Content-Type: application/json']});
 has(r,'-d',body); has(r,'-X','POST'); assert.ok(r.command.includes("'\"'\"'"));
});
test('POSIX quoting is exact and never interpolates values', () => {
 assert.equal(g.quote("a'b"),"'a'\"'\"'b'");
 for (const value of ['a b', '$(touch x); & | > <', '"quoted"', '`echo x`', 'line\nline']) assert.ok(g.quote(value).startsWith("'"));
 has(valid({wordlist:"/My Lists/O'Brien.txt"}),'-w',"/My Lists/O'Brien.txt");
});
test('raw file accepts unverified contents and excludes manual inputs', () => {
 const r=valid({scanType:'raw',requestFile:'req.txt',url:'invalid',method:'POST',headers:['Bad header'],body:'ignored',cookies:'ignored'});
 has(r,'-request','req.txt'); assert.ok(!r.args.includes('-u')); assert.ok(!r.args.includes('-d')); assert.ok(!r.args.includes('-H')); assert.ok(!r.args.includes('-X')); assert.ok(!r.args.includes('-b')); assert.ok(r.warnings.some(w=>w.includes('could not be verified')));
});
test('raw HTTP protocol and redirects are independent', () => {
 const r=valid({scanType:'raw',protocol:'http',requestFile:'my req.txt',redirects:true});
 has(r,'-request-proto','http'); const i=r.args.indexOf('-r'); assert.ok(i>=0); assert.notEqual(r.args[i+1],'my req.txt');
});
test('pasted raw request checks effective FUZZ locations', () => {
 for(const content of ['GET /FUZZ HTTP/1.1\nHost: example.com\n\n','POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nFUZZ','GET / HTTP/1.1\nHost: FUZZ.example.com\n\n']) valid({scanType:'raw',rawContent:content});
 invalid({scanType:'raw',rawContent:'GET / HTTP/FUZZ\nHost: example.com\n\n'},'rawContent');
 invalid({scanType:'raw',rawContent:'GET /#FUZZ HTTP/1.1\nHost: example.com\n\n'},'rawContent');
 invalid({scanType:'raw',requestFile:''},'requestFile');
});
test('all numeric matchers and filters support ranges', () => {
 for (const key of ['mc','fc','ms','fs','mw','fw','ml','fl']) has(valid({[key]:'200-299,301'}),'-'+key,'200-299,301');
 has(valid({mc:'all'}),'-mc','all'); invalid({fc:'all'},'fc');
 for(const value of ['-1','1.5','300-200','200,','text']) invalid({fs:value},'fs');
 invalid({mc:'99'},'mc'); invalid({fc:'600'},'fc');
});
test('regular expressions: Go flags and common invalid constructs', () => {
 for(const pattern of ['(?i)not found','^error [0-9]+$','(?P<name>test)','\\p{Greek}+','[[:alpha:]]+']) has(valid({fr:pattern}),'-fr',pattern);
 for(const pattern of ['[','(', '(?=x)', '(a)\\1', 'a{1001}']) invalid({mr:pattern},'mr');
});
test('response time and combination operators', () => {
 has(valid({mt:'>500',ft:'<100',mmode:'and',fmode:'or'}),'-mt','>500');
 invalid({ft:'>=100'},'ft'); invalid({mmode:'xor'},'mmode');
});
test('calibration, quiet, verbose and more options', () => {
 const r=valid({calibration:true,perHost:true,quiet:true,verbose:true,ignoreComments:true,proxy:'http://127.0.0.1:8080',replayProxy:'socks5://127.0.0.1:9050'});
 for(const flag of ['-ac','-ach','-s','-v','-ic','-x','-replay-proxy']) has(r,flag);
 invalid({perHost:true},'perHost'); invalid({proxy:'ftp://example.com'},'proxy');
});
test('threads rate timeout delay and omitted optional defaults', () => {
 const r=valid({threads:'5',rate:'10',timeout:'15',delay:'0.1-2.0'});
 has(r,'-t','5');has(r,'-rate','10');has(r,'-timeout','15');has(r,'-p','0.1-2.0');
 assert.ok(!valid({threads:'',rate:''}).args.includes('-t'));
 for(const [key,value] of [['threads','0'],['rate','-1'],['timeout','a'],['threads','2.5'],['delay','2-1'],['delay','-1']]) invalid({[key]:value},key);
});
test('recursion compatible paths depth strategy and inactive settings', () => {
 const r=valid({recursion:true,depth:'2',strategy:'greedy'});has(r,'-recursion');has(r,'-recursion-depth','2');has(r,'-recursion-strategy','greedy');
 for(const state of [{url:'https://example.com/FUZZ/'},{url:'https://example.com/?x=FUZZ'},{scanType:'raw'},{scanType:'vhost'}]) invalid({...state,recursion:true},'recursion');
 assert.ok(!valid({recursion:false,depth:'2',strategy:'greedy'}).args.includes('-recursion-depth'));
 invalid({recursion:true,depth:'-1'},'depth');
});
test('each documented output format', () => {
 for(const format of ['json','ejson','html','md','csv','ecsv','all']) has(valid({output:'my results',format}),'-of',format);
 invalid({format:'json'},'output');invalid({format:'xml',output:'x'},'format');
});
test('missing inputs FUZZ and injection-safe header validation', () => {
 invalid({url:''},'url');invalid({wordlist:''},'wordlist');invalid({url:'ftp://example.com/FUZZ'},'url');
 invalid({url:'https://example.com/'},'url');invalid({url:'https://example.com/#FUZZ'},'url');
 invalid({headers:['X: FUZZ\nOther: value']},'headers-list');invalid({wordlist:'foo\0bar'},'wordlist');
 invalid({wordlist:'foo:OTHER'},'wordlist');valid({wordlist:'foo:FUZZ'});
 valid({url:'https://example.com/',cookies:'test=FUZZ'});
});
test('each profile creates a valid configuration; profiles do not mutate state', () => {
 for(const name of ['quick','deep','noise','param-names','param-values','vhost','raw']) valid(g.profileChanges(name,false));
 const state=g.defaults(),snapshot=JSON.stringify(state);g.buildCommand(state);assert.equal(JSON.stringify(state),snapshot);
});
test('copy command success failure and invalid empty command', async () => {
 let copied='';assert.equal(await g.copyCommand('ffuf -h',{writeText:async x=>{copied=x}}),true);assert.equal(copied,'ffuf -h');
 assert.equal(await g.copyCommand('x',{writeText:async()=>{throw Error('denied')}}),false);
 assert.equal(await g.copyCommand('x',undefined),false);assert.equal(await g.copyCommand('',{writeText:()=>{throw Error('must not call')}}),false);
});


test('parameter profiles select distinct FUZZ locations and wordlists', () => {
 for (const pwnbox of [false,true]) {
  const names=g.profileChanges('param-names',pwnbox), values=g.profileChanges('param-values',pwnbox);
  assert.equal(names.scanType,'query');assert.equal(values.scanType,'query');
  assert.equal(names.url,'https://example.com/?FUZZ=test');assert.equal(values.url,'https://example.com/?id=FUZZ');
  assert.ok(names.wordlist.endsWith('burp-parameter-names.txt'));assert.equal(values.wordlist,'values.txt');
  has(valid(names),'-u',names.url);has(valid(values),'-w','values.txt');
 }
});
test('all profiles omit performance defaults and preserve explicit custom speed', () => {
 for (const name of ['quick','deep','noise','param-names','param-values','vhost','raw']) {
  for (const pwnbox of [false,true]) {
   const profile=g.profileChanges(name,pwnbox), r=valid(profile);
   assert.ok(!r.args.includes('-t'));assert.ok(!r.args.includes('-rate'));
   const custom=valid({...g.defaults(),threads:'15',rate:'25',...profile});
   has(custom,'-t','15');has(custom,'-rate','25');
  }
 }
 assert.ok(!valid({threads:'',rate:''}).args.includes('-rate'));
 has(valid({rate:'0'}),'-rate','0');
 invalid({threads:'-1'},'threads');invalid({rate:'1.5'},'rate');
});
test('manual edits are copyable until the next form-driven generation', async () => {
 const editor=g.createCommandEditor();const base=valid({}).command;editor.generate(base);
 const text=`  ffuf -w "my list.txt" -H "X: it's $VALUE"
-s  `;
 editor.edit(text);assert.equal(editor.value,text);assert.equal(editor.edited,true);
 let copied;await g.copyCommand(editor.value,{writeText:async value=>{copied=value}});assert.equal(copied,text);
 for (const state of [{threads:'15'},{fc:'404'},...['quick','param-names','param-values','raw'].map(name=>g.profileChanges(name,false))]) {
  editor.edit(text);const generated=valid(state).command;editor.generate(generated);
  assert.equal(editor.value,generated);assert.equal(editor.edited,false);
 }
 // Even a mode change that regenerates the same text ends the temporary edit.
 editor.edit(text);editor.generate(base);assert.equal(editor.value,base);assert.equal(editor.edited,false);
 editor.edit(text);editor.generate(build({url:''}).command);assert.equal(editor.value,'');assert.equal(editor.canCopy,false);
 editor.generate(base);editor.edit(text);editor.reset();assert.equal(editor.value,base);assert.equal(editor.edited,false);
 editor.edit('');assert.equal(editor.canCopy,false);editor.generate(base);assert.equal(editor.canCopy,true);
});

test('initial HTML reserves the generator and has one shared pair of speed inputs', () => {
 const html=require('node:fs').readFileSync(require('node:path').join(__dirname,'../tools/ffuf/index.html'),'utf8');
 const form=html.match(/<form[^>]+id="ffuf-form"[^>]*>/)[0];
 assert.ok(!/\bhidden\b/.test(form));assert.match(form,/\binert\b/);
 for(const key of ['threads','rate']) {
  assert.equal((html.match(new RegExp('id="'+key+'"','g'))||[]).length,1);
  assert.match(html,new RegExp('<input[^>]+id="'+key+'"[^>]+value=""'));
 }
 assert.match(html,/<textarea id="command"[^>]*>ffuf -u 'https:\/\/example.com\/FUZZ' -w 'common.txt'<\/textarea>/);
 assert.equal((html.match(/data-profile="param-(names|values)"/g)||[]).length,2);
});

test('username presets preserve exact paths and allow custom paths', () => {
 const paths=['/usr/share/seclists/Usernames/top-usernames-shortlist.txt','/usr/share/seclists/Usernames/Names/names.txt','/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'];
 assert.deepEqual(g.WORDLISTS.slice(6).map(item=>item.path),paths);
 for(const wordlist of paths) has(valid({wordlist}),'-w',wordlist);
 has(valid({wordlist:'/tmp/custom usernames.txt'}),'-w','/tmp/custom usernames.txt');
 assert.equal(g.WORDLISTS.length,9);
});

test('RockYou warning depends on selected preset and HTB, not filenames', () => {
 for(const preset of g.WORDLISTS.map(w=>w.id).concat('custom')) {
  assert.equal(g.rockYouSelected({pwnbox:true,wordlistPreset:preset}),preset==='rockyou');
  assert.equal(g.rockYouSelected({pwnbox:false,wordlistPreset:preset}),false);
 }
});
test('only the exact built-in RockYou destination expands HOME', () => {
 const state={pwnbox:true,wordlistPreset:'rockyou',wordlist:'$HOME/wordlists/rockyou.txt'};
 assert.ok(valid(state).command.includes('-w "$HOME/wordlists/rockyou.txt"'));
 for(const change of [{pwnbox:false},{wordlistPreset:'custom'},{wordlist:'$HOME/wordlists/rockyou.txt; $(whoami)'}]) {
  const custom={...state,...change};assert.ok(valid(custom).command.includes('-w '+g.quote(custom.wordlist)));
 }
 const raw=valid({...state,scanType:'raw',requestFile:'-w'}).command;
 assert.ok(raw.includes("-request '-w'"));assert.ok(raw.includes('-w "$HOME/wordlists/rockyou.txt"'));
 assert.equal(g.ROCKYOU_EXTRACT,'mkdir -p "$HOME/wordlists" && gzip -dc /usr/share/wordlists/rockyou.txt.gz > "$HOME/wordlists/rockyou.txt" && test -s "$HOME/wordlists/rockyou.txt" && echo "Wordlist ready"');
});
test('verified plaintext web and parameter paths are unchanged', () => {
 const names=['common.txt','DirBuster-2007_directory-list-2.3-medium.txt','raft-medium-directories.txt','big.txt','burp-parameter-names.txt'];
 assert.deepEqual(g.WORDLISTS.slice(0,5).map(w=>w.path),names.map(n=>'/usr/share/seclists/Discovery/Web-Content/'+n));
});
