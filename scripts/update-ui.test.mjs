import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

function ui() {
  const banner = { innerHTML: '', hidden: true, setAttribute() {}, querySelectorAll: () => [] };
  const events = {};
  const messages = [];
  const context = vm.createContext({
    document: { createElement: () => banner, body: { appendChild() {} }, getElementById: () => null },
    window: { addEventListener() {} },
    esc: String, toast: (...args) => messages.push(args),
    listen: (name, callback) => { events[name] = callback; },
    invoke: async () => ({ current: '1.0.0' }),
  });
  vm.runInContext(fs.readFileSync(new URL('../desktop/ui/update-upload.js', import.meta.url), 'utf8'), context);
  vm.runInContext('initUpdateEvents()', context);
  return { banner, events, messages };
}

test('Ubuntu auto download shows an in-app install button and password explanation', () => {
  const { banner, events } = ui();
  events['update-ready']({ payload: { version: '1.2.3', requires_confirmation: true } });
  assert.equal(banner.hidden, false);
  assert.match(banner.innerHTML, /立即更新/);
  assert.match(banner.innerHTML, /系統管理員密碼/);
  assert.doesNotMatch(banner.innerHTML, /結束或重新開啟/);
  assert.doesNotMatch(banner.innerHTML, /https?:/);
});

test('Mac and AppImage ready updates offer restart, and automatic failures are visible', () => {
  const { banner, events, messages } = ui();
  events['update-ready']({ payload: { version: '1.2.3', requires_confirmation: false } });
  assert.match(banner.innerHTML, /現在重新啟動並更新/);
  events['update-error']({ payload: { error: 'download failed' } });
  assert.match(messages[0][0], /download failed/);
});
