// SPDX-License-Identifier: AGPL-3.0-only
// Drive the installed guest browser in its own test session.
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';

export async function waitFor(read, timeout = 10000, timeoutCode = 'BROWSER_STATE_TIMEOUT') {
  const deadline = Date.now() + timeout;
  do {
    const result = await read();
    if (result) return result;
    await sleep(80);
  } while (Date.now() < deadline);
  throw Object.assign(new Error('Timed out waiting for browser state'), { code: timeoutCode });
}

async function launch(executable, args) {
  const child = spawn(executable, args, { stdio: 'ignore' });
  await once(child, 'spawn');
  return child;
}

async function waitForExit(child, timeout) {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  try {
    await once(child, 'exit', { signal: AbortSignal.timeout(timeout) });
    return true;
  } catch (error) {
    if (error.code !== 'ABORT_ERR') throw error;
    return child.exitCode !== null || child.signalCode !== null;
  }
}

async function stop(child, graceMs = 0) {
  if (graceMs && await waitForExit(child, graceMs)) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  if (!await waitForExit(child, 30000)) {
    throw Object.assign(new Error('Browser process did not exit'), { code: 'BROWSER_EXIT_TIMEOUT' });
  }
}

async function loopbackPort() {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const { port } = listener.address();
  await new Promise((resolve, reject) => listener.close(err => err ? reject(err) : resolve()));
  return port;
}

async function openSafari() {
  const port = await loopbackPort();
  const child = await launch('/usr/bin/safaridriver', ['-p', String(port)]);
  let session;
  async function command(method, route, data) {
    const response = await fetch('http://127.0.0.1:' + port + route, {
      method, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data), signal: AbortSignal.timeout(35000),
    });
    const { value } = await response.json();
    if (!response.ok || value?.error) {
      const error = new Error('Safari WebDriver command failed');
      if (route === '/session' && /allow remote automation/i.test(value?.message ?? '')) {
        error.code = 'SAFARI_AUTOMATION_DISABLED';
      }
      throw error;
    }
    return value;
  }
  const request = (route, data) => command('POST', '/session/' + session + route, data);
  try {
    await waitFor(() => command('GET', '/status').catch(() => false));
    const started = await command('POST', '/session', { capabilities: { alwaysMatch: { browserName: 'safari' } } });
    session = started.sessionId;
    if (!session || started.capabilities.browserName.toLowerCase() !== 'safari') throw new Error('Expected Safari');
    const keys = { Enter: '\uE007', Escape: '\uE00C', Tab: '\uE004', ShiftTab: '\uE004', Space: ' ' };
    return {
      version: 'Safari ' + started.capabilities.browserVersion,
      navigate: url => request('/url', { url }),
      resize: width => request('/window/rect', { x: 0, y: 35, width, height: 750 }),
      evaluate: (fn, ...args) => request('/execute/sync', { script: 'return (' + fn + ')(...arguments)', args }),
      async press(key) {
        const actions = [{ type: 'keyDown', value: keys[key] }, { type: 'keyUp', value: keys[key] }];
        if (key === 'ShiftTab') {
          actions.unshift({ type: 'keyDown', value: '\uE008' });
          actions.push({ type: 'keyUp', value: '\uE008' });
        }
        await request('/actions', { actions: [{ type: 'key', id: 'keyboard', actions }] });
      },
      async close() {
        try { await command('DELETE', '/session/' + session); }
        finally { await stop(child); }
      },
    };
  } catch (err) {
    await stop(child);
    throw err;
  }
}

function devToolsConnection(socket) {
  let sequence = 0;
  const pending = new Map();
  socket.addEventListener('message', ({ data }) => {
    const { id, result, error } = JSON.parse(data);
    const request = pending.get(id);
    if (request) error ? request.reject(new Error('Edge DevTools command failed')) : request.resolve(result);
  });
  socket.addEventListener('close', () => {
    for (const request of pending.values()) request.reject(new Error('Edge closed its test session'));
  });
  return async (method, params = {}) => {
    if (socket.readyState !== WebSocket.OPEN) throw new Error('Edge test session unavailable');
    const id = ++sequence;
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        timer = setTimeout(() => reject(new Error('Edge DevTools timeout')), 15000);
        socket.send(JSON.stringify({ id, method, params }));
      });
    } finally {
      clearTimeout(timer);
      pending.delete(id);
    }
  };
}

async function openEdge(profileDir) {
  const executable = path.join(process.env['ProgramFiles(x86)'], 'Microsoft/Edge/Application/msedge.exe');
  const child = await launch(executable, [
    '--user-data-dir=' + profileDir, '--remote-debugging-port=0', '--no-first-run',
    '--disable-first-run-ui', '--disable-default-apps', '--window-size=680,820', 'about:blank',
  ]);
  let socket;
  try {
    const port = await waitFor(async () => {
      const data = await fs.readFile(path.join(profileDir, 'DevToolsActivePort'), 'utf8').catch(() => '');
      return Number(data.split(/\r?\n/)[0]);
    }, 45000, 'EDGE_PORT_TIMEOUT');
    // Edge publishes DevToolsActivePort before its HTTP endpoint and initial tab are ready.
    const read = async route => {
      try {
        const response = await fetch('http://127.0.0.1:' + port + route, { signal: AbortSignal.timeout(5000) });
        return response.ok ? await response.json() : null;
      } catch (error) {
        if (error.name === 'TimeoutError' || error instanceof TypeError) return null;
        throw error;
      }
    };
    const version = await waitFor(async () => (await read('/json/version'))?.Browser, 30000, 'EDGE_VERSION_TIMEOUT');
    if (!/^Edg\/[\d.]+$/.test(version)) throw new Error('Expected Microsoft Edge');
    const page = await waitFor(async () => (await read('/json/list'))?.find(
      target => target.type === 'page' && target.url === 'about:blank',
    ), 30000, 'EDGE_TAB_TIMEOUT');
    socket = new WebSocket(page.webSocketDebuggerUrl);
    await once(socket, 'open', { signal: AbortSignal.timeout(10000) });
    const send = devToolsConnection(socket);
    const keys = { Enter: ['Enter', 13, '\r'], Escape: ['Escape', 27, ''], Space: [' ', 32, ' '], Tab: ['Tab', 9, ''], ShiftTab: ['Tab', 9, ''] };
    return {
      version,
      async navigate(url) {
        await send('Page.bringToFront');
        await send('Page.navigate', { url });
      },
      async resize(width) {
        if (width < 650) {
          await send('Emulation.setDeviceMetricsOverride', { width, height: 800, deviceScaleFactor: 1, mobile: false });
        } else {
          await send('Emulation.clearDeviceMetricsOverride');
          const { windowId } = await send('Browser.getWindowForTarget');
          await send('Browser.setWindowBounds', { windowId, bounds: { width, height: 800, windowState: 'normal' } });
        }
      },
      async evaluate(fn, ...args) {
        const expression = '(' + fn + ')(...' + JSON.stringify(args) + ')';
        const response = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
        if (response.exceptionDetails) throw new Error('Edge page evaluation failed');
        return response.result.value;
      },
      async press(key) {
        const [value, windowsVirtualKeyCode, text] = keys[key];
        const params = { key: value, code: key === 'Space' ? 'Space' : value, windowsVirtualKeyCode, modifiers: key === 'ShiftTab' ? 8 : 0 };
        await send('Input.dispatchKeyEvent', { ...params, type: text ? 'keyDown' : 'rawKeyDown', text, unmodifiedText: text });
        await send('Input.dispatchKeyEvent', { ...params, type: 'keyUp' });
      },
      async close() {
        // Edge may close the socket before acknowledging Browser.close.
        try { await send('Browser.close').catch(() => {}); }
        finally { socket.close(); await stop(child, 15000); }
      },
    };
  } catch (err) {
    socket?.close();
    await stop(child);
    throw err;
  }
}

export function openNativeBrowser(work) {
  if (process.platform === 'darwin') return openSafari();
  if (process.platform === 'win32') return openEdge(path.join(work, 'edge-profile'));
  throw new Error('A Windows or macOS test desktop is required');
}
