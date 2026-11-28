// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { el } from '../shared/client.mjs';

const stageLabels = { input: '输入检查', output: '输出检查', combined: '联合检查', stream_chunk: '流式分片', stream_end: '流式结束' };
const sourceLabels = { input: '用户输入', output: '工具返回', combined: '输入与返回联合命中' };
const actionLabels = { allow: '放行', escalate: '转人工审批', redact: '脱敏', block: '阻断' };
const formatTime = time => new Date(time).toLocaleTimeString('zh-CN', { hour12: false });
const scopeLabel = item => item.scope === 'global' ? '全局' : '客户端 ' + item.client;

export function renderInjectionAlerts(snapshot, selectedId, select) {
  const section = el('section', { class: 'lw-section', 'aria-labelledby': 'injection-alert-title' }, [
    el('h3', { id: 'injection-alert-title', text: '提示词注入告警' }),
  ]);
  const items = snapshot?.items || [];
  if (!items.length) {
    section.append(el('p', { class: 'lw-muted', text: snapshot?.unavailable ? '暂时无法读取本机告警记录。' : '最近 24 小时没有达到阈值的告警。' }));
    return section;
  }
  const current = items.find(item => item.id === selectedId) || items[0];
  const picker = el('select', {
    class: 'lw-select', id: 'injection-alert-picker', 'aria-label': '选择告警',
    onChange: event => select(Number(event.target.value)),
  }, items.map(item => el('option', { value: String(item.id),
    text: `#${item.id} · ${scopeLabel(item)} · ${item.active ? '触发中' : '已回落'} · ${formatTime(item.openedAt)}` })));
  picker.value = String(current.id);
  section.append(picker,
    el('p', { text: `最近一次命中时，10 分钟内有 ${current.count} 个独立请求，阈值 ${current.threshold}，涉及 ${current.clients} 个客户端。` }),
    el('p', { text: `用户输入 ${current.inputs} · 工具返回 ${current.outputs} · 联合来源 ${current.combined}。同一请求可命中多个来源。` }),
    el('p', { class: 'lw-muted', text: `首次触发 ${new Date(current.openedAt).toLocaleString('zh-CN')} · 最近更新 ${formatTime(current.updatedAt)}` }),
    el('h4', { text: '最近命中请求（最多 5 个）' }),
    el('ul', { class: 'lw-alert-samples' }, current.samples.map(sample => el('li', {}, [
      el('strong', { text: `${sourceLabels[sample.source]} · ${stageLabels[sample.stage]} · ${actionLabels[sample.action]}` }),
      el('div', { text: `工具 ${sample.tool} · 规则 ${sample.rule} · 客户端 ${sample.client}` }),
      el('code', { text: '请求摘要 ' + sample.request }),
    ]))),
  );
  return section;
}
