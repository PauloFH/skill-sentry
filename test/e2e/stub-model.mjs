// A scripted stand-in for the model APIs, so the real Claude Code and Codex CLIs run a tool call (and spawn the
// installed hook) without a real model or any secret. Zero dependencies; loopback only; no side effects at import.
//
// Wire formats, checked against the pinned CLIs:
// - Claude Code 2.1.330 uses the Anthropic SDK bundled in its binary: POST /v1/messages?beta=true, streamed as SSE
//   (message_start, content_block_start, content_block_delta with input_json_delta / text_delta,
//   content_block_stop, message_delta with stop_reason, message_stop), or one JSON message when `stream` is false.
// - Codex 0.171.0 speaks only the Responses wire API (model-provider-info WireApi::Responses; "chat" is rejected):
//   POST <base_url>/responses, streamed as SSE `event: <type>` / `data: <json>` with response.created,
//   response.output_item.done (a function_call item: call_id, name, arguments) and response.completed — the same
//   events codex-rs/core/tests/common/responses.rs builds for Codex's own tests.
//
// Every model turn that offers a shell tool and has no tool result yet gets one call of that tool running
// `state.command`; a turn that carries a tool result (or offers no shell tool) gets a short text answer. Every
// request is recorded in `requests`, and tool results are collected in `toolResults` for the assertions.
import http from 'node:http';

const sseEvent = (type, data) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;

function readBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      try { resolve(JSON.parse(raw)); } catch { resolve(raw); }
    });
  });
}

const textOf = content => (typeof content === 'string' ? content
  : Array.isArray(content) ? content.map(c => (typeof c === 'string' ? c : c?.text ?? textOf(c?.content) ?? '')).join('\n') : '');

// ---- Anthropic Messages (Claude Code)

function claudeToolResults(body) {
  const last = Array.isArray(body?.messages) ? body.messages.at(-1) : null;
  if (!last || last.role !== 'user' || !Array.isArray(last.content)) return [];
  return last.content.filter(c => c?.type === 'tool_result').map(c => ({ isError: c.is_error === true, text: textOf(c.content) }));
}

function claudeReply(res, body, block, stopReason) {
  const message = {
    id: `msg_e2e_${Date.now()}`, type: 'message', role: 'assistant', model: body?.model ?? 'stub',
    content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 },
  };
  if (body?.stream !== true) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ...message, content: [block], stop_reason: stopReason }));
    return;
  }
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  let out = sseEvent('message_start', { type: 'message_start', message });
  if (block.type === 'tool_use') {
    out += sseEvent('content_block_start', { type: 'content_block_start', index: 0, content_block: { ...block, input: {} } });
    out += sseEvent('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: JSON.stringify(block.input) } });
  } else {
    out += sseEvent('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
    out += sseEvent('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: block.text } });
  }
  out += sseEvent('content_block_stop', { type: 'content_block_stop', index: 0 });
  out += sseEvent('message_delta', { type: 'message_delta', delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 1 } });
  out += sseEvent('message_stop', { type: 'message_stop' });
  res.end(out);
}

// ---- Responses API (Codex)

function codexToolResults(body) {
  const input = Array.isArray(body?.input) ? body.input : [];
  return input.filter(i => i?.type === 'function_call_output' || i?.type === 'custom_tool_call_output')
    .map(i => ({ isError: false, text: typeof i.output === 'string' ? i.output : JSON.stringify(i.output) }));
}

/** The shell tool Codex offered and the arguments that run `command` through it. */
function codexShellCall(body, command) {
  const tools = Array.isArray(body?.tools) ? body.tools : [];
  const names = tools.map(t => t?.name ?? t?.function?.name).filter(Boolean);
  if (names.includes('exec_command')) return { name: 'exec_command', arguments: JSON.stringify({ cmd: command }) };
  if (names.includes('shell_command')) return { name: 'shell_command', arguments: JSON.stringify({ command }) };
  if (names.includes('shell')) {
    const argv = process.platform === 'win32' ? ['powershell.exe', '-NoProfile', '-Command', command] : ['bash', '-lc', command];
    return { name: 'shell', arguments: JSON.stringify({ command: argv }) };
  }
  return null;
}

function codexReply(res, items) {
  const id = `resp_e2e_${Date.now()}`;
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  let out = sseEvent('response.created', { type: 'response.created', response: { id } });
  for (const item of items) out += sseEvent('response.output_item.done', { type: 'response.output_item.done', item });
  out += sseEvent('response.completed', {
    type: 'response.completed',
    response: { id, usage: { input_tokens: 0, input_tokens_details: null, output_tokens: 0, output_tokens_details: null, total_tokens: 0 } },
  });
  res.end(out);
}

/**
 * Start the stub on 127.0.0.1 (random port). Returns { url, state, requests, toolCalls, toolResults, close }.
 * Set `state.command` before each CLI run; `reset()` clears the recordings.
 */
export async function startStubModel() {
  const state = { command: null };
  const requests = [];
  const toolCalls = [];
  const toolResults = [];
  let n = 0;
  const server = http.createServer(async (req, res) => {
    const body = await readBody(req);
    const path = (req.url ?? '').split('?')[0];
    requests.push({ method: req.method, path, tools: Array.isArray(body?.tools) ? body.tools.map(t => t?.name ?? t?.function?.name) : [] });
    try {
      if (req.method === 'POST' && path.endsWith('/v1/messages')) {
        const results = claudeToolResults(body);
        toolResults.push(...results.map(r => ({ agent: 'claude', ...r })));
        const offersBash = Array.isArray(body?.tools) && body.tools.some(t => t?.name === 'Bash');
        if (!results.length && offersBash && state.command) {
          const input = { command: state.command, description: 'skill-sentry e2e probe' };
          toolCalls.push({ agent: 'claude', name: 'Bash', input });
          claudeReply(res, body, { type: 'tool_use', id: `toolu_e2e_${++n}`, name: 'Bash', input }, 'tool_use');
        } else {
          claudeReply(res, body, { type: 'text', text: 'Done.' }, 'end_turn');
        }
        return;
      }
      if (req.method === 'POST' && path.endsWith('/responses')) {
        const results = codexToolResults(body);
        toolResults.push(...results.map(r => ({ agent: 'codex', ...r })));
        const call = !results.length && state.command ? codexShellCall(body, state.command) : null;
        if (call) {
          toolCalls.push({ agent: 'codex', ...call });
          codexReply(res, [{ type: 'function_call', call_id: `call_e2e_${++n}`, ...call }]);
        } else {
          codexReply(res, [{ type: 'message', role: 'assistant', id: `msg_e2e_${++n}`, content: [{ type: 'output_text', text: 'Done.' }] }]);
        }
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'not_found', message: `stub: ${req.method} ${path}` } }));
    } catch (e) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'stub_error', message: String(e?.message ?? e) } }));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    state, requests, toolCalls, toolResults,
    reset() { requests.length = 0; toolCalls.length = 0; toolResults.length = 0; },
    close: () => new Promise(resolve => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}
