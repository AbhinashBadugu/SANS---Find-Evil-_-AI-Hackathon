const $ = (s) => document.querySelector(s);
const messagesEl = $("#messages");
const reportEl = $("#report");
const picker = $("#report-picker");
const statusEl = $("#status");
const input = $("#input");
const sendBtn = $("#send");

// Conversation state sent to the backend (Anthropic message format: text only).
const history = [];
let streaming = false;
const CASE = "srl2015";

// ---------- helpers ----------
// Render markdown if the library is present; otherwise (e.g. CDN/script blocked)
// fall back to escaped plain text so the chat never silently fails to render.
function md(text) {
  text = text || "";
  if (typeof marked !== "undefined" && marked.parse) {
    try { return marked.parse(text); } catch (e) { /* fall through to plain text */ }
  }
  return "<p>" + escapeHtml(text).replace(/\n/g, "<br>") + "</p>";
}

function addMsg(role, text) {
  const el = document.createElement("div");
  el.className = `msg ${role}`;
  if (role === "assistant") {
    el.innerHTML = `<div class="markdown">${md(text)}</div>`;
  } else {
    el.textContent = text;
  }
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return el;
}

function addTool(name, input) {
  const el = document.createElement("div");
  el.className = "tool";
  el.innerHTML = `<span class="name">${name}</span>(<span class="args">${
    escapeHtml(JSON.stringify(input || {}))}</span>)`;
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return el;
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

// ---------- chat streaming ----------
async function send(text) {
  if (streaming || !text.trim()) return;
  streaming = true; sendBtn.disabled = true;
  addMsg("user", text);
  history.push({ role: "user", content: text });

  // Lazily open assistant bubbles so order reads: text → tool → text → tool …
  let body = null, acc = "";
  const fullText = [];
  const openBubble = () => {
    body = addMsg("assistant", "").querySelector(".markdown");
    body.classList.add("cursor"); acc = "";
  };
  const closeBubble = () => { if (body) { body.classList.remove("cursor"); if (acc.trim()) fullText.push(acc); } body = null; };

  try {
    const resp = await fetch("/api/chat", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: history }),
    });
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      // sse_starlette frames events with CRLF; normalize so the \n\n split works.
      buf += dec.decode(value, { stream: true });
      buf = buf.replace(/\r\n/g, "\n");
      const parts = buf.split("\n\n");
      buf = parts.pop();
      for (const part of parts) handleEvent(part, {
        onText: (t) => { if (!body) openBubble(); acc += t; body.innerHTML = md(acc); body.classList.add("cursor"); messagesEl.scrollTop = messagesEl.scrollHeight; },
        onTool: () => closeBubble(),
      });
    }
  } catch (e) {
    if (!body) openBubble();
    acc += `\n\n_(connection error: ${e})_`; body.innerHTML = md(acc);
  }
  closeBubble();
  if (fullText.join("").trim()) history.push({ role: "assistant", content: fullText.join("\n\n") });
  // A tool may have produced a new report/score — refresh the side panel.
  refreshReports();
  streaming = false; sendBtn.disabled = false;
}

function handleEvent(raw, cb) {
  // SSE: an event may have multiple `data:` lines; rejoin them with "\n" and strip
  // only the single separator space — never trim, or streamed token whitespace breaks.
  let event = "message";
  const dataLines = [];
  for (const line of raw.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
  }
  const data = dataLines.join("\n");
  if (event === "text") { cb.onText(data); }
  else if (event === "tool_use") {
    cb.onTool();
    try { const d = JSON.parse(data); addTool(d.name, d.input); } catch {}
  }
  else if (event === "tool_result") {
    try {
      const d = JSON.parse(data);
      const tools = messagesEl.querySelectorAll(".tool");
      const last = tools[tools.length - 1];
      if (last && !last.classList.contains("ok")) {
        last.classList.add("ok");
        const r = document.createElement("div"); r.className = "res";
        const s = JSON.stringify(d.result);
        r.textContent = s.length > 240 ? s.slice(0, 240) + " …" : s;
        last.appendChild(r);
      }
    } catch {}
  }
  else if (event === "error") {
    addMsg("assistant", `⚠️ ${data}`);
  }
}

// ---------- side report panel ----------
async function refreshReports() {
  // populate the picker once
  if (picker.options.length <= 1) {
    try {
      const cases = await (await fetch("/api/cases")).json();
      const c = (cases.cases || []).find((x) => x.case === CASE) || (cases.cases || [])[0];
      if (c) {
        addOption(`Cross-host CASE_REPORT (${c.case})`, `report:${c.case}:`);
        for (const h of c.hosts) addOption(`Host report — ${h}`, `report:${c.case}:${h}`);
        addOption(`★ Accuracy score vs oracle (${c.case})`, `score:${c.case}`);
      }
    } catch {}
  }
}
function addOption(label, value) {
  const o = document.createElement("option"); o.value = value; o.textContent = label;
  picker.appendChild(o);
}

picker.addEventListener("change", async () => {
  const v = picker.value; if (!v) return;
  reportEl.innerHTML = `<p class="muted">loading…</p>`;
  if (v.startsWith("report:")) {
    const [, c, h] = v.split(":");
    const url = `/api/case/${c}/report` + (h ? `?host=${h}` : "");
    const r = await (await fetch(url)).json();
    reportEl.innerHTML = r.markdown ? `<div class="markdown">${md(r.markdown)}</div>`
      : `<p class="muted">${r.error || "no report"}</p>`;
  } else if (v.startsWith("score:")) {
    const c = v.split(":")[1];
    const s = await (await fetch(`/api/case/${c}/score`)).json();
    reportEl.innerHTML = renderScore(s);
  }
});

function renderScore(s) {
  if (s.error) return `<p class="muted">${s.error}</p>`;
  const cq = s.citation_quality || {};
  const rows = (s.hits || []).map((h) => `<li>✅ ${h}</li>`).join("")
    + (s.missed || []).map((m) => `<li class="muted">— ${m}</li>`).join("");
  return `<div class="markdown">
    <h2>Accuracy vs oracle_v2</h2>
    <table><tbody>
      <tr><td><b>Recall (weighted)</b></td><td>${s.recall}</td></tr>
      <tr><td>Wrong / hallucinated</td><td>${(s.wrong_milestones||[]).length} (target 0)</td></tr>
      <tr><td>Extra unsupported</td><td>${cq.extra_unsupported_count} (target 0)</td></tr>
      <tr><td>Full-citation quality</td><td>${cq.full_citation_pct}%</td></tr>
    </tbody></table>
    <h3>Milestones</h3><ul>${rows}</ul></div>`;
}

// ---------- wiring ----------
$("#composer").addEventListener("submit", (e) => { e.preventDefault(); const t = input.value; input.value = ""; input.style.height = "auto"; send(t); });
input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#composer").requestSubmit(); } });
input.addEventListener("input", () => { input.style.height = "auto"; input.style.height = input.scrollHeight + "px"; });
document.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", () => send(c.textContent)));

(async function init() {
  try {
    const h = await (await fetch("/api/health")).json();
    statusEl.textContent = h.chat_enabled ? `chat: on (${h.model})` : "chat: off — set ANTHROPIC_API_KEY";
    statusEl.className = "status " + (h.chat_enabled ? "on" : "off");
  } catch { statusEl.textContent = "server unreachable"; }
  refreshReports();
})();
