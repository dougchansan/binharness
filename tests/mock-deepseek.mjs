// Minimal OpenAI-compatible SSE mock of the DeepSeek API for testing the harness loop.
// Scripted: turn 1 -> file_info, turn 2 -> find_string_refs, turn 3 -> final answer.
// Also asserts that reasoning_content and tool results are passed back correctly.
import http from "node:http";

const fixture = process.argv[2];
let n = 0;
const errors = [];
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    const j = JSON.parse(body);
    n++;
    if (!j.tools?.length) errors.push("no tools sent");
    if (req.headers.authorization !== "Bearer test-key") errors.push("bad auth header");
    if (n > 1) {
      const asst = j.messages.filter((m) => m.role === "assistant");
      if (!asst.every((m) => m.reasoning_content)) errors.push(`turn ${n}: reasoning_content not passed back`);
      const last = j.messages[j.messages.length - 1];
      if (last.role !== "tool" || !last.tool_call_id || !last.content) errors.push(`turn ${n}: missing tool result`);
      if (n === 2 && !/Switch NSO/.test(last.content)) errors.push("file_info result wrong");
      if (n === 3 && !/nnMain\+0x8/.test(last.content)) errors.push("find_string_refs result wrong");
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    const send = (delta, extra = {}) => res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta }], ...extra })}\n\n`);
    send({ reasoning_content: `step ${n} reasoning` });
    if (n === 1) {
      send({ tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "file_info", arguments: "" } }] });
      send({ tool_calls: [{ index: 0, function: { arguments: `{"path":${JSON.stringify(fixture).slice(0, 10)}` } }] });
      send({ tool_calls: [{ index: 0, function: { arguments: `${JSON.stringify(fixture).slice(10)}}` } }] });
    } else if (n === 2) {
      send({ tool_calls: [{ index: 0, id: "call_2", type: "function", function: { name: "find_string_refs", arguments: JSON.stringify({ path: fixture, text: "error" }) } }] });
    } else {
      send({ content: "The error string at 0x7100001100 is used by " });
      send({ content: "nnMain (0x7100000008)." });
    }
    res.write(`data: ${JSON.stringify({ choices: [], usage: { prompt_tokens: 1000, completion_tokens: 50, prompt_cache_hit_tokens: n > 1 ? 900 : 0, prompt_cache_miss_tokens: n > 1 ? 100 : 1000 } })}\n\n`);
    res.end("data: [DONE]\n\n");
  });
});
server.listen(0, "127.0.0.1", () => console.log(server.address().port));
process.on("SIGTERM", () => { console.error(errors.length ? "MOCK ERRORS:\n" + errors.join("\n") : `MOCK OK (${n} requests)`); process.exit(errors.length ? 1 : 0); });
