"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    scenarios: [], runs: [], baselines: [], selectedScenario: null,
    selectedRuns: new Set(), detailId: null, detail: null,
    mode: "fixture", token: "", health: null, connected: false,
    refreshing: false, launching: false, detailBusy: false,
    timer: null, lastUpdated: null, catalogFailed: false, runsFailed: false,
  };
  const activeStatuses = new Set(["queued", "running", "cancelling"]);
  const terminalStatuses = new Set(["completed", "interrupted", "cancelled"]);
  const verdicts = new Set(["PASS", "FAIL", "ERROR", "INCONCLUSIVE", "CANCELLED"]);
  const modes = {
    fixture: {
      description: "Uses the scenario’s supplied test events. No external system is contacted.",
      scope: "FIXTURE · Evaluates supplied test data only. This run does not execute an action, contact Wazuh or verify detection in a live deployment.",
    },
    replay: {
      description: "Sends supplied log samples to Wazuh logtest. Requires a configured manager. Does not test agent collection or delivery.",
      scope: "REPLAY · Tests Wazuh rules and decoders against supplied logs. It does not validate execution, agent collection, transport or indexing.",
    },
    live: {
      description: "Executes the approved action on a configured laboratory VM and observes actual alerts. Requires explicit SSH and Wazuh configuration.",
      scope: "LIVE · Executes an approved action on the registered laboratory target. Assurance is limited to the scenario and checkpoints actually observed.",
    },
  };

  function text(value, limit = 1800) {
    if (value === null || value === undefined) return "—";
    const string = typeof value === "object" ? JSON.stringify(value) : String(value);
    return string.length > limit ? string.slice(0, limit) + "…" : string;
  }

  function node(tag, attrs = {}, ...children) {
    const item = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "className") item.className = value;
      else if (key === "text") item.textContent = text(value);
      else if (key === "checked" || key === "disabled" || key === "hidden") item[key] = value;
      else item.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child !== null && child !== undefined) item.append(child instanceof Node ? child : document.createTextNode(text(child)));
    }
    return item;
  }

  function notice(message, type = "info") {
    $("notice-text").textContent = text(message, 1200);
    $("notice").className = "notice" + (type === "info" ? "" : " " + type);
    $("notice").hidden = false;
  }

  function errorMessage(error) {
    return error && error.message ? text(error.message, 600) : "The request could not be completed.";
  }

  async function request(path, { method = "GET", body, raw = false, timeout = 15000 } = {}) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    const headers = { Accept: raw ? "*/*" : "application/json" };
    if (state.token) headers.Authorization = "Bearer " + state.token;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    try {
      const response = await fetch(path, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal, credentials: "same-origin", cache: "no-store", redirect: "error",
      });
      const length = Number(response.headers.get("content-length") || 0);
      if (length > 8 * 1024 * 1024) throw new Error("Controller response exceeds the display limit. Export a narrower report using the CLI.");
      const payload = await response.text();
      if (payload.length > 8 * 1024 * 1024) throw new Error("Controller response exceeds the display limit.");
      if (!response.ok) {
        let message = "Request failed (HTTP " + response.status + ").";
        try { message = JSON.parse(payload).error || message; } catch (_) { /* Never display a raw error page. */ }
        if (response.status === 401 || response.status === 403) message += " Check the bearer token in Connection settings.";
        throw new Error(text(message, 600));
      }
      if (raw) return { payload, contentType: response.headers.get("content-type") || "application/octet-stream" };
      try { return JSON.parse(payload); } catch (_) { throw new Error("Controller returned invalid JSON."); }
    } catch (error) {
      if (error.name === "AbortError") throw new Error("Controller request timed out. Its execution state may still have changed; refresh before retrying an action.");
      if (error instanceof TypeError) throw new Error("Cannot reach the controller. Check that Seori is running.");
      throw error;
    } finally { window.clearTimeout(timer); }
  }

  function badge(value, extra = "") {
    const label = text(value || "PENDING", 35).toUpperCase();
    const allowed = new Set(["pass", "fail", "error", "inconclusive", "cancelled", "interrupted", "running", "queued", "cancelling", "observed", "missing", "unavailable"]);
    const css = allowed.has(label.toLowerCase()) ? label.toLowerCase() : "neutral";
    return node("span", { className: "badge " + css + (extra ? " " + extra : ""), text: label });
  }

  function modeBadge(mode) {
    const known = Object.hasOwn(modes, mode) ? mode : "unknown";
    return node("span", { className: "badge mode-badge mode-" + known, text: known.toUpperCase(), title: modes[known]?.scope || "Unknown execution scope" });
  }

  function formatDate(timestamp) {
    const date = new Date(timestamp);
    if (!timestamp || !Number.isFinite(date.getTime())) return "—";
    return date.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function duration(run) {
    if (!run.started_at) return "—";
    const from = Date.parse(run.started_at);
    const to = run.finished_at ? Date.parse(run.finished_at) : Date.now();
    if (!Number.isFinite(from) || !Number.isFinite(to) || to < from) return "—";
    const seconds = (to - from) / 1000;
    return seconds < 60 ? seconds.toFixed(1) + "s" : Math.floor(seconds / 60) + "m " + Math.floor(seconds % 60) + "s";
  }

  function pretty(value, limit = 45000) {
    let string;
    try { string = JSON.stringify(value ?? {}, null, 2); } catch (_) { string = "Unable to display this evidence."; }
    return string.length > limit ? string.slice(0, limit) + "\n… Display truncated; use the exported report for the complete record." : string;
  }

  function empty(title, description, icon = "⌁", error = false) {
    return node("div", { className: "empty-state small" + (error ? " error" : "") },
      node("span", { className: "empty-symbol", "aria-hidden": "true", text: icon }),
      node("h3", { text: title }), node("p", { text: description }));
  }

  function renderConnection() {
    const online = state.connected && state.health?.status === "ok";
    $("connection-dot").className = "connection-dot " + (online ? "connected" : "disconnected");
    $("connection-label").textContent = online ? "Controller online" : "Controller unavailable";
    $("worker-label").textContent = online ? "Worker: " + text(state.health.worker || "unknown", 30) : "No current health confirmation";
    if (online && state.health.live_target_state?.blocked) {
      $("worker-label").textContent += " · live target blocked";
      $("worker-label").title = text(state.health.live_target_state.reason || "Restore the laboratory target before further live execution.");
    } else { $("worker-label").title = "Controller state does not attest SIEM health."; }
    $("version-label").textContent = "VERSION " + (online ? text(state.health.version || "—", 25) : "—");
    updateLaunch();
  }

  function renderStats() {
    const runs = state.runs;
    $("stat-total").textContent = String(runs.length);
    $("nav-run-count").textContent = String(runs.length);
    $("stat-passed").textContent = String(runs.filter((run) => run.verdict === "PASS").length);
    $("stat-attention").textContent = String(runs.filter((run) => ["FAIL", "ERROR", "INCONCLUSIVE"].includes(run.verdict)).length);
    $("stat-active").textContent = String(runs.filter((run) => activeStatuses.has(run.status)).length);
  }

  function renderCatalog() {
    $("scenario-count").textContent = String(state.scenarios.length);
    const query = $("scenario-search").value.trim().toLowerCase();
    const kind = $("kind-filter").value;
    const scenarios = state.scenarios.filter((scenario) => {
      const corpus = [scenario.id, scenario.title, scenario.description, ...(scenario.techniques || [])].join(" ").toLowerCase();
      return (kind === "all" || scenario.kind === kind) && (!query || corpus.includes(query));
    });
    const list = $("scenario-list");
    list.replaceChildren();
    if (state.catalogFailed) {
      list.append(empty("Catalog unavailable", "Check the controller connection and refresh.", "!", true));
      return;
    }
    if (!scenarios.length) {
      list.append(empty(state.scenarios.length ? "No matching scenarios" : "No scenarios loaded", state.scenarios.length ? "Try another search or scenario type." : "Add validated scenario files to the configured catalog directory."));
      return;
    }
    for (const scenario of scenarios) {
      const selected = state.selectedScenario?.id === scenario.id;
      const button = node("button", { type: "button", className: "scenario-button" + (selected ? " selected" : ""), "aria-pressed": String(selected) });
      const icon = node("span", { className: "scenario-icon" + (scenario.kind === "control" ? " control" : ""), "aria-hidden": "true", text: scenario.kind === "control" ? "◇" : "⌁" });
      const meta = node("span", { className: "scenario-meta" },
        node("span", { className: "scenario-kind", text: scenario.kind || "scenario" }),
        node("span", { "aria-hidden": "true", text: "·" }),
        node("span", { text: "v" + (scenario.version || "—") }));
      for (const technique of (scenario.techniques || []).slice(0, 2)) meta.append(node("span", { className: "scenario-technique", text: technique }));
      button.append(icon, node("span", { className: "scenario-copy" }, node("span", { className: "scenario-name", text: scenario.title || scenario.id }), meta), node("span", { className: "scenario-arrow", "aria-hidden": "true", text: selected ? "↗" : "›" }));
      button.addEventListener("click", () => { state.selectedScenario = scenario; renderCatalog(); renderSelectedScenario(); });
      list.append(button);
    }
  }

  function renderSelectedScenario() {
    const scenario = state.selectedScenario;
    $("selected-scenario-empty").hidden = Boolean(scenario);
    $("selected-scenario").hidden = !scenario;
    $("selected-kind").textContent = scenario ? text(scenario.kind, 20).toUpperCase() : "NO SCENARIO";
    if (scenario) {
      $("selected-id").textContent = text(scenario.id) + " / v" + text(scenario.version);
      $("selected-title").textContent = text(scenario.title);
      $("selected-description").textContent = text(scenario.description);
      $("selected-tags").replaceChildren(...(scenario.techniques || []).map((technique) => node("span", { className: "tag", text: technique })));
      const expectation = scenario.expect || {};
      const min = Number(expectation.min_alerts ?? 0);
      const max = expectation.max_alerts;
      let countDescription = max !== undefined && max === min ? "Exactly " + min : max !== undefined ? min + "–" + max : "At least " + min;
      countDescription += " matching alert" + (min === 1 && (max === undefined || max === 1) ? "" : "s");
      $("selected-expectation").textContent = countDescription;
      $("selected-predicates").replaceChildren(...(expectation.predicates || []).slice(0, 8).map((predicate) => node("span", { className: "predicate-chip", text: text(predicate.field, 60) + " " + text(predicate.op, 10) + " " + text(predicate.value, 100) })));
      $("run-timeout").textContent = "TIMEOUT " + text(scenario.timeout_seconds, 10) + "s";
    } else { $("run-timeout").textContent = "TIMEOUT —"; }
    updateLaunch();
  }

  function modeSupported(mode) {
    const scenario = state.selectedScenario;
    if (!scenario) return false;
    if (Array.isArray(scenario.metadata?.supported_modes) && !scenario.metadata.supported_modes.includes(mode)) return false;
    if (mode === "fixture") return Boolean(scenario.fixture);
    if (mode === "replay") return Array.isArray(scenario.replay) && scenario.replay.length > 0;
    if (mode === "live") return Boolean(scenario.action);
    return false;
  }

  function updateLaunch() {
    const configured = state.health?.configured_modes;
    for (const input of document.querySelectorAll('input[name="mode"]')) {
      const supported = modeSupported(input.value);
      const available = !Array.isArray(configured) || configured.includes(input.value);
      const blocked = input.value === "live" && state.health?.live_target_state?.blocked;
      input.disabled = !supported || !available || blocked || state.launching;
      input.closest("label").title = !supported ? "This scenario does not supply this mode." : !available ? "Controller is not configured for this mode." : blocked ? "Live target requires independently verified restoration and a target reset." : "";
    }
    const current = document.querySelector('input[name="mode"]:checked');
    if (current?.disabled && !state.launching) {
      const available = [...document.querySelectorAll('input[name="mode"]')].find((input) => !input.disabled);
      if (available) { available.checked = true; state.mode = available.value; }
    }
    const selected = document.querySelector('input[name="mode"]:checked');
    if (selected) state.mode = selected.value;
    $("mode-description").textContent = modes[state.mode].description;
    $("start-run").disabled = !state.connected || !state.selectedScenario || state.launching || !selected || selected.disabled || state.health?.worker === "stopped";
    $("start-run").textContent = state.launching ? "Queueing…" : "▶  Run validation";
  }

  function filteredRuns() {
    const filter = $("run-filter").value;
    return state.runs.filter((run) => filter === "all" || (filter === "active" && activeStatuses.has(run.status)) || (filter === "attention" && ["FAIL", "ERROR", "INCONCLUSIVE"].includes(run.verdict)) || run.verdict === filter);
  }

  function renderSelection() {
    $("selection-count").textContent = state.selectedRuns.size + " selected";
    const visible = filteredRuns();
    const all = $("select-all-runs");
    const selected = visible.filter((run) => state.selectedRuns.has(run.id)).length;
    all.checked = visible.length > 0 && selected === visible.length;
    all.indeterminate = selected > 0 && selected < visible.length;
    all.disabled = !visible.length;
    $("save-baseline").disabled = !state.selectedRuns.size || !state.connected;
    $("compare-baseline").disabled = !state.selectedRuns.size || !$("baseline-select").value || !state.connected;
  }

  function renderRuns() {
    const body = $("run-rows");
    body.replaceChildren();
    const runs = filteredRuns();
    $("runs-empty").hidden = runs.length > 0;
    if (!runs.length) {
      $("runs-empty").replaceChildren(...empty(state.runsFailed ? "History unavailable" : state.runs.length ? "No runs match this filter" : "No runs yet", state.runsFailed ? "The latest history could not be fetched. Refresh to try again." : state.runs.length ? "Choose another result filter." : "Select a scenario to create the first validation run.", state.runsFailed ? "!" : "⌁", state.runsFailed).childNodes);
    }
    for (const run of runs) {
      const row = node("tr", { className: state.detailId === run.id ? "row-selected" : "" });
      const checkbox = node("input", { type: "checkbox", "aria-label": "Select run " + text(run.id, 80), checked: state.selectedRuns.has(run.id) });
      checkbox.addEventListener("change", () => { if (checkbox.checked) state.selectedRuns.add(run.id); else state.selectedRuns.delete(run.id); renderSelection(); });
      const title = run.scenario?.title || state.scenarios.find((scenario) => scenario.id === run.scenario_id)?.title || run.scenario_id;
      const inspect = node("button", { className: "button button-subtle compact", type: "button", text: "Inspect ↗", "aria-label": "Inspect " + text(title, 120) + " run " + text(run.id, 80) });
      inspect.addEventListener("click", () => openDetail(run.id, true));
      row.append(node("td", { className: "checkbox-cell" }, checkbox), node("td", {}, node("span", { className: "run-scenario-name", text: title, title: text(title) }), node("div", { className: "mono run-id", text: text(run.id, 14) })), node("td", {}, modeBadge(run.mode)), node("td", {}, badge(run.verdict || run.status || "PENDING")), node("td", { className: "run-date", text: formatDate(run.started_at || run.created_at), title: text(run.started_at || run.created_at) }), node("td", { className: "run-duration", text: duration(run) }), node("td", {}, inspect));
      body.append(row);
    }
    renderSelection();
    renderStats();
  }

  function renderBaselines() {
    const selected = $("baseline-select").value;
    const select = $("baseline-select");
    select.replaceChildren();
    if (!state.baselines.length) select.append(node("option", { value: "", text: "No saved baselines" }));
    else {
      select.append(node("option", { value: "", text: "Choose a baseline…" }));
      for (const baseline of state.baselines) {
        const name = typeof baseline === "string" ? baseline : baseline.name;
        if (typeof name !== "string") continue;
        select.append(node("option", { value: name, text: name }));
      }
      if ([...select.options].some((option) => option.value === selected)) select.value = selected;
    }
    $("baseline-count").textContent = state.baselines.length + " saved";
    renderSelection();
  }

  function renderDetail(run) {
    if (!run || run.id !== state.detailId) return;
    state.detail = run;
    const result = run.result || {};
    $("run-detail").hidden = false;
    $("detail-title").textContent = text(run.scenario?.title || run.scenario_id || "Validation result");
    $("detail-id").textContent = text(run.id) + " · " + formatDate(run.created_at);
    $("detail-verdict").replaceWith(Object.assign(badge(run.verdict || run.status || "PENDING"), { id: "detail-verdict" }));
    $("detail-mode").replaceWith(Object.assign(modeBadge(run.mode), { id: "detail-mode" }));
    $("detail-summary-text").textContent = text(result.summary || (activeStatuses.has(run.status) ? "Execution is in progress. Results and evidence will appear when the controller finalizes this run." : "No finalized result is available for this run."));
    $("detail-scope").textContent = modes[run.mode]?.scope || "Unknown execution scope. Inspect the exported metadata before interpreting this result.";
    $("cancel-run").hidden = !activeStatuses.has(run.status);
    $("cancel-run").disabled = Boolean(run.cancel_requested) || run.status === "cancelling";
    $("cancel-run").textContent = run.cancel_requested || run.status === "cancelling" ? "Cancellation requested" : "Cancel run";
    $("download-json").disabled = !terminalStatuses.has(run.status);
    $("download-html").disabled = !terminalStatuses.has(run.status);
    const checkpoints = $("checkpoint-list"); checkpoints.replaceChildren();
    for (const checkpoint of (Array.isArray(result.checkpoints) ? result.checkpoints : []).slice(0, 50)) {
      checkpoints.append(node("div", { className: "checkpoint" }, node("div", { className: "checkpoint-heading" }, node("strong", { text: checkpoint.name }), badge(checkpoint.status)), node("p", { text: checkpoint.detail || "No additional checkpoint detail." })));
    }
    if (!checkpoints.children.length) checkpoints.append(node("p", { className: "muted", text: "No observed checkpoints recorded yet." }));
    const assertions = $("assertion-list"); assertions.replaceChildren();
    for (const assertion of (Array.isArray(result.assertions) ? result.assertions : []).slice(0, 100)) {
      assertions.append(node("div", { className: "assertion" }, node("div", { className: "assertion-heading" }, node("strong", { text: assertion.id || "Assertion" }), badge(assertion.verdict)), node("p", { text: assertion.message || "" }), node("div", { className: "assertion-values" }, node("div", { text: "Expected: " + text(assertion.expected, 450) }), node("div", { text: "Actual: " + text(assertion.actual, 450) }))));
    }
    if (!assertions.children.length) assertions.append(node("p", { className: "muted", text: "Assertions will appear after evaluation." }));
    const evidence = $("evidence-list"); evidence.replaceChildren();
    for (const record of (Array.isArray(result.evidence) ? result.evidence : []).slice(0, 30)) {
      evidence.append(node("details", { className: "evidence-item" }, node("summary", { text: text(record.kind || "evidence", 60) + " / " + text(record.id || "record", 80) }), node("pre", { text: pretty(record) })));
    }
    if (!evidence.children.length) evidence.append(node("p", { className: "muted", text: "No evidence records available." }));
    $("detail-metadata").textContent = pretty(result.metadata || {});
  }

  async function openDetail(id, scroll = false) {
    state.detailId = id;
    state.detail = null;
    const cached = state.runs.find((run) => run.id === id);
    if (cached) renderDetail(cached);
    renderRuns();
    if (scroll) { $("run-detail").scrollIntoView({ behavior: "smooth", block: "start" }); $("detail-title").focus({ preventScroll: true }); }
    try {
      const response = await request("/api/runs/" + encodeURIComponent(id));
      if (state.detailId === id) renderDetail(response.run);
    } catch (error) { notice(errorMessage(error), "error"); }
  }

  function scheduleRefresh() {
    if (state.timer) window.clearTimeout(state.timer);
    state.timer = window.setTimeout(() => refresh(false), document.hidden ? 12000 : 2500);
  }

  async function refresh(showErrors = false, full = false) {
    if (state.refreshing) return;
    state.refreshing = true;
    $("refresh").disabled = true;
    const tasks = [request("/api/health"), request("/api/runs?limit=100")];
    const getCatalog = full || !state.scenarios.length || state.catalogFailed;
    const getBaselines = full || !state.lastUpdated;
    if (getCatalog) tasks.push(request("/api/scenarios"));
    if (getBaselines) tasks.push(request("/api/baselines"));
    try {
      const results = await Promise.allSettled(tasks);
      const health = results[0], history = results[1];
      state.connected = health.status === "fulfilled" && health.value.status === "ok";
      state.health = health.status === "fulfilled" ? health.value : null;
      if (history.status === "fulfilled" && Array.isArray(history.value.runs)) {
        state.runs = history.value.runs.slice(0, 100);
        state.runsFailed = false;
        const known = new Set(state.runs.map((run) => run.id));
        state.selectedRuns = new Set([...state.selectedRuns].filter((id) => known.has(id)));
      } else { state.runsFailed = true; }
      let index = 2;
      if (getCatalog) {
        const catalog = results[index++];
        if (catalog.status === "fulfilled" && Array.isArray(catalog.value.scenarios)) {
          state.scenarios = catalog.value.scenarios.slice(0, 500);
          state.catalogFailed = false;
          if (state.selectedScenario) state.selectedScenario = state.scenarios.find((scenario) => scenario.id === state.selectedScenario.id) || null;
          if (!state.selectedScenario && state.scenarios.length) state.selectedScenario = state.scenarios[0];
        } else state.catalogFailed = true;
        renderCatalog(); renderSelectedScenario();
      }
      if (getBaselines) {
        const baselines = results[index];
        if (baselines.status === "fulfilled" && Array.isArray(baselines.value.baselines)) { state.baselines = baselines.value.baselines; renderBaselines(); }
      }
      renderConnection(); renderRuns();
      if (state.connected && !state.runsFailed) {
        state.lastUpdated = new Date();
        $("last-updated").textContent = "Updated " + state.lastUpdated.toLocaleTimeString();
      } else $("last-updated").textContent = state.lastUpdated ? "Connection lost · last update " + state.lastUpdated.toLocaleTimeString() : "Controller data unavailable";
      if (state.detailId) {
        const cached = state.runs.find((run) => run.id === state.detailId);
        if (cached) renderDetail(cached);
      }
      if (showErrors) {
        const failure = results.find((result) => result.status === "rejected");
        if (failure) notice(errorMessage(failure.reason), "error");
        else if (state.connected) notice("Workspace refreshed.", "success");
      }
    } finally { state.refreshing = false; $("refresh").disabled = false; scheduleRefresh(); }
  }

  async function startRun() {
    if (!state.selectedScenario || state.launching) return;
    state.launching = true; updateLaunch();
    try {
      const response = await request("/api/runs", { method: "POST", body: { scenario_id: state.selectedScenario.id, mode: state.mode } });
      if (!response.run?.id) throw new Error("Controller did not return a run identifier. Refresh before retrying.");
      state.runs = [response.run, ...state.runs.filter((run) => run.id !== response.run.id)].slice(0, 100);
      notice("Validation queued. " + modes[state.mode].scope, "success");
      await openDetail(response.run.id, true);
      await refresh(false);
    } catch (error) { notice(errorMessage(error), "error"); }
    finally { state.launching = false; updateLaunch(); }
  }

  async function cancelRun() {
    const id = state.detailId;
    if (!id) return;
    $("cancel-run").disabled = true;
    try {
      const response = await request("/api/runs/" + encodeURIComponent(id) + "/cancel", { method: "POST", body: {} });
      if (response.run) renderDetail(response.run);
      notice("Cancellation requested. Cleanup must finish before this run is finalized.");
      await refresh(false);
    } catch (error) { notice(errorMessage(error), "error"); $("cancel-run").disabled = false; }
  }

  async function downloadReport(format) {
    const id = state.detailId;
    if (!id) return;
    const button = $(format === "json" ? "download-json" : "download-html");
    button.disabled = true;
    try {
      const response = await request("/api/runs/" + encodeURIComponent(id) + "/report?format=" + format, { raw: true });
      const blob = new Blob([response.payload], { type: format === "json" ? "application/json" : "text/html" });
      const url = URL.createObjectURL(blob);
      const anchor = node("a", { href: url, download: "seori-" + String(id).replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64) + "." + format });
      document.body.append(anchor); anchor.click(); anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1500);
    } catch (error) { notice(errorMessage(error), "error"); }
    finally { button.disabled = !state.detail || !terminalStatuses.has(state.detail.status); }
  }

  function selectedCompletedRuns() {
    const selected = state.runs.filter((run) => state.selectedRuns.has(run.id));
    if (!selected.length) throw new Error("Select at least one run from the history.");
    if (selected.some((run) => !terminalStatuses.has(run.status) || !verdicts.has(run.verdict))) throw new Error("Select only finalized runs with a recorded verdict.");
    const scopes = new Set(selected.map((run) => run.mode));
    if (scopes.size > 1) throw new Error("Select runs from one execution mode. Fixture, replay and live results have different scopes.");
    return selected;
  }

  async function saveBaseline(event) {
    event.preventDefault();
    const button = $("save-baseline");
    button.disabled = true;
    try {
      const runs = selectedCompletedRuns();
      const name = $("baseline-name").value.trim();
      if (!name) throw new Error("Enter a baseline name.");
      await request("/api/baselines", { method: "POST", body: { name, run_ids: runs.map((run) => run.id) } });
      const response = await request("/api/baselines");
      state.baselines = Array.isArray(response.baselines) ? response.baselines : [];
      renderBaselines(); $("baseline-select").value = name; $("baseline-name").value = "";
      notice("Baseline “" + name + "” saved.", "success"); renderSelection();
    } catch (error) { notice(errorMessage(error), "error"); }
    finally { renderSelection(); }
  }

  async function compareBaseline() {
    $("compare-baseline").disabled = true;
    try {
      const runs = selectedCompletedRuns();
      const name = $("baseline-select").value;
      if (!name) throw new Error("Choose a saved baseline.");
      const params = new URLSearchParams({ baseline: name, run_ids: runs.map((run) => run.id).join(",") });
      const response = await request("/api/compare?" + params.toString());
      const comparison = response.comparison;
      if (!comparison || !Array.isArray(comparison.rows)) throw new Error("Controller returned an invalid comparison.");
      const container = $("comparison"); container.replaceChildren();
      container.append(node("div", { className: "comparison-heading" }, node("strong", { text: "Against " + name }), badge(comparison.verdict)), node("p", { text: comparison.summary || "Comparison of the selected run results." }));
      const table = node("table", { className: "comparison-table" });
      table.append(node("thead", {}, node("tr", {}, ...["Scenario", "Baseline", "Current", "Change"].map((label) => node("th", { scope: "col", text: label })))));
      const body = node("tbody");
      for (const row of comparison.rows.slice(0, 300)) {
        const allowed = new Set(["unchanged", "regression", "improvement", "missing", "new"]);
        const change = allowed.has(row.change) ? row.change : "unknown";
        body.append(node("tr", {}, node("td", { className: "mono", text: row.scenario_id }), node("td", {}, badge(row.baseline_verdict || "MISSING")), node("td", {}, badge(row.current_verdict || "MISSING")), node("td", { className: "change-" + change, text: change })));
      }
      table.append(body); container.append(node("div", { className: "table-scroll" }, table)); container.hidden = false;
      container.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) { notice(errorMessage(error), "error"); }
    finally { renderSelection(); }
  }

  $("scenario-search").addEventListener("input", renderCatalog);
  $("kind-filter").addEventListener("change", renderCatalog);
  $("run-filter").addEventListener("change", renderRuns);
  $("refresh").addEventListener("click", () => refresh(true, true));
  $("dismiss-notice").addEventListener("click", () => { $("notice").hidden = true; });
  $("apply-token").addEventListener("click", () => { state.token = $("api-token").value.trim(); $("api-token").value = ""; refresh(true, true); });
  $("api-token").addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); $("apply-token").click(); } });
  for (const input of document.querySelectorAll('input[name="mode"]')) input.addEventListener("change", () => { state.mode = input.value; updateLaunch(); });
  $("start-run").addEventListener("click", startRun);
  $("cancel-run").addEventListener("click", cancelRun);
  $("download-json").addEventListener("click", () => downloadReport("json"));
  $("download-html").addEventListener("click", () => downloadReport("html"));
  $("close-detail").addEventListener("click", () => { state.detailId = null; state.detail = null; $("run-detail").hidden = true; renderRuns(); });
  $("select-all-runs").addEventListener("change", (event) => { for (const run of filteredRuns()) { if (event.target.checked) state.selectedRuns.add(run.id); else state.selectedRuns.delete(run.id); } renderRuns(); });
  $("baseline-form").addEventListener("submit", saveBaseline);
  $("compare-baseline").addEventListener("click", compareBaseline);
  $("baseline-select").addEventListener("change", renderSelection);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(false); });
  window.addEventListener("offline", () => { state.connected = false; state.health = null; renderConnection(); });
  window.addEventListener("online", () => refresh(false, true));
  renderSelectedScenario(); renderSelection(); refresh(false, true);
})();
