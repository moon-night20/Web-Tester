const $ = (selector) => document.querySelector(selector);
const state = { csrf: "", sites: [], scans: [], registering: false, selectedSite: null, poller: null };

function showError(element, message) {
  element.textContent = message;
  element.hidden = false;
}

function clearError(element) {
  element.textContent = "";
  element.hidden = true;
}

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 3600);
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function setAuthenticated(username, csrf) {
  state.csrf = csrf || state.csrf;
  $("#auth-view").hidden = true;
  $("#app-view").hidden = false;
  $("#user-email").textContent = username;
  $("#avatar").textContent = username.slice(0, 1).toUpperCase();
  $("#logout").hidden = false;
  $("#header-scan").hidden = false;
  refresh();
}

async function checkSession() {
  try {
    const data = await request("/api/me");
    setAuthenticated(data.username, data.csrf);
  } catch {
    $("#auth-view").hidden = false;
    $("#app-view").hidden = true;
  }
}

function setAuthMode(registering) {
  state.registering = registering;
  $("#auth-title").textContent = state.registering ? "Create your account" : "Welcome back";
  $("#auth-subtitle").textContent = state.registering ? "A clear view of your website's security starts here." : "Sign in to pick up where you left off.";
  $("#auth-eyebrow").textContent = state.registering ? "START YOUR SECURITY WORKSPACE" : "YOUR SECURITY WORKSPACE";
  $("#auth-submit").innerHTML = state.registering ? "Create account <span>→</span>" : "Sign in <span>→</span>";
  $("#switch-copy").textContent = state.registering ? "Already have an account?" : "New to SecureLaunch?";
  $("#switch-auth").textContent = state.registering ? "Sign in" : "Create an account";
  $("#password").autocomplete = state.registering ? "new-password" : "current-password";
  $("#password").minLength = state.registering ? 12 : 0;
  $("#email-field").hidden = !state.registering;
  $("#email").required = state.registering;
  $("#username-label").textContent = state.registering ? "Username" : "Username or email";
  $("#username").placeholder = state.registering ? "Choose a username" : "Your username or email";
  $("#username").autocomplete = "username";
  $("#username").minLength = state.registering ? 3 : 1;
  $("#username").pattern = state.registering ? "[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}" : "";
  $("#username").value = "";
  $("#email").value = "";
  $("#password").value = "";
  clearError($("#auth-error"));
}

$("#switch-auth").addEventListener("click", () => setAuthMode(!state.registering));

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError($("#auth-error"));
  const button = $("#auth-submit");
  button.disabled = true;
  try {
    const data = await request(state.registering ? "/api/register" : "/api/login", {
      method: "POST",
      body: JSON.stringify(state.registering
        ? { username: $("#username").value, email: $("#email").value, password: $("#password").value }
        : { identifier: $("#username").value, password: $("#password").value }),
    });
    setAuthenticated(data.username, data.csrf);
  } catch (error) {
    showError($("#auth-error"), error.message);
  } finally {
    button.disabled = false;
  }
});

$("#logout").addEventListener("click", async () => {
  try { await request("/api/logout", { method: "POST", body: "{}" }); }
  catch (error) { toast(error.message); }
  state.csrf = "";
  $("#auth-view").hidden = false;
  $("#app-view").hidden = true;
  $("#logout").hidden = true;
  $("#header-scan").hidden = true;
  $("#password").value = "";
  $("#username").value = "";
  $("#email").value = "";
  setAuthMode(false);
});

function emptyState(title, message) {
  const section = document.createElement("div");
  section.className = "empty-state";
  const heading = document.createElement("b");
  heading.textContent = title;
  const description = document.createElement("p");
  description.textContent = message;
  section.append(heading, description);
  return section;
}

function pill(text, className = "") {
  const node = document.createElement("span");
  node.className = `pill ${className}`;
  node.textContent = text;
  return node;
}

function openVerification(site) {
  state.selectedSite = site;
  $("#dns-name").textContent = `_securelaunch-challenge.${site.domain}`;
  $("#dns-value").textContent = `securelaunch-verification=${site.verification_token}`;
  clearError($("#verify-error"));
  $("#verify-dialog").showModal();
}

function renderSites() {
  const list = $("#sites-list");
  list.replaceChildren();
  $("#site-count").textContent = String(state.sites.length);
  $("#stat-sites").textContent = String(state.sites.filter((site) => site.verified_at).length);
  if (!state.sites.length) {
    list.append(emptyState("Your workspace is ready.", "Add a website you own to generate its DNS verification token."));
    return;
  }
  state.sites.forEach((site) => {
    const card = document.createElement("article");
    card.className = "site-card";
    const symbol = document.createElement("span");
    symbol.className = "site-symbol";
    symbol.textContent = "◎";
    const content = document.createElement("div");
    content.className = "site-content";
    const domain = document.createElement("b");
    domain.textContent = site.domain;
    const detail = document.createElement("small");
    detail.textContent = site.verified_at ? "DNS ownership verified" : `TXT: _securelaunch-challenge.${site.domain}`;
    content.append(domain, detail);
    const actions = document.createElement("div");
    actions.className = "site-actions";
    if (site.verified_at) {
      actions.append(pill("● Verified"));
      const scan = document.createElement("button");
      scan.className = "small-button";
      scan.textContent = "Scan";
      scan.addEventListener("click", () => openScan(site));
      actions.append(scan);
    } else {
      actions.append(pill("Verification needed", "pending"));
      const verify = document.createElement("button");
      verify.className = "small-button";
      verify.textContent = "Verify";
      verify.addEventListener("click", () => openVerification(site));
      actions.append(verify);
    }
    card.append(symbol, content, actions);
    list.append(card);
  });
}

function statusPill(status) {
  const labels = { running: "In progress", completed: "Complete", failed: "Failed" };
  return pill(labels[status] || status, status === "failed" ? "failed" : status === "running" ? "pending" : "");
}

function renderScans() {
  const list = $("#scans-list");
  list.replaceChildren();
  renderCategories();
  if (!state.scans.length) {
    list.append(emptyState("No scans yet.", "Verify a website, then start a passive scan to see real OWASP ZAP findings."));
    $("#stat-latest").textContent = "—";
    $("#stat-findings").textContent = "—";
    $("#stat-latest-note").textContent = "No scans yet";
    return;
  }
  const latest = state.scans[0];
  $("#stat-latest").textContent = latest.status === "running" ? "Running" : latest.status === "failed" ? "Failed" : new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(parseDatabaseDate(latest.started_at));
  $("#stat-findings").textContent = latest.status === "completed" ? String(latest.findings.total) : "—";
  $("#stat-latest-note").textContent = latest.status === "failed" ? latest.error || "Scan failed" : latest.status === "running" ? latest.domain : latest.domain;
  state.scans.forEach((scan) => {
    const card = document.createElement("article");
    card.className = "scan-card";
    const icon = document.createElement("span");
    icon.className = "scan-symbol";
    icon.textContent = scan.status === "completed" ? "✓" : scan.status === "failed" ? "!" : "◷";
    const details = document.createElement("div");
    details.className = "scan-details";
    const title = document.createElement("span");
    title.className = "scan-title";
    title.textContent = scan.domain;
    const subtitle = document.createElement("span");
    subtitle.className = "scan-subtitle";
    subtitle.textContent = scan.error || `${scan.target_url} · ZAP passive rules`;
    details.append(title, subtitle);
    const result = document.createElement("span");
    result.className = "scan-results";
    result.textContent = scan.status === "completed" ? `${scan.findings.total} finding${scan.findings.total === 1 ? "" : "s"}` : "";
    const date = document.createElement("span");
    date.className = "scan-date";
    date.textContent = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(parseDatabaseDate(scan.started_at));
    card.append(icon, details, statusPill(scan.status), result, date);
    if (scan.status === "completed" && scan.findings.items.length) {
      const view = document.createElement("button");
      view.className = "small-button";
      view.textContent = "Findings";
      view.addEventListener("click", () => showFindings(scan));
      card.append(view);
    }
    if (scan.status === "completed") {
      const compare = document.createElement("button");
      compare.className = "small-button";
      compare.textContent = "Compare";
      compare.addEventListener("click", () => compareScan(scan.id));
      card.append(compare);
    }
    list.append(card);
  });
}

function parseDatabaseDate(value) {
  return new Date(`${value.replace(" ", "T")}Z`);
}

function renderCategories() {
  const list = $("#categories-list");
  list.replaceChildren();
  const latest = state.scans.find((scan) => scan.status === "completed");
  if (!latest) {
    list.append(emptyState("No completed scan to summarize.", "After a ZAP passive scan completes, category totals will appear here."));
    return;
  }
  const categories = Object.entries(latest.findings.byCategory).filter(([name]) => name !== "Needs review");
  const max = Math.max(1, ...categories.map(([, count]) => count));
  categories.forEach(([name, count]) => {
    const row = document.createElement("article");
    row.className = "category-card";
    const label = document.createElement("span");
    label.className = "category-name";
    label.textContent = name;
    const amount = document.createElement("b");
    amount.textContent = String(count);
    const track = document.createElement("span");
    track.className = "category-track";
    const bar = document.createElement("progress");
    bar.className = "category-progress";
    bar.max = max;
    bar.value = count;
    track.append(bar);
    row.append(label, amount, track);
    list.append(row);
  });
  const unmapped = latest.findings.byCategory["Needs review"] || 0;
  const note = document.createElement("p");
  note.className = "category-note";
  note.textContent = `${unmapped} alert${unmapped === 1 ? "" : "s"} need${unmapped === 1 ? "s" : ""} manual category review.`;
  list.append(note);
}

function showFindings(scan) {
  if (!scan.findings.items.length) {
    toast("ZAP returned no passive alerts for this scan.");
    return;
  }
  const content = document.createElement("div");
  content.className = "finding-list";
  scan.findings.items.forEach((finding) => {
    const row = document.createElement("button");
    row.className = "finding-row";
    const title = document.createElement("b");
    title.textContent = finding.alert || finding.name || "ZAP alert";
    const subtitle = document.createElement("small");
    subtitle.textContent = `${finding.risk || "Informational"} · ${finding.category || "Needs review"}`;
    row.append(title, subtitle);
    row.addEventListener("click", () => showFindingDetail(finding));
    content.append(row);
  });
  const dialog = $("#finding-dialog");
  $("#finding-title").textContent = `${scan.findings.total} finding${scan.findings.total === 1 ? "" : "s"}`;
  $("#finding-meta").replaceChildren();
  $("#finding-description").textContent = "Select a finding to view its evidence, description, and remediation.";
  $("#finding-solution").textContent = `OWASP Top 10:2025 counts: ${Object.entries(scan.findings.byCategory).filter(([, count]) => count > 0).map(([category, count]) => `${category} (${count})`).join(", ") || "No alerts mapped."}`;
  $("#finding-url").hidden = true;
  const previous = dialog.querySelector(".finding-list");
  if (previous) previous.remove();
  dialog.append(content);
  dialog.showModal();
}

function showFindingDetail(finding) {
  $("#finding-title").textContent = finding.alert || finding.name || "ZAP alert";
  const meta = $("#finding-meta");
  meta.replaceChildren();
  [finding.risk || "Informational", finding.confidence && `Confidence: ${finding.confidence}`, finding.category || "Needs review"].filter(Boolean).forEach((value) => meta.append(pill(value)));
  $("#finding-description").textContent = finding.description || "No description was returned by this ZAP rule.";
  $("#finding-solution").textContent = finding.solution || "Review the affected endpoint and apply the relevant security controls.";
  const link = $("#finding-url");
  if (finding.url && /^https?:\/\//i.test(finding.url)) {
    link.href = finding.url;
    link.hidden = false;
  } else {
    link.hidden = true;
  }
}

async function compareScan(id) {
  try {
    const result = await request(`/api/scans/${id}/comparison`);
    $("#comparison-title").textContent = result.previousScanId ? `Scan #${result.previousScanId} → #${id}` : "No earlier completed scan";
    const summary = $("#comparison-summary");
    summary.replaceChildren();
    [["New", result.new.length], ["Resolved", result.resolved.length], ["Unchanged", result.unchanged]].forEach(([label, count]) => {
      const item = document.createElement("div");
      item.className = "comparison-stat";
      const number = document.createElement("b");
      number.textContent = String(count);
      const caption = document.createElement("span");
      caption.textContent = label;
      item.append(number, caption);
      summary.append(item);
    });
    const findings = $("#comparison-findings");
    findings.replaceChildren();
    [["New findings", result.new], ["Resolved findings", result.resolved]].forEach(([label, items]) => {
      const heading = document.createElement("h3");
      heading.textContent = label;
      findings.append(heading);
      if (!items.length) {
        const empty = document.createElement("p");
        empty.className = "comparison-empty";
        empty.textContent = "None";
        findings.append(empty);
        return;
      }
      items.forEach((finding) => {
        const row = document.createElement("button");
        row.className = "finding-row";
        const title = document.createElement("b");
        title.textContent = finding.alert || finding.name || "ZAP alert";
        const category = document.createElement("small");
        category.textContent = `${finding.risk || "Informational"} · ${finding.category || "Needs review"}`;
        row.append(title, category);
        row.addEventListener("click", () => {
          showFindingDetail(finding);
          $("#finding-dialog").showModal();
        });
        findings.append(row);
      });
    });
    $("#comparison-dialog").showModal();
  } catch (error) { toast(error.message); }
}

async function refresh() {
  try {
    const [sitesData, scansData] = await Promise.all([request("/api/sites"), request("/api/scans")]);
    state.sites = sitesData.sites;
    state.scans = scansData.scans;
    renderSites();
    renderScans();
    const scanning = state.scans.some((scan) => scan.status === "running");
    if (scanning && !state.poller) state.poller = setInterval(refresh, 3000);
    if (!scanning && state.poller) { clearInterval(state.poller); state.poller = null; }
  } catch (error) {
    if (error.message.includes("Sign in")) checkSession();
  }
}

$("#add-site").addEventListener("click", () => {
  clearError($("#site-error"));
  $("#site-form").reset();
  $("#site-dialog").showModal();
});

$("#site-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError($("#site-error"));
  try {
    const data = await request("/api/sites", { method: "POST", body: JSON.stringify({ domain: $("#domain").value }) });
    $("#site-dialog").close();
    state.sites.unshift(data.site);
    renderSites();
    openVerification(data.site);
  } catch (error) { showError($("#site-error"), error.message); }
});

$("#verify-button").addEventListener("click", async () => {
  if (!state.selectedSite) return;
  clearError($("#verify-error"));
  const button = $("#verify-button");
  button.disabled = true;
  button.textContent = "Checking DNS…";
  try {
    await request(`/api/sites/${state.selectedSite.id}/verify`, { method: "POST", body: "{}" });
    const verifiedSiteId = state.selectedSite.id;
    $("#verify-dialog").close();
    await refresh();
    const verifiedSite = state.sites.find((site) => site.id === verifiedSiteId);
    toast("Website verified. Next, start a passive scan.");
    if (verifiedSite) openScan(verifiedSite);
  } catch (error) {
    showError($("#verify-error"), error.message);
  } finally {
    button.disabled = false;
    button.innerHTML = 'Check DNS again <span>→</span>';
  }
});

document.querySelectorAll(".copy-button").forEach((button) => {
  button.addEventListener("click", async () => {
    const text = $(`#${button.dataset.copy}`).textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = "Copy"; }, 1500);
    } catch {
      showError($("#verify-error"), "Clipboard access was blocked. Select and copy the record value manually.");
    }
  });
});

function openScan(site) {
  const verified = state.sites.filter((item) => item.verified_at);
  $("#scan-site").replaceChildren(...verified.map((item) => {
    const option = document.createElement("option");
    option.value = String(item.id);
    option.textContent = item.domain;
    return option;
  }));
  if (site) $("#scan-site").value = String(site.id);
  const selected = verified.find((item) => String(item.id) === $("#scan-site").value);
  $("#scan-url").value = selected ? `https://${selected.domain}/` : "";
  clearError($("#scan-error"));
  $("#scan-dialog").showModal();
}

$("#scan-site").addEventListener("change", () => {
  const site = state.sites.find((item) => String(item.id) === $("#scan-site").value);
  $("#scan-url").value = site ? `https://${site.domain}/` : "";
});

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError($("#scan-error"));
  try {
    await request(`/api/sites/${$("#scan-site").value}/scans`, { method: "POST", body: JSON.stringify({ url: $("#scan-url").value }) });
    $("#scan-dialog").close();
    toast("Passive scan started. Results will appear when ZAP finishes.");
    await refresh();
  } catch (error) { showError($("#scan-error"), error.message); }
});

$("#new-scan").addEventListener("click", () => openScan());
$("#header-scan").addEventListener("click", () => openScan());
$("#nav-overview").addEventListener("click", () => {
  $("#crumb").textContent = "Overview";
  $("#page-title").textContent = "Overview";
  $("#nav-overview").classList.add("active");
  $("#nav-websites").classList.remove("active");
  window.scrollTo({ top: 0, behavior: "smooth" });
});
$("#nav-websites").addEventListener("click", () => {
  $("#crumb").textContent = "Websites";
  $("#page-title").textContent = "Websites";
  $("#nav-websites").classList.add("active");
  $("#nav-overview").classList.remove("active");
  $("#sites-list").scrollIntoView({ behavior: "smooth", block: "center" });
});
checkSession();
