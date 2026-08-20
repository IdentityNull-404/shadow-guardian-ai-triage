/*
 * Shadow Guardian AI Incident Triage Center
 * GitHub Pages client-side application
 *
 * The code is deliberately framework-free and well commented so the complete
 * NLP, sentiment, reinforcement-feedback, and genetic-algorithm logic can be
 * reviewed directly in the browser. No submitted text leaves the device.
 */

(() => {
  "use strict";

  const samples = {
    phishing: {
      label: "Credential phishing",
      type: "email",
      text: `From: Microsoft Security <alerts@micros0ft-support.com>
Subject: URGENT — Your account will be suspended

We detected an unauthorized login to your company account. Verify your identity and password immediately at http://account-check.example/verify or your access will be disabled within 30 minutes.`,
    },
    malware: {
      label: "Malware delivery",
      type: "email",
      text: `From: Payroll Services <payroll@outside-vendor.example>
Subject: Updated direct deposit form

Open the attached macro-enabled document today to prevent a delay in your paycheck. Enable content when prompted so the secure form can load.`,
    },
    login: {
      label: "Security alert",
      type: "security-log",
      text: `2026-08-19T02:14:03Z AUTH_FAILURE user=s.redding source_ip=198.51.100.42
2026-08-19T02:14:07Z AUTH_FAILURE user=s.redding source_ip=198.51.100.42
2026-08-19T02:14:12Z MFA_BYPASS_ATTEMPT user=s.redding source_ip=198.51.100.42
2026-08-19T02:14:19Z NEW_DEVICE_LOGIN user=s.redding source_ip=198.51.100.42`,
    },
    benign: {
      label: "Normal message",
      type: "message",
      text: "Hi team, the weekly project meeting moved to Thursday at 2:00 PM. The agenda is in our normal shared workspace. No action is needed today. Thanks!",
    },
  };

  // Transparent detection signals replace a black-box score with evidence that
  // a user can inspect and challenge.
  const signals = [
    {
      id: "credential",
      label: "Credential request",
      description: "Asks for passwords, verification, sign-in, or MFA details.",
      weight: 19,
      terms: ["password", "verify your identity", "verify your account", "sign in", "login", "mfa", "one-time code", "authentication code"],
    },
    {
      id: "urgency",
      label: "Pressure language",
      description: "Uses fear, urgency, or a short deadline to force action.",
      weight: 12,
      terms: ["urgent", "immediately", "within 30 minutes", "final warning", "act now", "today", "disabled", "suspended"],
    },
    {
      id: "account",
      label: "Account threat",
      description: "Claims unusual access, lockout, or account compromise.",
      weight: 15,
      terms: ["unauthorized login", "unusual activity", "account compromise", "new_device_login", "auth_failure", "mfa_bypass", "access will be disabled"],
    },
    {
      id: "delivery",
      label: "Suspicious delivery method",
      description: "Uses a link, attachment, macro, or executable payload.",
      weight: 16,
      terms: ["http://", "https://", "attached", "attachment", "macro-enabled", "enable content", ".exe", ".zip"],
    },
    {
      id: "malware",
      label: "Malware behavior",
      description: "Contains language commonly associated with unsafe payloads.",
      weight: 22,
      terms: ["enable macros", "enable content", "run this file", "disable antivirus", "powershell -enc", "ransomware", "payload"],
    },
    {
      id: "money",
      label: "Financial pressure",
      description: "Requests payment, gift cards, banking changes, or cryptocurrency.",
      weight: 17,
      terms: ["gift card", "wire transfer", "bank account", "direct deposit", "bitcoin", "crypto", "invoice", "payment"],
    },
    {
      id: "impersonation",
      label: "Impersonation cue",
      description: "Claims authority or discourages normal verification.",
      weight: 11,
      terms: ["ceo", "it department", "security team", "payroll services", "do not call", "confidential request", "keep this private"],
    },
  ];

  const positiveWords = ["thanks", "thank you", "normal", "scheduled", "welcome", "helpful", "approved"];
  const negativeWords = ["urgent", "warning", "failure", "unauthorized", "suspended", "disabled", "delay", "threat", "compromise", "bypass"];
  const defaultWeights = Object.fromEntries(signals.map((signal) => [signal.id, signal.weight]));

  const state = {
    bias: 0,
    feedbackCount: 0,
    weights: { ...defaultWeights },
    modelVersion: 1,
    analysis: null,
  };

  const trainingSet = [
    { text: samples.phishing.text, type: "email", target: 90 },
    { text: samples.malware.text, type: "email", target: 86 },
    { text: samples.login.text, type: "security-log", target: 82 },
    { text: samples.benign.text, type: "message", target: 7 },
    { text: "CEO confidential request: buy gift cards immediately and send the codes. Do not call me about this payment.", type: "email", target: 92 },
    { text: "The approved monthly invoice is available in our normal finance workspace. Payment follows the existing schedule; no action is needed today.", type: "email", target: 15 },
  ];

  const byId = (id) => document.getElementById(id);
  const clamp = (value, minimum, maximum) => Math.max(minimum, Math.min(maximum, value));
  const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const countTerm = (text, term) => (text.match(new RegExp(escapeRegExp(term), "gi")) || []).length;
  const unique = (values) => [...new Set(values.map((value) => value.replace(/[),.;]+$/, "")))];

  // User-controlled text is escaped before it is inserted into HTML. This
  // prevents a pasted message from becoming executable page content.
  const escapeHtml = (value) =>
    String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

  function extractEntities(text) {
    const urls = unique(text.match(/https?:\/\/[^\s<>"']+/gi) || []);
    const emails = unique(text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []);
    const ips = unique(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []);
    return [
      { label: "URLs", values: urls },
      { label: "Email addresses", values: emails },
      { label: "IP addresses", values: ips },
    ].filter((group) => group.values.length > 0);
  }

  /**
   * Applies natural-language feature matching, entity extraction, sentiment
   * analysis, and an explainable weighted risk model.
   */
  function analyze(text, type, bias = state.bias, weights = state.weights) {
    const normalized = text.toLowerCase();
    const tokenCount = (normalized.match(/[a-z0-9_.@:/-]+/g) || []).length;
    const entities = extractEntities(text);
    const matchedSignals = signals
      .map((signal) => ({
        ...signal,
        weight: weights[signal.id] ?? signal.weight,
        matches: signal.terms.reduce((total, term) => total + countTerm(normalized, term), 0),
      }))
      .filter((signal) => signal.matches > 0);

    let score = matchedSignals.reduce(
      (total, signal) => total + signal.weight + Math.min(signal.matches - 1, 2) * 2,
      4,
    );
    const entityCount = entities.reduce((total, group) => total + group.values.length, 0);
    score += Math.min(entityCount * 3, 9);
    score += type === "security-log" && /auth_failure|mfa_bypass/i.test(text) ? 8 : 0;
    score -= /no action (?:is )?needed|for your information only/i.test(text) ? 18 : 0;
    score = clamp(Math.round(score + bias), 2, 98);

    const positive = positiveWords.reduce((total, word) => total + countTerm(normalized, word), 0);
    const negative = negativeWords.reduce((total, word) => total + countTerm(normalized, word), 0);
    const has = (id) => matchedSignals.some((signal) => signal.id === id);

    const tone = has("urgency")
      ? "High-pressure / urgent"
      : negative > positive
        ? "Negative / concerning"
        : positive > negative
          ? "Neutral-positive"
          : "Neutral";

    const severity = score >= 78 ? "Critical" : score >= 55 ? "High" : score >= 30 ? "Elevated" : "Low";
    const classification = has("malware") && has("delivery")
      ? "Malware delivery attempt"
      : has("credential") && has("delivery")
        ? "Credential phishing"
        : has("money") && has("impersonation")
          ? "Business email compromise"
          : type === "security-log" && has("account")
            ? "Account takeover activity"
            : has("money")
              ? "Financial social engineering"
              : score >= 30
                ? "Suspicious communication"
                : "Likely routine communication";

    const confidence = Math.min(97, 46 + matchedSignals.length * 7 + Math.min(entityCount, 4) * 3);
    const actions = severity === "Critical" || severity === "High"
      ? [
          "Do not click links, open attachments, reply, or provide credentials.",
          "Preserve the original message or log as evidence and notify the security team.",
          classification.includes("Account") || has("credential")
            ? "Verify the account through a known-good channel and reset exposed credentials."
            : "Verify the sender through a separate, trusted channel.",
          "Block or isolate the identified indicator only after organizational review.",
        ]
      : severity === "Elevated"
        ? ["Pause before interacting with the content.", "Verify the sender and request using a known contact method.", "Report the item if the context cannot be confirmed."]
        : ["No immediate threat response is indicated.", "Continue normal caution and verify unexpected requests."];

    return {
      score,
      severity,
      classification,
      tone,
      confidence,
      matchedSignals,
      entities,
      actions,
      tokenCount,
      summary: matchedSignals.length
        ? `${classification} is the best-fit category. The model found ${matchedSignals.length} explainable risk signal${matchedSignals.length === 1 ? "" : "s"} and ${entityCount} extractable indicator${entityCount === 1 ? "" : "s"}.`
        : "The model found no strong threat indicators in the submitted text.",
    };
  }

  function currentInput() {
    return { text: byId("case-text").value, type: byId("case-type").value };
  }

  function reportText(analysis) {
    return [
      "SHADOW GUARDIAN INCIDENT TRIAGE REPORT",
      `Risk: ${analysis.score}/100 (${analysis.severity})`,
      `Classification: ${analysis.classification}`,
      `Language tone: ${analysis.tone}`,
      `Confidence: ${analysis.confidence}%`,
      "",
      analysis.summary,
      "",
      "Recommended actions:",
      ...analysis.actions.map((action, index) => `${index + 1}. ${action}`),
      "",
      "Educational prototype — results require human review.",
    ].join("\n");
  }

  function renderAnalysis(analysis) {
    state.analysis = analysis;
    const severityClass = analysis.severity.toLowerCase();
    byId("risk-score").textContent = analysis.score;
    byId("score-ring").className = `score-ring score-${severityClass}`;
    byId("score-ring").style.setProperty("--score", `${analysis.score * 3.6}deg`);
    byId("severity").className = `severity severity-${severityClass}`;
    byId("severity").textContent = `${analysis.severity} risk`;
    byId("classification").textContent = analysis.classification;
    byId("analysis-summary").textContent = analysis.summary;
    byId("tone").textContent = analysis.tone;
    byId("confidence").textContent = `${analysis.confidence}%`;
    byId("token-count").textContent = analysis.tokenCount;
    byId("signal-count").textContent = `${analysis.matchedSignals.length} signals`;

    byId("signal-list").innerHTML = analysis.matchedSignals.length
      ? analysis.matchedSignals.map((signal) => `
          <div class="signal-item">
            <span class="signal-icon" aria-hidden="true">!</span>
            <div><strong>${escapeHtml(signal.label)}</strong><p>${escapeHtml(signal.description)}</p></div>
            <b>+${signal.weight}</b>
          </div>`).join("")
      : '<p class="empty-state">No strong threat signals detected.</p>';

    byId("entity-block").hidden = analysis.entities.length === 0;
    byId("entity-list").innerHTML = analysis.entities.map((entity) => `
      <div><span>${escapeHtml(entity.label)}</span>${entity.values.map((value) => `<code>${escapeHtml(value)}</code>`).join("")}</div>
    `).join("");
    byId("action-list").innerHTML = analysis.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("");
  }

  function runAnalysis() {
    const input = currentInput();
    if (input.text.trim().length < 12) return;
    renderAnalysis(analyze(input.text, input.type));
  }

  function loadSample(key) {
    const sample = samples[key];
    byId("case-type").value = sample.type;
    byId("case-text").value = sample.text;
    document.querySelectorAll("[data-sample]").forEach((button) => {
      button.classList.toggle("active", button.dataset.sample === key);
    });
    updateCharacterCount();
    runAnalysis();
  }

  function updateCharacterCount() {
    const length = byId("case-text").value.length;
    byId("character-count").textContent = `${length.toLocaleString()} characters`;
    byId("analyze-button").disabled = length < 12;
  }

  // Reinforcement feedback changes only a small session bias. The original
  // text is never saved, and Reset immediately restores the baseline model.
  function recordFeedback(kind) {
    const adjustment = kind === "too-high" ? -3 : kind === "too-low" ? 3 : 0;
    state.bias = clamp(state.bias + adjustment, -15, 15);
    state.feedbackCount += 1;
    const message = kind === "accurate"
      ? "Positive reward recorded. The current threshold was reinforced."
      : kind === "too-high"
        ? "Negative reward recorded. Session risk sensitivity decreased by 3 points."
        : "Corrective reward recorded. Session risk sensitivity increased by 3 points.";
    byId("feedback-message").textContent = message;
    updateLearningUi();
    runAnalysis();
  }

  function buildTrainingFeatures() {
    return trainingSet.map((item) => {
      const normalized = item.text.toLowerCase();
      const matches = signals.map((signal) => signal.terms.reduce((total, term) => total + countTerm(normalized, term), 0));
      const entityCount = extractEntities(item.text).reduce((total, group) => total + group.values.length, 0);
      const baseScore = 4
        + Math.min(entityCount * 3, 9)
        + (item.type === "security-log" && /auth_failure|mfa_bypass/i.test(item.text) ? 8 : 0)
        - (/no action (?:is )?needed|for your information only/i.test(item.text) ? 18 : 0);
      return { target: item.target, matches, baseScore };
    });
  }

  /**
   * Runs a real genetic algorithm: 36 genomes compete for 40 generations.
   * Elites survive, parent weights cross over, and random genes mutate.
   */
  function evolveModel() {
    const ids = signals.map((signal) => signal.id);
    const seed = ids.map((id) => state.weights[id]);
    const features = buildTrainingFeatures();
    const populationSize = 36;
    const generations = 40;
    const scoreGenome = (genome) => features.reduce((total, item) => {
      const predicted = item.matches.reduce(
        (risk, matches, index) => matches > 0 ? risk + genome[index] + Math.min(matches - 1, 2) * 2 : risk,
        item.baseScore,
      );
      return total + Math.abs(clamp(Math.round(predicted), 2, 98) - item.target);
    }, 0) / features.length;

    let population = Array.from({ length: populationSize }, (_, index) => index === 0
      ? [...seed]
      : seed.map((weight) => clamp(weight + Math.round(Math.random() * 14 - 7), 4, 30)));
    const before = scoreGenome(seed);

    for (let generation = 0; generation < generations; generation += 1) {
      population.sort((a, b) => scoreGenome(a) - scoreGenome(b));
      const elite = population.slice(0, 8);
      const next = elite.map((genome) => [...genome]);
      while (next.length < populationSize) {
        const parentA = elite[Math.floor(Math.random() * elite.length)];
        const parentB = elite[Math.floor(Math.random() * elite.length)];
        next.push(parentA.map((gene, index) => {
          const inherited = Math.random() > 0.5 ? gene : parentB[index];
          const mutation = Math.random() < 0.28 ? Math.round(Math.random() * 8 - 4) : 0;
          return clamp(inherited + mutation, 4, 30);
        }));
      }
      population = next;
    }

    population.sort((a, b) => scoreGenome(a) - scoreGenome(b));
    state.weights = Object.fromEntries(ids.map((id, index) => [id, population[0][index]]));
    state.modelVersion += 1;
    byId("before-error").textContent = before.toFixed(1);
    byId("after-error").textContent = scoreGenome(population[0]).toFixed(1);
    updateLearningUi(true);
    runAnalysis();
  }

  function renderWeights() {
    byId("weight-list").innerHTML = signals.slice(0, 5).map((signal) => `
      <div class="weight-row">
        <span>${escapeHtml(signal.label)}</span>
        <div><i style="width: ${(state.weights[signal.id] / 30) * 100}%"></i></div>
        <b>${state.weights[signal.id]}</b>
      </div>
    `).join("");
  }

  function updateLearningUi(optimized = false) {
    const displayBias = state.bias > 0 ? `+${state.bias}` : String(state.bias);
    byId("bias-value").textContent = displayBias;
    byId("bias-dot").style.left = `${((state.bias + 15) / 30) * 100}%`;
    byId("reward-events").textContent = state.feedbackCount;
    byId("feedback-count").textContent = `${state.feedbackCount} reward${state.feedbackCount === 1 ? "" : "s"}`;
    byId("engine-model-version").textContent = `v${state.modelVersion}.0`;
    byId("ga-model-version").textContent = `GA / MODEL ${state.modelVersion}.0`;
    if (optimized) byId("learning-status").textContent = `Model ${state.modelVersion}.0 · 40 generations completed`;
    renderWeights();
  }

  function resetLearning() {
    state.bias = 0;
    state.feedbackCount = 0;
    state.weights = { ...defaultWeights };
    state.modelVersion = 1;
    byId("before-error").textContent = "—";
    byId("after-error").textContent = "—";
    byId("feedback-message").textContent = "No analyst reward has been recorded yet.";
    byId("learning-status").textContent = "Model 1.0 · Baseline weights active";
    updateLearningUi();
    runAnalysis();
  }

  function connectEvents() {
    document.querySelectorAll("[data-sample]").forEach((button) => {
      button.addEventListener("click", () => loadSample(button.dataset.sample));
    });
    document.querySelectorAll("[data-feedback]").forEach((button) => {
      button.addEventListener("click", () => recordFeedback(button.dataset.feedback));
    });
    byId("case-text").addEventListener("input", () => {
      document.querySelectorAll("[data-sample]").forEach((button) => button.classList.remove("active"));
      updateCharacterCount();
    });
    byId("analyze-button").addEventListener("click", runAnalysis);
    byId("evolve-button").addEventListener("click", evolveModel);
    byId("reset-learning").addEventListener("click", resetLearning);
    byId("copy-report").addEventListener("click", async () => {
      if (!state.analysis) return;
      await navigator.clipboard.writeText(reportText(state.analysis));
      byId("copy-report").textContent = "Copied";
      window.setTimeout(() => { byId("copy-report").textContent = "Copy report"; }, 1600);
    });
  }

  connectEvents();
  loadSample("phishing");
  updateLearningUi();
})();
