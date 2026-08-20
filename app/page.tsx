"use client";

import { useMemo, useState } from "react";

type CaseType = "email" | "message" | "security-log";
type Severity = "Low" | "Elevated" | "High" | "Critical";

type SignalDefinition = {
  id: string;
  label: string;
  description: string;
  weight: number;
  terms: string[];
};

type MatchedSignal = SignalDefinition & {
  matches: number;
};

type Analysis = {
  score: number;
  severity: Severity;
  classification: string;
  tone: string;
  confidence: number;
  matchedSignals: MatchedSignal[];
  entities: { label: string; values: string[] }[];
  actions: string[];
  summary: string;
  tokenCount: number;
};

type ModelWeights = Record<string, number>;

type OptimizationResult = {
  beforeError: number;
  afterError: number;
  generations: number;
};

const SAMPLE_CASES: Record<
  string,
  { label: string; type: CaseType; text: string }
> = {
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
    text: `Hi team, the weekly project meeting moved to Thursday at 2:00 PM. The agenda is in our normal shared workspace. No action is needed today. Thanks!`,
  },
};

// Each signal is intentionally transparent: the interface can explain why a
// score changed instead of presenting a mysterious black-box answer.
const SIGNALS: SignalDefinition[] = [
  {
    id: "credential",
    label: "Credential request",
    description: "Asks for passwords, verification, sign-in, or MFA details.",
    weight: 19,
    terms: [
      "password",
      "verify your identity",
      "verify your account",
      "sign in",
      "login",
      "mfa",
      "one-time code",
      "authentication code",
    ],
  },
  {
    id: "urgency",
    label: "Pressure language",
    description: "Uses fear, urgency, or a short deadline to force action.",
    weight: 12,
    terms: [
      "urgent",
      "immediately",
      "within 30 minutes",
      "final warning",
      "act now",
      "today",
      "disabled",
      "suspended",
    ],
  },
  {
    id: "account",
    label: "Account threat",
    description: "Claims unusual access, lockout, or account compromise.",
    weight: 15,
    terms: [
      "unauthorized login",
      "unusual activity",
      "account compromise",
      "new_device_login",
      "auth_failure",
      "mfa_bypass",
      "access will be disabled",
    ],
  },
  {
    id: "delivery",
    label: "Suspicious delivery method",
    description: "Uses a link, attachment, macro, or executable payload.",
    weight: 16,
    terms: [
      "http://",
      "https://",
      "attached",
      "attachment",
      "macro-enabled",
      "enable content",
      ".exe",
      ".zip",
    ],
  },
  {
    id: "malware",
    label: "Malware behavior",
    description: "Contains language commonly associated with unsafe payloads.",
    weight: 22,
    terms: [
      "enable macros",
      "enable content",
      "run this file",
      "disable antivirus",
      "powershell -enc",
      "ransomware",
      "payload",
    ],
  },
  {
    id: "money",
    label: "Financial pressure",
    description: "Requests payment, gift cards, banking changes, or cryptocurrency.",
    weight: 17,
    terms: [
      "gift card",
      "wire transfer",
      "bank account",
      "direct deposit",
      "bitcoin",
      "crypto",
      "invoice",
      "payment",
    ],
  },
  {
    id: "impersonation",
    label: "Impersonation cue",
    description: "Claims authority or discourages normal verification.",
    weight: 11,
    terms: [
      "ceo",
      "it department",
      "security team",
      "payroll services",
      "do not call",
      "confidential request",
      "keep this private",
    ],
  },
];

const DEFAULT_WEIGHTS: ModelWeights = Object.fromEntries(
  SIGNALS.map((signal) => [signal.id, signal.weight]),
);

// A compact labeled training set lets the genetic algorithm demonstrate model
// optimization without sending any information to an outside API.
const TRAINING_SET: { text: string; type: CaseType; target: number }[] = [
  { text: SAMPLE_CASES.phishing.text, type: "email", target: 90 },
  { text: SAMPLE_CASES.malware.text, type: "email", target: 86 },
  { text: SAMPLE_CASES.login.text, type: "security-log", target: 82 },
  { text: SAMPLE_CASES.benign.text, type: "message", target: 7 },
  {
    type: "email",
    target: 92,
    text: "CEO confidential request: buy gift cards immediately and send the codes. Do not call me about this payment.",
  },
  {
    type: "email",
    target: 15,
    text: "The approved monthly invoice is available in our normal finance workspace. Payment follows the existing schedule; no action is needed today.",
  },
];

const POSITIVE_WORDS = [
  "thanks",
  "thank you",
  "normal",
  "scheduled",
  "welcome",
  "helpful",
  "approved",
];

const NEGATIVE_WORDS = [
  "urgent",
  "warning",
  "failure",
  "unauthorized",
  "suspended",
  "disabled",
  "delay",
  "threat",
  "compromise",
  "bypass",
];

const escapeRegExp = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function countTerm(text: string, term: string) {
  return (text.match(new RegExp(escapeRegExp(term), "gi")) ?? []).length;
}

function unique(values: string[]) {
  return [...new Set(values.map((value) => value.replace(/[),.;]+$/, "")))];
}

function extractEntities(text: string) {
  const urls = unique(text.match(/https?:\/\/[^\s<>"']+/gi) ?? []);
  const emails = unique(
    text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) ?? [],
  );
  const ips = unique(
    text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [],
  );

  return [
    { label: "URLs", values: urls },
    { label: "Email addresses", values: emails },
    { label: "IP addresses", values: ips },
  ].filter((group) => group.values.length > 0);
}

/**
 * Performs an explainable local analysis. The score combines weighted security
 * indicators, entity extraction, sentiment cues, and a small false-positive
 * reduction for language that explicitly says no action is needed.
 */
function analyzeText(
  text: string,
  caseType: CaseType,
  learnedBias = 0,
  modelWeights: ModelWeights = DEFAULT_WEIGHTS,
): Analysis {
  const normalized = text.toLowerCase();
  const tokenCount = normalized.match(/[a-z0-9_.@:/-]+/g)?.length ?? 0;
  const entities = extractEntities(text);

  const matchedSignals = SIGNALS.map((signal) => {
    const matches = signal.terms.reduce(
      (total, term) => total + countTerm(normalized, term),
      0,
    );
    return { ...signal, weight: modelWeights[signal.id] ?? signal.weight, matches };
  }).filter((signal) => signal.matches > 0);

  // Repeated indicators add evidence, but their contribution is capped so one
  // repeated word cannot overwhelm every other feature.
  let score = matchedSignals.reduce(
    (total, signal) =>
      total + signal.weight + Math.min(signal.matches - 1, 2) * 2,
    4,
  );

  const entityCount = entities.reduce(
    (total, group) => total + group.values.length,
    0,
  );
  score += Math.min(entityCount * 3, 9);
  score += caseType === "security-log" && /auth_failure|mfa_bypass/i.test(text) ? 8 : 0;
  score -= /no action (?:is )?needed|for your information only/i.test(text) ? 18 : 0;
  score += learnedBias;
  score = Math.max(2, Math.min(98, Math.round(score)));

  const positive = POSITIVE_WORDS.reduce(
    (total, word) => total + countTerm(normalized, word),
    0,
  );
  const negative = NEGATIVE_WORDS.reduce(
    (total, word) => total + countTerm(normalized, word),
    0,
  );
  const pressureSignal = matchedSignals.find((signal) => signal.id === "urgency");
  const tone = pressureSignal
    ? "High-pressure / urgent"
    : negative > positive
      ? "Negative / concerning"
      : positive > negative
        ? "Neutral-positive"
        : "Neutral";

  const severity: Severity =
    score >= 78
      ? "Critical"
      : score >= 55
        ? "High"
        : score >= 30
          ? "Elevated"
          : "Low";

  const has = (id: string) =>
    matchedSignals.some((signal) => signal.id === id);
  const classification =
    has("malware") && has("delivery")
      ? "Malware delivery attempt"
      : has("credential") && has("delivery")
        ? "Credential phishing"
        : has("money") && has("impersonation")
          ? "Business email compromise"
          : caseType === "security-log" && has("account")
            ? "Account takeover activity"
            : has("money")
              ? "Financial social engineering"
              : score >= 30
                ? "Suspicious communication"
                : "Likely routine communication";

  const confidence = Math.min(
    97,
    46 + matchedSignals.length * 7 + Math.min(entityCount, 4) * 3,
  );

  const actions =
    severity === "Critical" || severity === "High"
      ? [
          "Do not click links, open attachments, reply, or provide credentials.",
          "Preserve the original message or log as evidence and notify the security team.",
          classification.includes("Account") || has("credential")
            ? "Verify the account through a known-good channel and reset exposed credentials."
            : "Verify the sender through a separate, trusted channel.",
          "Block or isolate the identified indicator only after organizational review.",
        ]
      : severity === "Elevated"
        ? [
            "Pause before interacting with the content.",
            "Verify the sender and request using a known contact method.",
            "Report the item if the context cannot be confirmed.",
          ]
        : [
            "No immediate threat response is indicated.",
            "Continue normal caution and verify unexpected requests.",
          ];

  const summary =
    matchedSignals.length > 0
      ? `${classification} is the best-fit category. The model found ${matchedSignals.length} explainable risk signal${matchedSignals.length === 1 ? "" : "s"} and ${entityCount} extractable indicator${entityCount === 1 ? "" : "s"}.`
      : "The model found no strong threat indicators in the submitted text.";

  return {
    score,
    severity,
    classification,
    tone,
    confidence,
    matchedSignals,
    entities,
    actions,
    summary,
    tokenCount,
  };
}

/**
 * Evolves signal weights through selection, crossover, and mutation. Lower
 * mean absolute error wins each generation, so better genomes survive.
 */
function evolveWeights(seedWeights: ModelWeights) {
  const signalIds = SIGNALS.map((signal) => signal.id);
  const toWeights = (genome: number[]) =>
    Object.fromEntries(signalIds.map((id, index) => [id, genome[index]]));

  // Feature extraction is performed once per labeled case. Every candidate
  // genome can then be scored with fast numeric operations instead of running
  // the full NLP pipeline thousands of times.
  const trainingFeatures = TRAINING_SET.map((item) => {
    const normalized = item.text.toLowerCase();
    const matches = SIGNALS.map((signal) =>
      signal.terms.reduce(
        (total, term) => total + countTerm(normalized, term),
        0,
      ),
    );
    const entityCount = extractEntities(item.text).reduce(
      (total, group) => total + group.values.length,
      0,
    );
    const baseScore =
      4 +
      Math.min(entityCount * 3, 9) +
      (item.type === "security-log" && /auth_failure|mfa_bypass/i.test(item.text)
        ? 8
        : 0) -
      (/no action (?:is )?needed|for your information only/i.test(item.text)
        ? 18
        : 0);
    return { target: item.target, matches, baseScore };
  });

  const scoreGenome = (genome: number[]) => {
    const error = trainingFeatures.reduce((total, item) => {
      const predicted = item.matches.reduce(
        (risk, matches, index) =>
          matches > 0
            ? risk + genome[index] + Math.min(matches - 1, 2) * 2
            : risk,
        item.baseScore,
      );
      const clamped = Math.max(2, Math.min(98, Math.round(predicted)));
      return total + Math.abs(clamped - item.target);
    }, 0);
    return error / trainingFeatures.length;
  };
  const seed = signalIds.map((id) => seedWeights[id]);
  const populationSize = 36;
  const generations = 40;

  let population = Array.from({ length: populationSize }, (_, index) =>
    index === 0
      ? seed
      : seed.map((weight) =>
          Math.max(4, Math.min(30, weight + Math.round(Math.random() * 14 - 7))),
        ),
  );

  for (let generation = 0; generation < generations; generation += 1) {
    population.sort((a, b) => scoreGenome(a) - scoreGenome(b));
    const elite = population.slice(0, 8);
    const next = elite.map((genome) => [...genome]);

    while (next.length < populationSize) {
      const parentA = elite[Math.floor(Math.random() * elite.length)];
      const parentB = elite[Math.floor(Math.random() * elite.length)];
      const child = parentA.map((gene, index) => {
        const inherited = Math.random() > 0.5 ? gene : parentB[index];
        const mutation = Math.random() < 0.28 ? Math.round(Math.random() * 8 - 4) : 0;
        return Math.max(4, Math.min(30, inherited + mutation));
      });
      next.push(child);
    }

    population = next;
  }

  population.sort((a, b) => scoreGenome(a) - scoreGenome(b));
  const weights = toWeights(population[0]);
  return {
    weights,
    result: {
      beforeError: scoreGenome(seed),
      afterError: scoreGenome(population[0]),
      generations,
    } satisfies OptimizationResult,
  };
}

function ScoreRing({ score, severity }: { score: number; severity: Severity }) {
  const ringStyle = {
    "--score": `${score * 3.6}deg`,
  } as React.CSSProperties;

  return (
    <div className={`score-ring score-${severity.toLowerCase()}`} style={ringStyle}>
      <div>
        <strong>{score}</strong>
        <span>/ 100</span>
      </div>
    </div>
  );
}

export default function Home() {
  const initial = SAMPLE_CASES.phishing;
  const [caseType, setCaseType] = useState<CaseType>(initial.type);
  const [text, setText] = useState(initial.text);
  const [selectedSample, setSelectedSample] = useState("phishing");
  const [learnedBias, setLearnedBias] = useState(0);
  const [modelWeights, setModelWeights] = useState<ModelWeights>(DEFAULT_WEIGHTS);
  const [modelVersion, setModelVersion] = useState(1);
  const [feedbackCount, setFeedbackCount] = useState(0);
  const [feedbackMessage, setFeedbackMessage] = useState(
    "No analyst reward has been recorded yet.",
  );
  const [optimization, setOptimization] = useState<OptimizationResult | null>(null);
  const [analysis, setAnalysis] = useState<Analysis>(() =>
    analyzeText(initial.text, initial.type),
  );
  const [copied, setCopied] = useState(false);

  const characterCount = text.length;
  const canAnalyze = text.trim().length >= 12;

  const reportText = useMemo(
    () =>
      [
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
      ].join("\n"),
    [analysis],
  );

  function loadSample(key: string) {
    const sample = SAMPLE_CASES[key];
    setSelectedSample(key);
    setCaseType(sample.type);
    setText(sample.text);
    setAnalysis(analyzeText(sample.text, sample.type, learnedBias, modelWeights));
  }

  function runAnalysis() {
    if (!canAnalyze) return;
    setAnalysis(analyzeText(text, caseType, learnedBias, modelWeights));
  }

  function recordFeedback(feedback: "accurate" | "too-high" | "too-low") {
    const adjustment = feedback === "too-high" ? -3 : feedback === "too-low" ? 3 : 0;
    const nextBias = Math.max(-15, Math.min(15, learnedBias + adjustment));
    setLearnedBias(nextBias);
    setFeedbackCount((count) => count + 1);
    setFeedbackMessage(
      feedback === "accurate"
        ? "Positive reward recorded. The current threshold was reinforced."
        : feedback === "too-high"
          ? "Negative reward recorded. Session risk sensitivity decreased by 3 points."
          : "Corrective reward recorded. Session risk sensitivity increased by 3 points.",
    );
    setAnalysis(analyzeText(text, caseType, nextBias, modelWeights));
  }

  function runOptimization() {
    const evolved = evolveWeights(modelWeights);
    setModelWeights(evolved.weights);
    setOptimization(evolved.result);
    setModelVersion((version) => version + 1);
    setAnalysis(analyzeText(text, caseType, learnedBias, evolved.weights));
  }

  function resetLearning() {
    setLearnedBias(0);
    setModelWeights(DEFAULT_WEIGHTS);
    setModelVersion(1);
    setFeedbackCount(0);
    setFeedbackMessage("No analyst reward has been recorded yet.");
    setOptimization(null);
    setAnalysis(analyzeText(text, caseType, 0, DEFAULT_WEIGHTS));
  }

  async function copyReport() {
    await navigator.clipboard.writeText(reportText);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  return (
    <main>
      <header className="site-header">
        <a className="brand" href="#top" aria-label="Shadow Guardian home">
          <span className="brand-mark" aria-hidden="true">
            SG
          </span>
          <span>
            <strong>SHADOW GUARDIAN</strong>
            <small>AI INCIDENT TRIAGE</small>
          </span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#triage">Triage</a>
          <a href="#learning">Learning</a>
          <a href="#team">AI team</a>
          <a href="#guide">Guide</a>
        </nav>
        <div className="local-badge">
          <span aria-hidden="true" /> Local analysis
        </div>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="eyebrow">AI-ASSISTED SECURITY OPERATIONS</p>
          <h1>
            Turn suspicious text into an <em>actionable</em> incident brief.
          </h1>
          <p className="hero-description">
            Shadow Guardian analyzes emails, messages, and security logs for
            social-engineering pressure, malicious indicators, suspicious
            entities, and account threats—then explains what to do next.
          </p>
          <div className="hero-actions">
            <a className="button button-primary" href="#triage">
              Analyze a case <span aria-hidden="true">→</span>
            </a>
            <a className="button button-quiet" href="#guide">
              How it works
            </a>
          </div>
          <p className="privacy-note">
            <span aria-hidden="true">◆</span> Runs entirely in your browser. No
            submitted text is uploaded or stored.
          </p>
        </div>

        <aside className="engine-panel" aria-label="Analysis engine status">
          <div className="panel-topline">
            <span>ENGINE STATUS</span>
            <span className="status-online">ONLINE</span>
          </div>
          <div className="engine-visual" aria-hidden="true">
            <div className="radar-ring radar-one" />
            <div className="radar-ring radar-two" />
            <div className="radar-sweep" />
            <div className="radar-core">SG</div>
            <i className="ping ping-one" />
            <i className="ping ping-two" />
            <i className="ping ping-three" />
          </div>
          <div className="engine-modules">
            <div>
              <span>NLP ENGINE</span>
              <strong>READY</strong>
            </div>
            <div>
              <span>SENTIMENT</span>
              <strong>READY</strong>
            </div>
            <div>
              <span>ENTITY SCAN</span>
              <strong>READY</strong>
            </div>
            <div>
              <span>RISK MODEL</span>
              <strong>v{modelVersion}.0</strong>
            </div>
          </div>
        </aside>
      </section>

      <section className="trust-strip" aria-label="Product features">
        <span><b>01</b> Explainable scoring</span>
        <span><b>02</b> No account required</span>
        <span><b>03</b> Human review built in</span>
        <span><b>04</b> Zero data retention</span>
      </section>

      <section className="triage-section" id="triage">
        <div className="section-heading">
          <div>
            <p className="eyebrow">LIVE WORKSPACE</p>
            <h2>Incident triage console</h2>
          </div>
          <p>
            Test a realistic example or paste your own non-confidential text.
            Every result includes the evidence behind the score.
          </p>
        </div>

        <div className="workspace-grid">
          <div className="input-panel">
            <div className="panel-heading">
              <div>
                <span className="panel-kicker">CASE INPUT</span>
                <h3>What are you investigating?</h3>
              </div>
              <span className="case-id">CASE-0826</span>
            </div>

            <div className="field-row">
              <label htmlFor="case-type">Content type</label>
              <select
                id="case-type"
                value={caseType}
                onChange={(event) => setCaseType(event.target.value as CaseType)}
              >
                <option value="email">Email</option>
                <option value="message">Text / chat message</option>
                <option value="security-log">Security log</option>
              </select>
            </div>

            <div className="sample-group">
              <span>LOAD A TEST CASE</span>
              <div className="sample-buttons">
                {Object.entries(SAMPLE_CASES).map(([key, sample]) => (
                  <button
                    className={selectedSample === key ? "active" : ""}
                    key={key}
                    onClick={() => loadSample(key)}
                    type="button"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
            </div>

            <label className="textarea-label" htmlFor="case-text">
              Message or log content
              <span>{characterCount.toLocaleString()} characters</span>
            </label>
            <textarea
              id="case-text"
              value={text}
              onChange={(event) => {
                setText(event.target.value);
                setSelectedSample("");
              }}
              placeholder="Paste suspicious text here…"
              spellCheck="false"
            />
            <div className="input-footer">
              <p>Minimum 12 characters. Never paste passwords or sensitive data.</p>
              <button
                className="button button-primary analyze-button"
                disabled={!canAnalyze}
                onClick={runAnalysis}
                type="button"
              >
                Run AI triage <span aria-hidden="true">→</span>
              </button>
            </div>
          </div>

          <div className="result-panel" aria-live="polite">
            <div className="panel-heading result-heading">
              <div>
                <span className="panel-kicker">ANALYSIS COMPLETE</span>
                <h3>Threat assessment</h3>
              </div>
              <button className="copy-button" onClick={copyReport} type="button">
                {copied ? "Copied" : "Copy report"}
              </button>
            </div>

            <div className="score-summary">
              <ScoreRing score={analysis.score} severity={analysis.severity} />
              <div>
                <span className={`severity severity-${analysis.severity.toLowerCase()}`}>
                  {analysis.severity} risk
                </span>
                <h4>{analysis.classification}</h4>
                <p>{analysis.summary}</p>
              </div>
            </div>

            <div className="metric-grid">
              <div>
                <span>LANGUAGE TONE</span>
                <strong>{analysis.tone}</strong>
              </div>
              <div>
                <span>MODEL CONFIDENCE</span>
                <strong>{analysis.confidence}%</strong>
              </div>
              <div>
                <span>TOKENS REVIEWED</span>
                <strong>{analysis.tokenCount}</strong>
              </div>
            </div>

            <div className="result-block">
              <div className="block-title">
                <h4>Why it was flagged</h4>
                <span>{analysis.matchedSignals.length} signals</span>
              </div>
              {analysis.matchedSignals.length > 0 ? (
                <div className="signal-list">
                  {analysis.matchedSignals.map((signal) => (
                    <div className="signal-item" key={signal.id}>
                      <span className="signal-icon" aria-hidden="true">!</span>
                      <div>
                        <strong>{signal.label}</strong>
                        <p>{signal.description}</p>
                      </div>
                      <b>+{signal.weight}</b>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="empty-state">No strong threat signals detected.</p>
              )}
            </div>

            {analysis.entities.length > 0 && (
              <div className="result-block">
                <div className="block-title">
                  <h4>Extracted indicators</h4>
                  <span>NLP entities</span>
                </div>
                <div className="entity-list">
                  {analysis.entities.map((entity) => (
                    <div key={entity.label}>
                      <span>{entity.label}</span>
                      {entity.values.map((value) => (
                        <code key={value}>{value}</code>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="result-block action-block">
              <div className="block-title">
                <h4>Recommended response</h4>
                <span>Human decision</span>
              </div>
              <ol>
                {analysis.actions.map((action) => (
                  <li key={action}>{action}</li>
                ))}
              </ol>
            </div>

            <div className="feedback-panel">
              <div className="feedback-copy">
                <span>REINFORCEMENT FEEDBACK</span>
                <strong>Help the model learn</strong>
                <p>Reward or correct this result. Adjustments last for the current session only.</p>
              </div>
              <div className="feedback-buttons" aria-label="Assessment feedback">
                <button onClick={() => recordFeedback("accurate")} type="button">
                  Accurate
                </button>
                <button onClick={() => recordFeedback("too-high")} type="button">
                  Risk too high
                </button>
                <button onClick={() => recordFeedback("too-low")} type="button">
                  Risk too low
                </button>
              </div>
              <div className="reward-status">
                <span>{feedbackCount} reward{feedbackCount === 1 ? "" : "s"}</span>
                <p>{feedbackMessage}</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="method-section" id="method">
        <div className="section-heading compact-heading">
          <div>
            <p className="eyebrow">UNDER THE HOOD</p>
            <h2>AI that shows its work</h2>
          </div>
          <p>
            The prototype uses transparent browser-based methods so students,
            analysts, and nontechnical users can understand each decision.
          </p>
        </div>
        <div className="method-grid">
          <article>
            <span>01 / NLP</span>
            <h3>Language processing</h3>
            <p>Tokenizes the text, recognizes security phrases, and extracts URLs, email addresses, and IP addresses.</p>
          </article>
          <article>
            <span>02 / SENTIMENT</span>
            <h3>Pressure detection</h3>
            <p>Compares emotional and urgency cues to identify fear-based language used in social engineering.</p>
          </article>
          <article>
            <span>03 / CLASSIFICATION</span>
            <h3>Explainable risk model</h3>
            <p>Combines weighted evidence to classify the case and produce a severity-based response plan.</p>
          </article>
          <article>
            <span>04 / REINFORCEMENT</span>
            <h3>Analyst feedback</h3>
            <p>Accepts rewards and corrections, then adjusts risk sensitivity during the active session.</p>
          </article>
          <article>
            <span>05 / GENETIC ALGORITHM</span>
            <h3>Weight evolution</h3>
            <p>Uses selection, crossover, mutation, and fitness scoring to optimize detection weights.</p>
          </article>
        </div>
      </section>

      <section className="learning-section" id="learning">
        <div className="section-heading">
          <div>
            <p className="eyebrow">MODEL LEARNING LAB</p>
            <h2>Train it. Test it. Keep the human in charge.</h2>
          </div>
          <p>
            These interactive demonstrations show two contemporary AI learning
            approaches without hiding the logic behind an external service.
          </p>
        </div>

        <div className="learning-grid">
          <article className="learning-card reinforcement-card">
            <div className="learning-card-heading">
              <span>RL / SESSION 01</span>
              <b>REINFORCEMENT LEARNING</b>
            </div>
            <h3>Feedback changes model sensitivity.</h3>
            <p>
              The analyst acts as the environment. Each correction becomes a
              reward signal that moves the session risk threshold up or down.
            </p>
            <div className="bias-meter" aria-label={`Session bias ${learnedBias} points`}>
              <span>−15</span>
              <div>
                <i style={{ left: `${((learnedBias + 15) / 30) * 100}%` }} />
              </div>
              <span>+15</span>
            </div>
            <div className="learning-readout">
              <div>
                <span>CURRENT BIAS</span>
                <strong>{learnedBias > 0 ? `+${learnedBias}` : learnedBias}</strong>
              </div>
              <div>
                <span>REWARD EVENTS</span>
                <strong>{feedbackCount}</strong>
              </div>
              <div>
                <span>MEMORY</span>
                <strong>SESSION</strong>
              </div>
            </div>
          </article>

          <article className="learning-card genetic-card">
            <div className="learning-card-heading">
              <span>GA / MODEL {modelVersion}.0</span>
              <b>GENETIC ALGORITHM</b>
            </div>
            <h3>Evolve a stronger set of detection weights.</h3>
            <p>
              A population of 36 candidate models competes against six labeled
              cases for 40 generations. The fittest weights survive.
            </p>
            <div className="weight-list">
              {SIGNALS.slice(0, 5).map((signal) => (
                <div className="weight-row" key={signal.id}>
                  <span>{signal.label}</span>
                  <div><i style={{ width: `${(modelWeights[signal.id] / 30) * 100}%` }} /></div>
                  <b>{modelWeights[signal.id]}</b>
                </div>
              ))}
            </div>
            <div className="optimizer-footer">
              <div className="optimizer-metrics">
                <span>
                  BEFORE <b>{optimization ? optimization.beforeError.toFixed(1) : "—"}</b>
                </span>
                <span>
                  AFTER <b>{optimization ? optimization.afterError.toFixed(1) : "—"}</b>
                </span>
              </div>
              <button className="button button-primary" onClick={runOptimization} type="button">
                Evolve model <span aria-hidden="true">↗</span>
              </button>
            </div>
          </article>
        </div>
        <div className="learning-reset">
          <p>
            Model {modelVersion}.0 · {optimization ? `${optimization.generations} generations completed` : "Baseline weights active"}
          </p>
          <button onClick={resetLearning} type="button">Reset learning lab</button>
        </div>
      </section>

      <section className="team-section" id="team">
        <div className="team-intro">
          <div>
            <p className="eyebrow">AI DEVELOPMENT TEAM</p>
            <h2>Three specialists. One human manager.</h2>
          </div>
          <div className="manager-badge">
            <span>PROJECT MANAGER</span>
            <strong>Stefanie Redding</strong>
            <p>Defined the purpose, assigned roles, reviewed outputs, and approved the final experience.</p>
          </div>
        </div>

        <div className="team-grid">
          <article>
            <div className="employee-topline">
              <span className="employee-avatar">N</span>
              <span className="employee-status">ASSIGNMENT COMPLETE</span>
            </div>
            <span className="employee-number">AI EMPLOYEE 01</span>
            <h3>Nyx</h3>
            <h4>Threat Logic Engineer</h4>
            <p>Designed the security-signal taxonomy, risk categories, and incident-response recommendations.</p>
            <ul>
              <li>Threat indicator research</li>
              <li>Explainable scoring rules</li>
              <li>Response playbooks</li>
            </ul>
          </article>
          <article>
            <div className="employee-topline">
              <span className="employee-avatar">M</span>
              <span className="employee-status">ASSIGNMENT COMPLETE</span>
            </div>
            <span className="employee-number">AI EMPLOYEE 02</span>
            <h3>Mara</h3>
            <h4>UX &amp; NLP Analyst</h4>
            <p>Refined the language analysis, pressure detection, plain-language explanations, and user flow.</p>
            <ul>
              <li>Sentiment vocabulary</li>
              <li>Entity extraction review</li>
              <li>Accessibility and UX</li>
            </ul>
          </article>
          <article>
            <div className="employee-topline">
              <span className="employee-avatar">C</span>
              <span className="employee-status">ASSIGNMENT COMPLETE</span>
            </div>
            <span className="employee-number">AI EMPLOYEE 03</span>
            <h3>Cipher</h3>
            <h4>QA &amp; Optimization Engineer</h4>
            <p>Tested sample cases, validated responsive behavior, and implemented genetic model optimization.</p>
            <ul>
              <li>Functional test cases</li>
              <li>Genetic algorithm tuning</li>
              <li>Code and quality review</li>
            </ul>
          </article>
        </div>

        <p className="team-note">
          Each AI employee received a defined role, deliverables, constraints,
          and review criteria. Final decisions remained with the human manager.
        </p>
      </section>

      <section className="guide-section" id="guide">
        <div>
          <p className="eyebrow">HOW TO USE</p>
          <h2>Three steps. No cybersecurity degree required.</h2>
        </div>
        <div className="guide-steps">
          <article>
            <b>1</b>
            <div>
              <h3>Add the evidence</h3>
              <p>Choose the content type, then paste a suspicious email, message, or security log.</p>
            </div>
          </article>
          <article>
            <b>2</b>
            <div>
              <h3>Run AI triage</h3>
              <p>Review the score, threat category, language tone, extracted entities, and evidence.</p>
            </div>
          </article>
          <article>
            <b>3</b>
            <div>
              <h3>Make the human call</h3>
              <p>Follow the recommended response, verify independently, and escalate when appropriate.</p>
            </div>
          </article>
        </div>
      </section>

      <footer>
        <div className="brand footer-brand">
          <span className="brand-mark" aria-hidden="true">SG</span>
          <span>
            <strong>SHADOW GUARDIAN</strong>
            <small>AI INCIDENT TRIAGE</small>
          </span>
        </div>
        <p>Educational security prototype created by Stefanie Redding.</p>
        <p>AI assists. Humans decide.</p>
      </footer>
    </main>
  );
}
