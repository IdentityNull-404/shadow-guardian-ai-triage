# AI Employee Development Log

## Human Project Manager

**Stefanie Redding**

The project manager defined the application purpose, divided the work into specialized roles, set acceptance criteria, reviewed the results, tested the finished application, and retained final decision-making authority.

## Shared Project Brief

Create a useful, intuitive cybersecurity application that helps a user triage suspicious emails, messages, and logs. The application must explain its decisions, protect user privacy, work on desktop and mobile browsers, include clear instructions, use well-commented code, and demonstrate multiple artificial intelligence methods from CSC150.

## AI Employee 01 … Nyx

**Role:** Threat Logic Engineer

**Assigned work:**

1. Define realistic threat indicators for credential phishing, malware delivery, account compromise, financial social engineering, and impersonation.
2. Design a transparent scoring model that can explain each contribution.
3. Create severity-based response recommendations that keep a human analyst in control.
4. Review sample cases for false negatives and unreasonable actions.

**Required output:** Threat taxonomy, scoring weights, classification rules, and response playbooks.

**Acceptance criteria:** Every risk score must have visible evidence. Recommendations must avoid automatically deleting, blocking, or executing anything. High-risk results must encourage independent verification and escalation.

**Completed contribution:** The signal library, classification logic, risk thresholds, and response actions in `app/page.tsx` and `static-app.js`.

## AI Employee 02 … Mara

**Role:** UX and NLP Analyst

**Assigned work:**

1. Review the user journey from case input through human decision.
2. Create plain-language explanations that do not require advanced cybersecurity knowledge.
3. Develop urgency, pressure, positive, and negative sentiment vocabulary.
4. Review accessibility, keyboard focus, color contrast, responsive layout, and privacy language.

**Required output:** NLP vocabulary, sentiment rules, interface copy, use instructions, and UX review notes.

**Acceptance criteria:** A first-time user must understand the purpose and complete a test case without separate instructions. The interface must identify itself, explain how to use it, remain readable on mobile devices, and state that text is processed locally.

**Completed contribution:** Sentiment analysis, entity labels, interface instructions, accessible form labels, privacy notices, and responsive layout.

## AI Employee 03 … Cipher

**Role:** QA and Optimization Engineer

**Assigned work:**

1. Create test cases for phishing, malware delivery, account takeover, and normal communication.
2. Implement a genetic algorithm using selection, crossover, mutation, and fitness scoring.
3. Validate reinforcement feedback and model-reset behavior.
4. Review the source for clear comments, safe text rendering, and consistent results.

**Required output:** Test matrix, genetic optimization module, reinforcement-feedback checks, and final quality review.

**Acceptance criteria:** Built-in samples must produce the expected categories. Genetic optimization must improve or preserve mean model error. Pasted text must be escaped before HTML rendering. Reset must restore baseline weights and feedback state.

**Completed contribution:** Six-case training set, 36-genome genetic algorithm, session reinforcement feedback, safe output rendering, and functional test expectations.

## Manager Review

The human manager reviewed the combined work for usefulness, clarity, safety, course alignment, and visual quality. Conflicting goals were resolved in favor of explainability, privacy, and human control. The completed application includes a name, description, instructions, multiple AI methods, three documented AI employee roles, well-commented source code, and a responsive user experience.
