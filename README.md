# Shadow Guardian AI Incident Triage Center

Shadow Guardian is a client-side cybersecurity assistant that analyzes suspicious emails, text messages, and security logs. It identifies social-engineering pressure, credential requests, malicious delivery methods, account threats, and financial manipulation. It then explains the risk score, extracts useful indicators, and recommends a human-reviewed response.

The application has a practical purpose: helping a user decide whether suspicious text should be ignored, verified, reported, or escalated. It is an educational prototype, not a replacement for a security analyst or a production security platform.

## Live Application

After GitHub Pages is enabled, the static site is available at:

`https://identitynull-404.github.io/shadow-guardian-ai-triage/`

## How to Use

1. Open the application in a modern browser.
2. Choose Email, Text / chat message, or Security log.
3. Load a built-in test case or paste non-confidential text.
4. Select **Run AI triage**.
5. Review the score, classification, sentiment, extracted entities, evidence, and response plan.
6. Use **Accurate**, **Risk too high**, or **Risk too low** to demonstrate reinforcement feedback.
7. Open the Learning Lab and select **Evolve model** to run the genetic algorithm.

## Artificial Intelligence Methods

| Method | Implementation | User Benefit |
| --- | --- | --- |
| Natural Language Processing | Tokenization, phrase recognition, and entity extraction for URLs, email addresses, and IP addresses | Converts unstructured security text into useful evidence |
| Sentiment Analysis | Positive, negative, urgency, and pressure-language comparison | Detects fear and urgency used in social engineering |
| Explainable Classification | Weighted, visible security indicators | Shows why a risk score changed |
| Reinforcement Learning Demonstration | Analyst feedback adjusts risk sensitivity during the active session | Demonstrates reward and correction signals while keeping a human in control |
| Genetic Algorithm | Population selection, crossover, mutation, and fitness testing across labeled cases | Evolves detection weights and displays the before-and-after model error |
| Generative AI | Specialized AI employee roles supported planning, threat logic, UX review, optimization, and quality assurance | Demonstrates managed AI collaboration during software development |

## AI Development Team

Stefanie Redding served as the human project manager. The project used three defined AI employee roles:

1. **Nyx … Threat Logic Engineer:** Developed the threat taxonomy, scoring rules, and response playbooks.
2. **Mara … UX and NLP Analyst:** Refined sentiment vocabulary, explanations, accessibility, and user flow.
3. **Cipher … QA and Optimization Engineer:** Tested sample cases, reviewed the code, and implemented model optimization.

Detailed assignments and acceptance criteria are recorded in [AI_EMPLOYEE_LOG.md](AI_EMPLOYEE_LOG.md).

## Source Files

| File | Purpose |
| --- | --- |
| `index.html` | GitHub Pages entry point and complete user interface |
| `static-app.js` | Commented NLP, sentiment, scoring, feedback, and genetic-algorithm logic |
| `app/globals.css` | Responsive visual design and accessibility styling |
| `app/page.tsx` | React version used for the hosted application |
| `AI_EMPLOYEE_LOG.md` | AI employee responsibilities, deliverables, and review criteria |

## Run Locally

No build step is required for the GitHub Pages version. Download the repository and open `index.html`, or serve the repository with any basic static web server.

## Privacy and Safety

The static application processes text entirely inside the browser. It does not create an account, call an external API, transmit submitted text, or retain case content. Users should still avoid pasting passwords, confidential records, or regulated data. All results require human verification.

## Test Cases

| Case | Expected Result |
| --- | --- |
| Credential phishing sample | Critical risk and Credential phishing |
| Malware delivery sample | High or Critical risk and Malware delivery attempt |
| Security alert sample | High or Critical risk and Account takeover activity |
| Normal message sample | Low risk and Likely routine communication |

Created by Stefanie Redding for CSC150 … Introduction to AI and Analytics.
