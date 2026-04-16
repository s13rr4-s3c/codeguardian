# CodeGuardian

CodeGuardian is a multi-agent pipeline for **secure code generation, analysis, and automated hardening**.

It simulates a **DevSecOps workflow powered by LLMs**, enabling developers to generate code, identify vulnerabilities, and automatically improve security posture.

---

## 🚀 Features

- Multi-agent orchestration using LangGraph
- Automated secure code generation
- Security-focused code review (AppSec-oriented)
- Automated refactoring based on identified vulnerabilities
- Multi-language support
- Rich CLI output with syntax highlighting (Rich)

---

## 🧠 How It Works

The pipeline is composed of three agents:

- **Generator Agent** → Produces code based on user input
- **Security Reviewer Agent** → Identifies vulnerabilities and bad practices
- **Refactor Agent** → Applies security improvements and hardening

---

## 📦 Requirements

- Python 3.10+
- OpenAI API Key (or compatible provider)

---

## 🔑 Environment Variables

```bash
export OPENAI_API_KEY="your-api-key"
# optional
export OPENAI_MODEL="gpt-4o-mini"

```

---

## ⚙️ Setup

```bash
git clone https://github.com/s13rr4-s3c/codeguardian.git
cd codeguardian

python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

./venv/bin/pip3 install -r requirements.txt

```

---

## ▶️ Usage

```bash
python main.py

```

Steps:

- Select a programming language
- Describe the function you want
- The pipeline will generate, review, and harden the code

---

## Additional Review Mode

Besides the main pipeline in `main.py`, the project also includes `review-commits_agent.py`.

This agent does not generate or refactor code. It is focused only on reviewing the changes prepared by the developer for commit, analyzing just the modified portion of the project instead of the whole codebase.

---

## 🛡️ Security Focus

This project is designed with an **Application Security (AppSec)** mindset, including:

- Identification of insecure coding patterns
- Basic vulnerability detection (LLM-assisted)
- Automated secure refactoring
- Secure-by-design development approach

---

## ⚠️ Disclaimer

This tool **does not replace**:

- Manual code review
- SAST/DAST tools
- Professional security assessments

It should be used as a **support tool** in a secure development lifecycle.

---

## 📌 Future Improvements

- Integration with SAST/DAST tools (e.g., OWASP ZAP)
- CI/CD pipeline integration
- Custom security policies (policy-as-code)
- Export reports (JSON / SARIF)
- Integration with vulnerability management workflows

---

## 🤖 AI Usage

This project uses LLMs as part of its architecture for:

- Code generation
- Security analysis
- Automated refactoring

All outputs are orchestrated through a structured multi-agent pipeline aligned with secure development practices.

---

## 👨‍💻 Author

s13rr4_sec