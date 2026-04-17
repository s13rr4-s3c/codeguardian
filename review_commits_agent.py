#!/usr/bin/env python3
"""
CodeGuardian - AppSec diff analyzer testes.
Streaming com buffer de bloco para garantir cores corretas e feedback estruturado.
"""

import subprocess
import os
import re
import sys
from collections import Counter
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.theme import Theme
from rich import box

# =========================
# CONFIG
# =========================

MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY:
    raise SystemExit("Define OPENAI_API_KEY in environment variables")

console = Console(theme=Theme({
    "high":   "bold red",
    "medium": "bold yellow",
    "low":    "bold cyan",
    "info":   "bold blue",
    "ok":     "bold green",
    "muted":  "dim white",
    "arrow":  "dim",
    "lineno": "bright_magenta",
    "label":  "bold white",
}))

llm = ChatOpenAI(
    model=MODEL,
    temperature=0,
    api_key=API_KEY,
    streaming=True,
)

# =========================
# LANGUAGE DETECTION
# =========================

EXT_MAP: dict[str, str] = {
    ".py":   "Python",      ".js":   "JavaScript", ".ts":    "TypeScript",
    ".jsx":  "React/JSX",   ".tsx":  "React/TSX",  ".java":  "Java",
    ".kt":   "Kotlin",      ".go":   "Go",          ".rb":    "Ruby",
    ".php":  "PHP",         ".cs":   "C#",          ".cpp":   "C++",
    ".c":    "C",           ".rs":   "Rust",         ".swift": "Swift",
    ".sh":   "Shell",       ".bash": "Bash",         ".yaml":  "YAML",
    ".yml":  "YAML",        ".json": "JSON",         ".tf":    "Terraform",
    ".sql":  "SQL",         ".html": "HTML",         ".xml":   "XML",
    ".toml": "TOML",        ".env":  "Env/Config",
}

LEXER_MAP: dict[str, str] = {
    "Python": "python",  "JavaScript": "javascript", "TypeScript": "typescript",
    "React/JSX": "jsx",  "React/TSX": "tsx",         "Java": "java",
    "Kotlin": "kotlin",  "Go": "go",                 "Ruby": "ruby",
    "PHP": "php",        "C#": "csharp",             "C++": "cpp",
    "C": "c",            "Rust": "rust",             "Swift": "swift",
    "Shell": "bash",     "Bash": "bash",             "YAML": "yaml",
    "JSON": "json",      "Terraform": "hcl",         "SQL": "sql",
    "HTML": "html",      "XML": "xml",               "TOML": "toml",
}

def detect_languages(diff: str) -> list[str]:
    filenames  = re.findall(r"diff --git a/(.+?) b/", diff)
    filenames += re.findall(r"(?:\+\+\+|---) [ab]/(.+)", diff)

    ext_counter: Counter = Counter()
    for fname in filenames:
        base = os.path.basename(fname).lower()
        if base == "dockerfile" or base.startswith("dockerfile."):
            ext_counter["Dockerfile"] += 1
            continue
        _, ext = os.path.splitext(fname.lower())
        if ext in EXT_MAP:
            ext_counter[EXT_MAP[ext]] += 1

    return [lang for lang, _ in ext_counter.most_common()] if ext_counter else ["Unknown"]


# =========================
# GIT DIFF
# =========================

def get_staged_diff() -> str:
    result = subprocess.run(["git", "diff", "--cached"], capture_output=True, text=True)
    if result.returncode != 0:
        console.print(f"[red]Erro ao executar git diff:[/red] {result.stderr}")
        sys.exit(1)
    return result.stdout.strip()


# =========================
# PROMPT
# =========================

SYSTEM_PROMPT = """\
You are a senior Application Security (AppSec) engineer.
Analyze code diffs for security vulnerabilities.
Be precise, concise, and actionable.
Always respond in the EXACT structured format requested — no deviations, no extra text outside the blocks.
"""

def build_user_prompt(diff: str, languages: list[str]) -> str:
    lang_str = ", ".join(languages)
    return f"""\
Analyze the following {lang_str} code diff for security vulnerabilities.

Focus on:
- OWASP Top 10
- Injection (SQL, command, LDAP, template)
- XSS, SSRF, RCE, IDOR
- Secrets / sensitive data hardcoded
- Missing validation or sanitization
- Insecure dependencies or patterns
- Auth / authorization flaws
- Insecure deserialization
- Misconfigured infra (YAML/TF/Dockerfile)

Use EXACTLY this format for each issue. No extra text outside the blocks.

===ISSUE===
SEVERITY: HIGH | MEDIUM | LOW | INFO
TITLE: <short title>
FILE: <filename>
LINE: <line number from the diff where the vulnerability appears, or "unknown">
SNIPPET:
<the vulnerable code line(s) exactly as they appear in the diff, without the leading + or ->
FIX:
<corrected version of the snippet, or a short practical explanation if a full snippet fix is not applicable>
EXPLANATION: <one or two sentences explaining the risk>
===END===

If no issues found, output exactly:
NO_ISSUES

Code diff:
{diff}
"""


# =========================
# RENDERING
# =========================

SEVERITY_STYLE = {
    "HIGH":   ("high",   "🔴"),
    "MEDIUM": ("medium", "🟡"),
    "LOW":    ("low",    "🔵"),
    "INFO":   ("info",   "ℹ️ "),
}

def render_issue(block: str, languages: list[str], index: int) -> None:
    """Parseia e imprime um bloco ===ISSUE=== formatado."""

    def field(name: str) -> str:
        m = re.search(rf"^{name}:\s*(.+)$", block, re.MULTILINE)
        return m.group(1).strip() if m else ""

    def multiline_field(name: str) -> str:
        # Captura tudo após "NAME:\n" até a próxima chave ou fim
        m = re.search(rf"^{name}:\n([\s\S]+?)(?=\n[A-Z_]+:|\Z)", block, re.MULTILINE)
        return m.group(1).strip() if m else ""

    severity    = field("SEVERITY").upper()
    title       = field("TITLE")
    file_       = field("FILE")
    line        = field("LINE")
    explanation = field("EXPLANATION")
    snippet     = multiline_field("SNIPPET")
    fix         = multiline_field("FIX")

    style, icon = SEVERITY_STYLE.get(severity, ("muted", "⚪"))

    # Cabeçalho do issue
    console.print()
    console.print(Panel(
        f"[{style}]{icon}  [{severity}][/{style}]  [label]{title}[/label]",
        title=f"[muted]Issue #{index}[/muted]",
        border_style=style,
        box=box.ROUNDED,
        padding=(0, 2),
    ))

    # Localização
    loc_parts = []
    if file_:
        loc_parts.append(f"[muted]📄 Arquivo:[/muted] [white]{file_}[/white]")
    if line and line.lower() not in ("unknown", "n/a", ""):
        loc_parts.append(f"[muted]📍 Linha:[/muted] [lineno]{line}[/lineno]")
    if loc_parts:
        console.print("   " + "   ".join(loc_parts))

    # Explicação
    if explanation:
        console.print(f"\n   [arrow]→[/arrow] [muted]{explanation}[/muted]")

    # Detecta lexer pelo arquivo ou linguagem principal
    lexer = "text"
    if file_:
        _, ext = os.path.splitext(file_.lower())
        lang_from_ext = EXT_MAP.get(ext, "")
        lexer = LEXER_MAP.get(lang_from_ext, "text")
    elif languages:
        lexer = LEXER_MAP.get(languages[0], "text")

    # Snippet vulnerável
    if snippet:
        line_label = f"linha {line}" if line and line.lower() not in ("unknown", "n/a", "") else "trecho"
        console.print(f"\n   [muted]Código vulnerável ({line_label}):[/muted]")
        console.print(Syntax(snippet, lexer, theme="monokai", line_numbers=False, padding=(0, 4)))

    # Correção sugerida
    if fix:
        console.print(f"\n   [ok]✔  Correção sugerida:[/ok]")
        looks_like_code = bool(re.search(r"[(){}\[\]=;]|->|::", fix))
        if looks_like_code and snippet:
            console.print(Syntax(fix, lexer, theme="vim", line_numbers=False, padding=(0, 4)))
        else:
            # Texto simples, mas quebra linhas longas
            for fix_line in fix.splitlines():
                console.print(f"   [white]{fix_line}[/white]")


# =========================
# STREAM + PARSE
# =========================

def stream_and_render(diff: str, languages: list[str]) -> None:
    """
    Coleta a resposta em streaming, acumula em buffer,
    e renderiza cada bloco ===ISSUE=== imediatamente ao completá-lo.
    """
    prompt   = build_user_prompt(diff, languages)
    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)]

    console.print()
    console.print(Rule("[muted]iniciando análise[/muted]", style="bright_blue"))
    console.print()

    # Indicador de progresso enquanto aguarda o primeiro token
    with Progress(SpinnerColumn(), TextColumn("[muted]{task.description}[/muted]"),
                  console=console, transient=True) as progress:
        task = progress.add_task("Aguardando resposta do modelo...", total=None)

        buffer     = ""
        in_issue   = False
        first_seen = False
        issue_count = 0

        for chunk in llm.stream(messages):
            token = chunk.content
            if not token:
                continue

            if not first_seen:
                progress.stop()   # para o spinner ao receber o primeiro token
                first_seen = True

            buffer += token

            # Processa todos os blocos completos disponíveis no buffer
            while True:
                if not in_issue:
                    start = buffer.find("===ISSUE===")
                    if start == -1:
                        # Descarta tudo exceto um sufixo que pode ser início de marcador
                        buffer = buffer[-20:]
                        break
                    in_issue = True
                    buffer   = buffer[start:]

                end = buffer.find("===END===")
                if end == -1:
                    break  # bloco incompleto, aguarda mais tokens

                block       = buffer[len("===ISSUE==="):end].strip()
                buffer      = buffer[end + len("===END==="):]
                in_issue    = False
                issue_count += 1
                render_issue(block, languages, issue_count)

    # Resultado final
    console.print()
    if issue_count == 0:
        console.print(Panel(
            "[ok]✅  Nenhum problema de segurança relevante encontrado.[/ok]",
            border_style="green",
            box=box.ROUNDED,
            padding=(0, 2),
        ))
    else:
        total_label = f"{issue_count} issue{'s' if issue_count > 1 else ''} encontrado{'s' if issue_count > 1 else ''}"
        console.print(Rule(f"[muted]{total_label}[/muted]", style="bright_blue"))


# =========================
# HEADER / FOOTER
# =========================

def print_header(languages: list[str]) -> None:
    lang_str = " · ".join(languages)
    console.print(Panel(
        Text(f"AppSec Review  │  {lang_str}", style="muted"),
        title=Text("🔐  CodeGuardian", style="bold white"),
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))


def print_footer() -> None:
    console.print(f"\n[muted]Model: {MODEL}  │  CodeGuardian[/muted]\n", justify="right")


# =========================
# MAIN
# =========================

def main() -> None:
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        t = progress.add_task("Coletando staged diff...", total=None)
        diff = get_staged_diff()
        progress.update(t, description="Detectando linguagens...")
        languages = detect_languages(diff)

    if not diff:
        console.print("[yellow]⚠  Nenhuma alteração staged. Use `git add` antes.[/yellow]")
        return

    print_header(languages)
    stream_and_render(diff, languages)
    print_footer()


if __name__ == "__main__":
    main()
