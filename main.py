import os
import re
from typing import TypedDict
from langgraph.graph import StateGraph
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.text import Text

console = Console()

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise SystemExit(
        "Defina OPENAI_API_KEY antes de executar o script. "
        "Exemplo: export OPENAI_API_KEY='sua-chave'"
    )

llm_kwargs = {
    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
    "temperature": 0,
    "api_key": api_key,
}
base_url = os.getenv("OPENAI_BASE_URL")
if base_url:
    llm_kwargs["base_url"] = base_url

llm = ChatOpenAI(**llm_kwargs)

# Mapa de linguagens suportadas: nome exibido -> lexer do rich
LINGUAGENS = {
    "1": ("Python",     "python"),
    "2": ("JavaScript", "javascript"),
    "3": ("TypeScript", "typescript"),
    "4": ("Go",         "go"),
    "5": ("Rust",       "rust"),
    "6": ("Java",       "java"),
    "7": ("C",          "c"),
    "8": ("C++",        "cpp"),
    "9": ("Bash",       "bash"),
}

class State(TypedDict, total=False):
    input: str
    language: str       # nome legível, ex: "Python"
    lexer: str          # lexer do rich, ex: "python"
    code: str
    review: str
    final_code: str


def extrair_codigo(texto: str, lexer: str) -> tuple[str, str]:
    """Separa blocos de código markdown do texto explicativo."""
    # aceita ```python, ```js, ``` etc.
    padrao = re.compile(r"```(?:\w+)?\n(.*?)```", re.DOTALL)
    blocos = padrao.findall(texto)
    codigo = "\n\n".join(blocos) if blocos else ""
    texto_limpo = padrao.sub("", texto).strip()
    return codigo, texto_limpo


def print_codigo(titulo: str, texto: str, lexer: str):
    codigo, comentarios = extrair_codigo(texto, lexer)
    if comentarios:
        console.print(f"\n[bold dim]{comentarios}[/bold dim]")
    alvo = codigo if codigo else texto  # fallback sem markdown
    syntax = Syntax(alvo, lexer, theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=f"[bold cyan]{titulo}[/bold cyan]", border_style="cyan"))


def gerar_codigo(state):
    # \\[ é o escape correto para exibir "[" literal no rich sem SyntaxWarning
    console.print("\n[bold yellow]⚙️  [AGENTE 1][/bold yellow] Gerando código...", highlight=False)
    prompt = (
        f"Crie uma função em {state['language']} baseada nisso: {state['input']}. "
        f"Retorne apenas o código, sem explicações fora do bloco de código."
    )
    response = llm.invoke([HumanMessage(content=prompt)])
    console.print("[bold green]✅ [AGENTE 1][/bold green] Código gerado!")
    print_codigo("CÓDIGO GERADO", response.content, state["lexer"])
    return {"code": response.content}


def revisar_codigo(state):
    console.print("\n[bold yellow]🔍  [AGENTE 2][/bold yellow] Revisando segurança...", highlight=False)
    prompt = (
        f"Analise o código {state['language']} abaixo com foco em segurança. "
        f"Aponte vulnerabilidades e problemas:\n{state['code']}"
    )
    response = llm.invoke([HumanMessage(content=prompt)])
    console.print("[bold green]✅ [AGENTE 2][/bold green] Revisão concluída!")
    console.print(Panel(
        Text(response.content),
        title="[bold magenta]REVIEW DE SEGURANÇA[/bold magenta]",
        border_style="magenta"
    ))
    return {"review": response.content}


def melhorar_codigo(state):
    console.print("\n[bold yellow]🛠️   [AGENTE 3][/bold yellow] Refatorando código...", highlight=False)
    prompt = (
        f"Melhore o código {state['language']} abaixo considerando a análise de segurança.\n"
        f"Retorne apenas o código melhorado, sem explicações fora do bloco de código.\n\n"
        f"Código:\n{state['code']}\n\nAnálise:\n{state['review']}"
    )
    response = llm.invoke([HumanMessage(content=prompt)])
    console.print("[bold green]✅ [AGENTE 3][/bold green] Refatoração concluída!")
    print_codigo("CÓDIGO FINAL MELHORADO", response.content, state["lexer"])
    return {"final_code": response.content}


graph = StateGraph(State)
graph.add_node("gerar",   gerar_codigo)
graph.add_node("revisar", revisar_codigo)
graph.add_node("melhorar", melhorar_codigo)
graph.set_entry_point("gerar")
graph.add_edge("gerar",   "revisar")
graph.add_edge("revisar", "melhorar")
app = graph.compile()

# --- Input do usuário ---
console.print("\n[bold white on blue] 🤖 PIPELINE MULTI-AGENTE [/bold white on blue]\n")

console.print("[bold]Escolha a linguagem:[/bold]")
for k, (nome, _) in LINGUAGENS.items():
    console.print(f"  [cyan]{k}[/cyan] - {nome}")

escolha = input("\nNúmero da linguagem: ").strip()
if escolha not in LINGUAGENS:
    raise SystemExit("Opção inválida. Encerrando.")

lang_nome, lang_lexer = LINGUAGENS[escolha]
console.print(f"[dim]Linguagem selecionada:[/dim] [italic]{lang_nome}[/italic]")

user_input = input("Descreva a função que deseja gerar: ").strip()
if not user_input:
    raise SystemExit("Nenhuma entrada fornecida. Encerrando.")

console.print(f"\n[dim]Tarefa recebida:[/dim] [italic]{user_input}[/italic]")
console.print("[bold]🚀 Iniciando pipeline...[/bold]\n")

for step in app.stream({
    "input":    user_input,
    "language": lang_nome,
    "lexer":    lang_lexer,
}):
    pass

console.print("\n[bold green]✨ Pipeline concluído![/bold green]\n")
