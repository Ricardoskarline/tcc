"""
Script de Validação do Middleware de Governança e Segurança.

Realiza experimento controlado para validação de acurácia e latência do
Firewall de Intenções, gerando métricas estatísticas e relatórios em CSV
para fundamentação de resultados e discussão no TCC.

Autor: Ricardo Santos Silva
Orientador: Marcelo Pereira da Silva
Instituição: Universidade de São Paulo (USP / ESALQ)
Curso: MBA em Engenharia de Software
Ano: 2026
"""

import argparse
import csv
import math
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Importações de Módulos do Projeto
# ---------------------------------------------------------------------------
try:
    from security_firewall import IntentionFirewall
except ImportError:
    print("❌ ERRO CRÍTICO: Módulo 'security_firewall' não encontrado.", file=sys.stderr)
    print("Certifique-se de que o arquivo security_firewall.py está no PYTHONPATH.", file=sys.stderr)
    sys.exit(1)

try:
    from llm_service import llm_service
except ImportError:
    # Em modo offline, o llm_service não é estritamente necessário para rodar o core,
    # mas logamos o aviso caso o usuário tente rodar online.
    llm_service = None


# ---------------------------------------------------------------------------
# Constantes de Configuração
# ---------------------------------------------------------------------------
SEPARATOR = "=" * 125
SUB_SEPARATOR = "-" * 125
DEFAULT_OUTPUT_CSV = "resultado_experimento_tcc.csv"
MAX_API_RETRIES = 3
INITIAL_BACKOFF_SEC = 2.0


# ---------------------------------------------------------------------------
# Funções Estatísticas e de Suporte
# ---------------------------------------------------------------------------
def calculate_std_dev(values: List[float]) -> float:
    """
    Calcula o desvio padrão amostral de uma lista de valores.

    Args:
        values: Lista de valores numéricos (ex: latências).

    Returns:
        Desvio padrão amostral. Retorna 0.0 se houver menos de 2 valores.
    """
    n = len(values)
    if n < 2:
        return 0.0

    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return math.sqrt(variance)


def evaluate_status(expected_type: str, is_safe: bool) -> Tuple[bool, str]:
    """
    Avalia a corretude da decisão do Firewall baseada no tipo esperado.

    Args:
        expected_type: 'Seguro' ou 'Ataque'.
        is_safe: Decisão retornada pelo Firewall (True para seguro, False para bloqueio).

    Returns:
        Tupla (acertou: bool, status_label: str ['Acerto', 'FP', 'FN']).
    """
    is_attack = expected_type.strip().lower() == "ataque"

    if (is_attack and not is_safe) or (not is_attack and is_safe):
        return True, "Acerto"
    elif not is_attack and not is_safe:
        return False, "FP"  # Falso Positivo: Era seguro, mas bloqueou
    else:
        return False, "FN"  # Falso Negativo: Era ataque, mas liberou


# ---------------------------------------------------------------------------
# Integração com APIs e I/O de Dados
# ---------------------------------------------------------------------------
def call_llm_with_resilience(prompt: str) -> str:
    """
    Chama o serviço LLM real aplicando resiliência (Retry com Exponential Backoff)
    para mitigação de erros de rede ou Rate Limit (HTTP 429).

    Args:
        prompt: Texto do comando enviado para a API.

    Returns:
        String gerada como resposta pelo modelo LLM.
    """
    if llm_service is None or not hasattr(llm_service, "generate"):
        raise RuntimeError("Módulo 'llm_service.generate' indisponível para o modo Online.")

    for attempt in range(1, MAX_API_RETRIES + 1):
        try:
            output = llm_service.generate(prompt)
            # Sleep reduzido para 0.1s visando acelerar os testes com a DeepSeek API
            time.sleep(0.1)
            return output
        except Exception as e:
            if attempt == MAX_API_RETRIES:
                print(f"\n⚠️ [FALHA NA API] Esgotadas {MAX_API_RETRIES} tentativas para o prompt: '{prompt[:30]}...' | Erro: {e}")
                return "ERROR: LLM_API_UNAVAILABLE"
            
            sleep_time = INITIAL_BACKOFF_SEC * (2 ** (attempt - 1))
            print(f"\n⏳ [RATE LIMIT / ERRO] Falha na tentativa {attempt}/{MAX_API_RETRIES}. Aguardando {sleep_time}s... (Motivo: {e})")
            time.sleep(sleep_time)
            
    return "ERROR: LLM_API_UNAVAILABLE"


def load_dataset(file_path: str) -> List[Dict[str, str]]:
    """
    Lê o arquivo CSV de entrada com os casos de teste para validação.
    Suporta automaticamente formatações do Excel (Latin-1, Windows-1252 e delimitadores variados).
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de dataset não encontrado no caminho: {file_path}")

    dataset = []
    required_cols = {"id", "tipo", "prompt", "pre_generated_output"}

    # Tenta ler com diferentes codificações para suportar arquivos do Excel
    for enc in ["utf-8-sig", "latin-1", "windows-1252"]:
        try:
            dataset.clear()
            with open(path, mode="r", encoding=enc) as f:
                # Descobre se o Excel salvou usando vírgula ou ponto-e-vírgula
                primeira_linha = f.readline()
                delimitador = ';' if ';' in primeira_linha else ','
                f.seek(0) # Volta para o início do arquivo
                
                reader = csv.DictReader(f, delimiter=delimitador)
                
                # Validação das colunas
                if not reader.fieldnames or not required_cols.issubset(set(reader.fieldnames)):
                    missing = required_cols - set(reader.fieldnames or [])
                    raise ValueError(f"O CSV está sem as colunas obrigatórias: {missing}. Verifique se o nome das colunas está correto.")

                for row in reader:
                    dataset.append(row)
            
            # Se leu o arquivo inteiro sem dar erro de UnicodeDecodeError, quebra o loop
            break
            
        except UnicodeDecodeError:
            continue # Se deu erro de codificação, tenta a próxima opção da lista

    print(f"📦 Dataset carregado com sucesso: {len(dataset)} registros encontrados em '{file_path}'.")
    return dataset


# ---------------------------------------------------------------------------
# Motor de Execução do Experimento
# ---------------------------------------------------------------------------
def run_experiment_case(
    firewall: IntentionFirewall,
    case: Dict[str, str],
    offline_mode: bool
) -> Dict[str, Any]:
    """
    Executa a avaliação de um único cenário no Firewall de Intenções.

    Args:
        firewall: Instância ativa do middleware IntentionFirewall.
        case: Dicionário com dados da linha do dataset.
        offline_mode: Flag indicando se deve consumir 'pre_generated_output' ou API real.

    Returns:
        Dicionário estruturado com todas as métricas e metadados da execução.
    """
    prompt = case["prompt"]
    expected_type = case["tipo"]
    case_id = case["id"]

    # 1. Obtenção da saída (LLM Real vs Mock Offline)
    if offline_mode:
        llm_output = case["pre_generated_output"]
    else:
        llm_output = call_llm_with_resilience(prompt)

    # 2. Intercepção e Medição pelo Firewall (API Fase 2)
    t0 = time.perf_counter()
    is_safe, reason, telemetry = firewall.analyze(llm_output)
    fallback_elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # 3. Cálculo de Latência Pelo Dicionário de Telemetria
    # Soma as latências das 3 camadas instrumentadas no middleware
    latency_keys = ("latency_regex_ms", "latency_ast_ms", "latency_semantic_ms")
    if all(k in telemetry for k in latency_keys):
        total_latency_ms = sum(float(telemetry.get(k, 0.0)) for k in latency_keys)
    else:
        # Fallback para o tempo medido no wrapper caso a telemetria esteja incompleta
        total_latency_ms = fallback_elapsed_ms

    layer_blocked = str(telemetry.get("layer_blocked", "Nenhuma/Permitido"))

    # 4. Avaliação Estatística
    acertou, status_label = evaluate_status(expected_type, is_safe)

    return {
        "ID": case_id,
        "Tipo Esperado": expected_type,
        "Modo": "Offline" if offline_mode else "Online",
        "Prompt": prompt,
        "Saida Gerada": llm_output,
        "Camada Interceptora": layer_blocked,
        "Latencia Total (ms)": round(total_latency_ms, 4),
        "Status": status_label,
        "Acertou": acertou,
        "Is Safe": is_safe,
        "Reason": reason
    }


# ---------------------------------------------------------------------------
# Consolidação e Exportação de Relatórios
# ---------------------------------------------------------------------------
def generate_summary_block(
    results: List[Dict[str, Any]],
    total_duration_sec: float
) -> str:
    """
    Gera o bloco de texto formatado com o resumo estatístico consolidado do TCC.

    Args:
        results: Lista com os dicionários de resultado de todos os cenários.
        total_duration_sec: Tempo de execução total do lote em segundos.

    Returns:
        String multi-linha formatada com os dados estatísticos.
    """
    n = len(results)
    if n == 0:
        return "Nenhum cenário avaliado."

    latencies = [r["Latencia Total (ms)"] for r in results]
    acertos = sum(1 for r in results if r["Acertou"])
    falsos_positivos = sum(1 for r in results if r["Status"] == "FP")
    falsos_negativos = sum(1 for r in results if r["Status"] == "FN")

    cenarios_benignos = sum(1 for r in results if r["Tipo Esperado"].strip().lower() == "seguro")
    cenarios_ataque = sum(1 for r in results if r["Tipo Esperado"].strip().lower() == "ataque")

    avg_latency = sum(latencies) / n
    std_latency = calculate_std_dev(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)
    total_latency_sum = sum(latencies)
    accuracy = (acertos / n) * 100.0

    summary_lines = [
        "RESUMO ESTATÍSTICO — RESULTADOS E DISCUSSÃO (TCC)",
        f"Total de Cenários Avaliados    : {n}",
        f"Cenários Benignos (Seguros)    : {cenarios_benignos}",
        f"Cenários de Ataque (Maliciosos): {cenarios_ataque}",
        f"Taxa de Acurácia Global        : {accuracy:.2f}%",
        f"Falsos Positivos (FP)          : {falsos_positivos}",
        f"Falsos Negativos (FN)          : {falsos_negativos}",
        f"Latência Média                 : {avg_latency:.4f} ms",
        f"Desvio Padrão da Latência      : {std_latency:.4f} ms",
        f"Latência Mínima                : {min_latency:.4f} ms",
        f"Latência Máxima                : {max_latency:.4f} ms",
        f"Tempo Total Acumulado (camadas): {total_latency_sum:.4f} ms",
        f"Tempo Total do Lote (Wall-clock): {total_duration_sec:.2f} segundos"
    ]
    return "\n".join(summary_lines)


def export_results_to_csv(
    output_path: str,
    results: List[Dict[str, Any]],
    summary_text: str
) -> None:
    """
    Grave os resultados no arquivo CSV e anexa o resumo estatístico no final.

    Args:
        output_path: Caminho do arquivo CSV a ser gerado.
        results: Lista contendo o resultado das execuções.
        summary_text: Bloco de texto estatístico para ser anexado ao rodapé.
    """
    headers = [
        "ID",
        "Tipo Esperado",
        "Modo (Online/Offline)",
        "Prompt",
        "Saida Gerada",
        "Camada Interceptora",
        "Latencia Total (ms)",
        "Status (Acerto/FP/FN)"
    ]

    path = Path(output_path)
    
    # 1. Gravação dos dados tabelados via CSV Writer
    with open(path, mode="w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(headers)
        
        for r in results:
            writer.writerow([
                r["ID"],
                r["Tipo Esperado"],
                r["Modo"],
                r["Prompt"],
                r["Saida Gerada"],
                r["Camada Interceptora"],
                f"{r['Latencia Total (ms)']:.4f}".replace(".", ","),  # Formato numérico universal PT-BR para Excel
                r["Status"]
            ])

    # 2. Anexando o resumo estatístico após pulo de duas linhas (Requisito TCC)
    with open(path, mode="a", encoding="utf-8-sig") as f:
        f.write("\n\n")  # Pula duas linhas
        f.write(summary_text)
        f.write("\n")

    print(f"📊 Relatório exportado com sucesso: '{path.resolve()}'")


# ---------------------------------------------------------------------------
# Ponto de Entrada Principal (Main & CLI)
# ---------------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """Configura e processa os argumentos de linha de comando (CLI)."""
    parser = argparse.ArgumentParser(
        description="Script de Validação e Experimentação de Middleware de Governança (TCC MBA USP)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="dataset_tcc_validation.csv",
        help="Caminho para o arquivo CSV contendo os cenários de teste."
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Executa o experimento em modo Offline (utilizando pre_generated_output do CSV)."
    )
    return parser.parse_args()


def main() -> None:
    """Função principal de orquestração do experimento de validação."""
    args = parse_arguments()

    print(SEPARATOR)
    print(" 🎓 USP / ESALQ - MBA EM ENGENHARIA DE SOFTWARE")
    print(" 🛡️  Experimento: Validação de Middleware de Governança e Segurança (IntentionFirewall)")
    print(f" ⚙️  Modo de Execução: {'📴 OFFLINE (Mock Dataset)' if args.offline else '🌐 ONLINE (APIs Reais LLM)'}")
    print(SEPARATOR + "\n")

    # 1. Carregamento da Massa de Dados
    try:
        dataset = load_dataset(args.dataset)
    except Exception as e:
        print(f"❌ Erro ao carregar dataset: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Instanciação e Aquecimento (Warm-up) do Middleware
    print("🔥 Realizando warm-up do Firewall (compilação Regex/AST JIT)...")
    firewall = IntentionFirewall()
    firewall.analyze("warmup — descartando overhead inicial de JIT/Regex das métricas do estudo")
    print("✅ Warm-up concluído. Iniciando medições do experimento...\n")

    # 3. Execução Controlada do Lote de Testes
    print(SUB_SEPARATOR)
    print(f"{'ID':<5} | {'Tipo Esperado':<14} | {'Modo':<8} | {'Status':<8} | {'Latência (ms)':<14} | {'Camada Bloqueio':<18} | {'Motivo / Padrão'}")
    print(SUB_SEPARATOR)

    results = []
    start_time_batch = time.perf_counter()

    for case in dataset:
        result = run_experiment_case(firewall, case, offline_mode=args.offline)
        results.append(result)

        # Imprime progresso no terminal em tempo real
        indicador = "✓" if result["Acertou"] else "✗"
        print(
            f"{result['ID']:<5} | "
            f"{result['Tipo Esperado']:<14} | "
            f"{result['Modo']:<8} | "
            f"{indicador} {result['Status']:<6} | "
            f"{result['Latencia Total (ms)']:>11.4f} ms | "
            f"{result['Camada Interceptora']:<18} | "
            f"{result['Reason'][:40]}"
        )

    total_wallclock_sec = time.perf_counter() - start_time_batch

    # 4. Cálculo Estatístico e Consolidação
    print(SUB_SEPARATOR)
    summary_text = generate_summary_block(results, total_wallclock_sec)
    print("\n" + SEPARATOR)
    print(summary_text)
    print(SEPARATOR + "\n")

    # 5. Exportação para Relatório CSV
    export_results_to_csv(DEFAULT_OUTPUT_CSV, results, summary_text)
    print("🎉 Experimento finalizado com sucesso!")


if __name__ == "__main__":
    main()