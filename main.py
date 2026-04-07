from fastapi import FastAPI
from pydantic import BaseModel
import time
import uvicorn

# Importação da instância global do firewall do seu módulo de segurança 
from security_firewall import firewall

# Inicializa o app FastAPI com título atualizado para o contexto do TCC 
app = FastAPI(title="Middleware de Governança e Segurança - Integrado")

# 1. Definição dos Modelos (Pydantic) 
# Atualizado para incluir campos de auditoria de segurança 
class UserRequest(BaseModel):
    prompt: str

class LLMResponse(BaseModel):
    status: bool               # True se for seguro, False se for bloqueado
    original_prompt: str       # O que o usuário enviou
    llm_output: str            # Comando original (se seguro) ou mensagem de erro (se bloqueado)
    security_status: str       # "Seguro" ou detalhe do padrão detectado
    firewall_latency_ms: float # Tempo gasto apenas na análise do firewall
    total_execution_time_ms: float # Tempo total da requisição

# 2. Mock do Serviço de LLM (Simulação)
def mock_llm_service(prompt: str) -> str:
    """
    Simula uma chamada a uma API externa. 
    Para fins de teste, se o prompt contiver 'apagar', simula um comando destrutivo. 
    """
    prompt_lower = prompt.lower()
    if "apagar" in prompt_lower or "remover" in prompt_lower:
        return "Claro, estou executando: rm -rf /"
    return "Aqui está o comando para listar diretórios: ls -la"

# 3. Rota Principal (O Middleware com Interceptação)
@app.post("/ask-ai", response_model=LLMResponse)
def ask_ai(request: UserRequest):
    # Inicia o cronômetro para o tempo total da operação
    start_total = time.perf_counter()
    
    # --- ETAPA 1: Chamada à Camada de IA ---
    try:
        raw_llm_output = mock_llm_service(request.prompt)
    except Exception as e:
        raw_llm_output = f"Erro na camada de IA: {str(e)}"

    # --- ETAPA 2: Validação de Segurança (Interceptação) ---
    # Iniciamos uma medição específica para o Firewall, conforme sua metodologia 
    start_firewall = time.perf_counter()
    
    # Chama a lógica de análise do seu arquivo security_firewall.py 
    is_safe, reason = firewall.analyze(raw_llm_output)
    
    end_firewall = time.perf_counter()
    firewall_latency = (end_firewall - start_firewall) * 1000 # Converte para ms

    # --- ETAPA 3: Lógica de Decisão do Middleware ---
    # Se o firewall detectar perigo, o comando original é descartado e o status vira False
    if is_safe:
        final_output = raw_llm_output
        status = True
    else:
        final_output = f"BLOQUEIO DE SEGURANÇA: {reason}"
        status = False

    # Finaliza o cronômetro total da requisição
    end_total = time.perf_counter()
    total_latency = (end_total - start_total) * 1000

    # Retorna o payload completo para alimentar os resultados do seu TCC 
    return LLMResponse(
        status=status,
        original_prompt=request.prompt,
        llm_output=final_output,
        security_status=reason,
        firewall_latency_ms=round(firewall_latency, 4),
        total_execution_time_ms=round(total_latency, 4)
    )

# 4. Bloco de Execução
if __name__ == "__main__":
    print("Servidor de Governança iniciado na porta 8089...")
    uvicorn.run(app, host="0.0.0.0", port=8089)