"""
Middleware de Governança e Segurança para IA Generativa.

API FastAPI que intercepta comandos gerados por modelos de linguagem e valida
sua segurança antes da execução, prevenindo ações destrutivas através de um
Firewall de Intenções baseado em análise léxica.

Desenvolvido como Prova de Conceito para o TCC do MBA USP/Esalq em 
Engenharia de Software.

Author: TCC MBA USP/Esalq - Engenharia de Software
Version: 2.0.0

Autor: Ricardo Santos Silva
Orientador: Marcelo Pereira da Silva
Instituição: Universidade de São Paulo (USP / ESALQ)
Curso: MBA em Engenharia de Software
Ano: 2026
=============================================================================
"""
import logging
import time
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from config import settings
from llm_service import llm_service
from security_firewall import firewall

# Configuração de logging da aplicação
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Inicialização do app FastAPI
app = FastAPI(
    title="Middleware de Governança e Segurança",
    description=(
        "PoC de middleware para classificação de risco e interceptação de comandos "
        "gerados por agentes autônomos de IA. Desenvolvido como Prova de Conceito "
        "para o TCC do MBA USP/Esalq em Engenharia de Software."
    ),
    version="2.0.0",
)


# ---------------------------------------------------------------------------
# Modelos Pydantic
# ---------------------------------------------------------------------------


class UserRequest(BaseModel):
    """
    Modelo de requisição do usuário.
    
    Attributes:
        prompt: Solicitação em linguagem natural a ser traduzida em comando técnico.
    
    Examples:
        >>> request = UserRequest(prompt="listar arquivos")
        >>> print(request.prompt)
        'listar arquivos'
    """
    
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Prompt do usuário em linguagem natural",
        examples=["listar arquivos", "verificar conectividade de rede"],
    )


class LLMResponse(BaseModel):
    """
    Modelo de resposta do middleware.
    
    Attributes:
        status: True se comando seguro, False se bloqueado.
        original_prompt: Prompt original enviado pelo usuário.
        llm_output: Saída do LLM ou mensagem de bloqueio.
        security_status: Descrição do status de segurança.
        firewall_latency_ms: Tempo de análise do firewall em milissegundos.
        total_execution_time_ms: Tempo total da requisição em milissegundos.
    
    Examples:
        >>> response = LLMResponse(
        ...     status=True,
        ...     original_prompt="listar",
        ...     llm_output="ls -la",
        ...     security_status="Seguro",
        ...     firewall_latency_ms=0.5,
        ...     total_execution_time_ms=25.3
        ... )
    """
    
    status: bool = Field(..., description="True = seguro, False = bloqueado")
    original_prompt: str = Field(..., description="Prompt enviado pelo usuário")
    llm_output: str = Field(..., description="Saída do LLM ou mensagem de bloqueio")
    security_status: str = Field(..., description="Status de segurança detalhado")
    firewall_latency_ms: float = Field(..., description="Latência do firewall em ms")
    total_execution_time_ms: float = Field(..., description="Tempo total em ms")


class ErrorResponse(BaseModel):
    """
    Modelo de resposta de erro padronizado.
    
    Attributes:
        error: Tipo do erro.
        message: Mensagem descritiva do erro.
        detail: Detalhes adicionais opcionais.
    
    Examples:
        >>> error = ErrorResponse(
        ...     error="ValidationError",
        ...     message="Prompt inválido",
        ...     detail={"field": "prompt", "issue": "too short"}
        ... )
    """
    
    error: str = Field(..., description="Tipo do erro")
    message: str = Field(..., description="Mensagem de erro")
    detail: Any = Field(None, description="Detalhes adicionais opcionais")


# ---------------------------------------------------------------------------
# Tratadores de Exceções Globais
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    """
    Tratador global para exceções HTTP do FastAPI.
    
    Args:
        request: Objeto Request do FastAPI.
        exc: Exceção HTTP capturada.
    
    Returns:
        JSONResponse com estrutura padronizada de erro.
    """
    logger.warning(
        "HTTPException capturada: %s %s - Status: %d - Detalhe: %s",
        request.method,
        request.url.path,
        exc.status_code,
        exc.detail,
    )
    
    error_response = ErrorResponse(
        error="HTTPException",
        message=exc.detail if isinstance(exc.detail, str) else "Erro HTTP",
        detail=exc.detail if not isinstance(exc.detail, str) else None,
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Tratador global para erros de validação Pydantic.
    
    Args:
        request: Objeto Request do FastAPI.
        exc: Exceção de validação capturada.
    
    Returns:
        JSONResponse com detalhes dos erros de validação.
    """
    logger.warning(
        "Erro de validação: %s %s - Erros: %s",
        request.method,
        request.url.path,
        exc.errors(),
    )
    
    error_response = ErrorResponse(
        error="ValidationError",
        message="Dados de entrada inválidos",
        detail=exc.errors(),
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Tratador global para exceções não capturadas.
    
    Args:
        request: Objeto Request do FastAPI.
        exc: Exceção genérica capturada.
    
    Returns:
        JSONResponse com erro interno do servidor.
    """
    logger.error(
        "Erro interno não tratado: %s %s - Erro: %s",
        request.method,
        request.url.path,
        str(exc),
        exc_info=True,
    )
    
    error_response = ErrorResponse(
        error="InternalServerError",
        message="Erro interno do servidor",
        detail=str(exc) if settings.log_level == "DEBUG" else None,
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/", tags=["Health"])
async def root() -> Dict[str, str]:
    """
    Endpoint raiz para health check.
    
    Returns:
        Dicionário com status da API e versão.
    
    Examples:
        >>> # GET /
        >>> {"status": "online", "version": "2.0.0"}
    """
    return {
        "status": "online",
        "version": "2.0.0",
        "llm_provider": (
            "OpenAI" if settings.has_openai_configured()
            else "Google" if settings.has_google_configured()
            else "Mock"
        ),
    }


@app.post(
    "/ask-ai",
    response_model=LLMResponse,
    responses={
        200: {
            "description": "Comando seguro — pode ser executado.",
            "model": LLMResponse,
        },
        403: {
            "description": "Comando bloqueado pelo firewall de intenções.",
            "model": LLMResponse,
        },
        422: {
            "description": "Requisição inválida.",
            "model": ErrorResponse,
        },
        500: {
            "description": "Erro interno na camada de IA.",
            "model": ErrorResponse,
        },
    },
    tags=["AI Middleware"],
)
async def ask_ai(request: UserRequest) -> JSONResponse:
    """
    Endpoint principal do middleware de governança.
    
    Fluxo de processamento:
    1. Recebe o prompt do usuário
    2. Encaminha ao serviço de LLM (OpenAI, Google ou Mock)
    3. Intercepta a saída e submete ao Firewall de Intenções
    4. Retorna HTTP 200 se seguro ou HTTP 403 se bloqueado
    """
    start_total = time.perf_counter()
    
    logger.info("Requisição recebida: '%s'", request.prompt)
    
    # --- ETAPA 1: Chamada à Camada de IA ---
    try:
        raw_llm_output = llm_service.generate(request.prompt)
        logger.debug("LLM Output: '%s'", raw_llm_output)
    except Exception as exc:
        logger.error("Erro na camada de IA: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro na camada de IA: {str(exc)}",
        ) from exc
    
    # --- ETAPA 2: Validação de Segurança (Interceptação pelo Firewall) ---
    start_firewall = time.perf_counter()
    
    # CORREÇÃO AQUI: Agora estamos desempacotando as 3 variáveis que o analyze() devolve
    is_safe, reason, telemetry = firewall.analyze(raw_llm_output)
    
    firewall_latency = (time.perf_counter() - start_firewall) * 1000
    
    # --- ETAPA 3: Decisão do Middleware ---
    total_latency = (time.perf_counter() - start_total) * 1000
    
    if is_safe:
        logger.info("Comando aprovado: '%s'", raw_llm_output)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=LLMResponse(
                status=True,
                original_prompt=request.prompt,
                llm_output=raw_llm_output,
                security_status=reason,
                firewall_latency_ms=round(firewall_latency, 4),
                total_execution_time_ms=round(total_latency, 4),
            ).model_dump(),
        )
    
    # Bloqueio: retorna HTTP 403 com o corpo estruturado
    logger.warning("Comando bloqueado: '%s' - Razão: %s", raw_llm_output, reason)
    blocked_payload = LLMResponse(
        status=False,
        original_prompt=request.prompt,
        llm_output=f"BLOQUEIO DE SEGURANÇA: {reason}",
        security_status=reason,
        firewall_latency_ms=round(firewall_latency, 4),
        total_execution_time_ms=round(total_latency, 4),
    )
    
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content=blocked_payload.model_dump(),
    )


# ---------------------------------------------------------------------------
# Bloco de Execução
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    logger.info("Iniciando servidor de governança...")
    logger.info("Configuração: Host=%s, Port=%d", settings.host, settings.port)
    logger.info("LLM Provider: %s", (
        "OpenAI" if settings.has_openai_configured()
        else "Google" if settings.has_google_configured()
        else "Mock"
    ))
    
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )