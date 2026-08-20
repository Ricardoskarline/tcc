# =============================================================================
# Dockerfile - Middleware de Governança TCC MBA USP/Esalq
# =============================================================================
# Multi-stage build otimizado para produção
# Baseado em Python 3.11 Debian Slim para imagem final leve e compatível (~150MB)
# =============================================================================

# ---------------------------------------------------------------------------
# STAGE 1: Builder - Instala dependências e prepara o ambiente virtual
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

# Metadados da imagem
LABEL maintainer="TCC MBA USP/Esalq"
LABEL description="Middleware de Governança e Segurança para IA Generativa"
LABEL version="2.0.0"

# Define variáveis de ambiente para otimização do Python e Pip
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Cria diretório de trabalho do builder
WORKDIR /build

# Copia apenas os requirements primeiro (otimização de cache das layers do Docker)
COPY requirements.txt .

# Instala dependências em um ambiente virtual isolado
# Como sqlparse e tenacity são pure-python, não há necessidade de compilar extensões C/C++
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt

# ---------------------------------------------------------------------------
# STAGE 2: Runtime - Imagem final mínima e segura para execução
# ---------------------------------------------------------------------------
FROM python:3.11-slim

# Define variáveis de ambiente do runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    HOST=0.0.0.0 \
    PORT=8089

# Cria usuário e grupo não-root (Princípio do Menor Privilégio - Segurança)
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 appuser && \
    mkdir -p /app && \
    chown -R appuser:appuser /app

# Copia apenas o virtual environment compilado no builder
COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv

# Define diretório de trabalho da aplicação
WORKDIR /app

# Copia código da aplicação com as devidas permissões
COPY --chown=appuser:appuser main.py .
COPY --chown=appuser:appuser config.py .
COPY --chown=appuser:appuser security_firewall.py .
COPY --chown=appuser:appuser llm_service.py .
COPY --chown=appuser:appuser tcc_validator.py .
COPY --chown=appuser:appuser .env.example .

# Cria diretório para logs com permissões corretas
RUN mkdir -p /app/logs && \
    chown -R appuser:appuser /app/logs

# Contexto de segurança: Muda para usuário não-root
USER appuser

# Expõe a porta de operação da aplicação
EXPOSE 8089

# Health check para monitoramento de vivacidade pelo Orchestrator/Docker
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8089/')" || exit 1

# Comando de inicialização do middleware
CMD ["python", "main.py"]