# ==============================================================================
# Script de Instalação e Configuração de Ambiente - TCC (Firewall de Intenções)
# ==============================================================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Iniciando a configuracao do ambiente TCC" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verifica se o Python está instalado no sistema
Write-Host "[1/3] Verificando instalacao do Python..." -ForegroundColor Yellow
if (!(Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "ERRO: Python nao encontrado!" -ForegroundColor Red
    Write-Host "Por favor, instale o Python (https://www.python.org/) e marque a opcao 'Add Python to PATH'." -ForegroundColor Red
    exit
}
Write-Host "OK: Python detectado." -ForegroundColor Green

# 2. Cria o ambiente virtual (venv) isolado
Write-Host "`n[2/3] Criando ambiente virtual isolado (venv)..." -ForegroundColor Yellow
if (!(Test-Path -Path "venv")) {
    python -m venv venv
    Write-Host "OK: Ambiente virtual criado na pasta 'venv'." -ForegroundColor Green
} else {
    Write-Host "Aviso: A pasta 'venv' ja existe. Pulando criacao." -ForegroundColor DarkGray
}

# 3. Instala as dependências necessárias
Write-Host "`n[3/3] Instalando bibliotecas (FastAPI, Uvicorn, Pydantic)..." -ForegroundColor Yellow
# Usamos o python de dentro do venv para garantir que instale no lugar certo
& .\venv\Scripts\python.exe -m pip install --upgrade pip --quiet
& .\venv\Scripts\python.exe -m pip install fastapi uvicorn pydantic --quiet
Write-Host "OK: Bibliotecas instaladas com sucesso." -ForegroundColor Green

# Mensagem de Conclusão
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Ambiente configurado com sucesso!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Para rodar o seu servidor FastAPI, primeiro ative o ambiente com o comando:"
Write-Host ".\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "E depois inicie o servidor com:"
Write-Host "python main.py" -ForegroundColor White