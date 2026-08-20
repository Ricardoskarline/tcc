"""
Módulo de Configuração do Middleware de Governança.

Centraliza o carregamento e validação de variáveis de ambiente usando
pydantic-settings para garantir type safety e valores default seguros.

Autor: Ricardo Santos Silva
Orientador: Marcelo Pereira da Silva
Instituição: Universidade de São Paulo (USP / ESALQ)
Curso: MBA em Engenharia de Software
Ano: 2026
"""

import os
from typing import Literal, Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Carrega variáveis do arquivo .env se existir
load_dotenv()


class Settings(BaseSettings):
    """
    Configurações da aplicação carregadas de variáveis de ambiente.
    
    Attributes:
        host: Endereço IP do servidor FastAPI.
        port: Porta TCP do servidor FastAPI.
        max_input_length: Limite máximo de caracteres aceitos pelo firewall.
        enable_ast_firewall: Ativa ou desativa o firewall de Árvore Sintática Abstrata (AST).
        enable_semantic_firewall: Ativa ou desativa o firewall de análise semântica via LLM.
        semantic_model: Modelo de IA dedicado para validação semântica rápida no firewall.
        deepseek_api_key: Chave de API da DeepSeek (opcional).
        deepseek_model: Modelo da DeepSeek a ser usado.
        openai_api_key: Chave de API da OpenAI (opcional).
        openai_model: Modelo da OpenAI a ser usado.
        google_api_key: Chave de API do Google Gemini (opcional).
        google_model: Modelo do Google Gemini a ser usado.
        api_max_retries: Número máximo de tentativas (retries) em chamadas de API externas.
        api_retry_delay_seconds: Tempo de espera inicial (em segundos) entre tentativas de retry.
        log_level: Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        firewall_audit_log: Caminho do arquivo de log de auditoria.
    """
    
    # Configuração do servidor
    host: str = "0.0.0.0"
    port: int = 8089
    
    # Configuração do firewall e motores de segurança
    max_input_length: int = 10_000
    enable_ast_firewall: bool = True
    enable_semantic_firewall: bool = True
    semantic_model: str = "deepseek-chat"
    
    # Configuração de APIs de IA (opcionais)
    deepseek_api_key: Optional[str] = None
    deepseek_model: str = "deepseek-chat"
    
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4-turbo-preview"
    
    google_api_key: Optional[str] = None
    google_model: str = "gemini-1.5-pro"
    
    # Configuração de resiliência e retries de APIs
    api_max_retries: int = 3
    api_retry_delay_seconds: float = 1.0
    
    # Configuração de logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    firewall_audit_log: str = "firewall_audit.log"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
    
    def has_deepseek_configured(self) -> bool:
        """
        Verifica se a chave de API da DeepSeek está configurada.
        
        Returns:
            True se a chave estiver presente e não vazia.
        """
        return bool(self.deepseek_api_key and self.deepseek_api_key.strip())

    def has_openai_configured(self) -> bool:
        """
        Verifica se a chave de API da OpenAI está configurada.
        
        Returns:
            True se a chave estiver presente e não vazia.
        """
        return bool(self.openai_api_key and self.openai_api_key.strip())
    
    def has_google_configured(self) -> bool:
        """
        Verifica se a chave de API do Google está configurada.
        
        Returns:
            True se a chave estiver presente e não vazia.
        """
        return bool(self.google_api_key and self.google_api_key.strip())
    
    def has_real_llm_configured(self) -> bool:
        """
        Verifica se qualquer API de IA real está configurada.
        
        Returns:
            True se DeepSeek, OpenAI ou Google estiverem configurados.
        """
        return self.has_deepseek_configured() or self.has_openai_configured() or self.has_google_configured()


# Instância global das configurações (singleton pattern)
settings = Settings()