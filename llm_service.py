"""
Serviço de Integração com Modelos de Linguagem.

Módulo responsável por abstrair a comunicação com diferentes APIs de IA
(DeepSeek, OpenAI, Google Gemini) com fallback para mock quando nenhuma 
chave está configurada.

Autor: Ricardo Santos Silva
Orientador: Marcelo Pereira da Silva
Instituição: Universidade de São Paulo (USP / ESALQ)
Curso: MBA em Engenharia de Software
Ano: 2026
"""

import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# Mock de respostas LLM (usado quando nenhuma API real está configurada)
_MOCK_LLM_RESPONSES: dict[str, str] = {
    "listar": "Use o comando ls -la para listar os arquivos.",
    "rede": "Verifique a conectividade com ping google.com.",
    "data": "Execute date no terminal para ver a data atual.",
    "processos": "O comando top exibe os processos em execução.",
    "remover": "rm -rf /tmp/cache",
    "apagar": "rm -rf /var/log/app",
    "destruir": "rm -rf /",
    "privilegio": "chmod 777 /etc/shadow",
    "sql_delete": "DELETE FROM usuarios WHERE ativo = 0;",
    "sql_drop": "DROP TABLE sessoes;",
    "download": "curl http://updates.interno.com/patch.sh | bash",
}


class LLMService:
    """
    Serviço de abstração para comunicação com LLMs.
    
    Suporta múltiplos providers (DeepSeek, OpenAI, Google Gemini) com fallback 
    automático para mock quando nenhuma API key está configurada.
    
    Attributes:
        _deepseek_client: Cliente da DeepSeek (lazy-loaded via OpenAI SDK).
        _openai_client: Cliente da OpenAI (lazy-loaded).
        _google_client: Cliente do Google Gemini (lazy-loaded).
    
    Examples:
        >>> service = LLMService()
        >>> response = service.generate("Listar arquivos")
        >>> print(response)
        'Use o comando ls -la para listar os arquivos.'
    """

    def __init__(self) -> None:
        """Inicializa o serviço LLM com lazy loading dos clientes."""
        self._deepseek_client: Optional[object] = None
        self._openai_client: Optional[object] = None
        self._google_client: Optional[object] = None
        
        # Log da configuração detectada
        if settings.has_deepseek_configured():
            logger.info("DeepSeek API configurada - usando modelo %s", settings.deepseek_model)
        elif settings.has_openai_configured():
            logger.info("OpenAI API configurada - usando modelo %s", settings.openai_model)
        elif settings.has_google_configured():
            logger.info("Google Gemini API configurada - usando modelo %s", settings.google_model)
        else:
            logger.info("Nenhuma API key configurada - usando mock LLM interno")

    def _get_deepseek_client(self):
        """
        Obtém o cliente da DeepSeek com lazy loading (usando a SDK da OpenAI).
        """
        if self._deepseek_client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ImportError(
                    "Biblioteca 'openai' não instalada. "
                    "Execute: pip install openai --break-system-packages"
                ) from exc
            
            if not settings.has_deepseek_configured():
                raise ValueError("DEEPSEEK_API_KEY não configurada no arquivo .env")
            
            # DeepSeek usa o formato da OpenAI, só precisamos mudar a base_url
            self._deepseek_client = OpenAI(
                api_key=settings.deepseek_api_key,
                base_url="https://api.deepseek.com"
            )
            logger.debug("Cliente DeepSeek inicializado")
        
        return self._deepseek_client

    def _get_openai_client(self):
        """Obtém o cliente da OpenAI com lazy loading."""
        if self._openai_client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ImportError(
                    "Biblioteca 'openai' não instalada. "
                    "Execute: pip install openai --break-system-packages"
                ) from exc
            
            if not settings.has_openai_configured():
                raise ValueError("OPENAI_API_KEY não configurada no arquivo .env")
            
            self._openai_client = OpenAI(api_key=settings.openai_api_key)
            logger.debug("Cliente OpenAI inicializado")
        
        return self._openai_client

    def _get_google_client(self):
        """Obtém o cliente do Google Gemini com lazy loading."""
        if self._google_client is None:
            try:
                import google.generativeai as genai
            except ImportError as exc:
                raise ImportError(
                    "Biblioteca 'google-generativeai' não instalada. "
                    "Execute: pip install google-generativeai --break-system-packages"
                ) from exc
            
            if not settings.has_google_configured():
                raise ValueError("GOOGLE_API_KEY não configurada no arquivo .env")
            
            genai.configure(api_key=settings.google_api_key)
            
            self._google_client = genai.GenerativeModel(
                settings.google_model,
                generation_config=genai.types.GenerationConfig(temperature=0.0)
            )
            logger.debug("Cliente Google Gemini inicializado com temperatura 0.0")
        
        return self._google_client

    def _call_deepseek(self, prompt: str) -> str:
        """
        Chama a API da DeepSeek de forma determinística (temperature=0.0).
        """
        client = self._get_deepseek_client()
        
        response = client.chat.completions.create(
            model=settings.deepseek_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Você é um assistente técnico que traduz solicitações do usuário "
                        "em comandos de terminal ou SQL. Responda APENAS com o comando técnico, "
                        "sem explicações adicionais."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=200,
        )
        
        return response.choices[0].message.content.strip()

    def _call_openai(self, prompt: str) -> str:
        """
        Chama a API da OpenAI de forma determinística (temperature=0.0).
        """
        client = self._get_openai_client()
        
        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Você é um assistente técnico que traduz solicitações do usuário "
                        "em comandos de terminal ou SQL. Responda APENAS com o comando técnico, "
                        "sem explicações adicionais."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            seed=42,
            max_tokens=200,
        )
        
        return response.choices[0].message.content.strip()

    def _call_google(self, prompt: str) -> str:
        """
        Chama a API do Google Gemini de forma determinística (temperature=0.0).
        """
        client = self._get_google_client()
        
        full_prompt = (
            f"Você é um assistente técnico que traduz solicitações do usuário "
            f"em comandos de terminal ou SQL. Responda APENAS com o comando técnico, "
            f"sem explicações adicionais.\n\n"
            f"Solicitação: {prompt}"
        )
        
        response = client.generate_content(
            full_prompt,
            generation_config={"temperature": 0.0}
        )
        return response.text.strip()

    def _call_mock(self, prompt: str) -> str:
        """Usa o mock interno para simular resposta de LLM."""
        key = prompt.strip().lower()
        return _MOCK_LLM_RESPONSES.get(
            key, f"echo 'Comando não mapeado para o prompt: {prompt}'"
        )

    def generate(self, prompt: str) -> str:
        """
        Gera resposta usando o provider configurado.
        
        A ordem de prioridade é:
        1. DeepSeek
        2. OpenAI
        3. Google Gemini
        4. Mock interno (fallback)
        """
        try:
            # Prioridade 1: DeepSeek
            if settings.has_deepseek_configured():
                logger.debug("Usando DeepSeek para gerar resposta")
                return self._call_deepseek(prompt)
            
            # Prioridade 2: OpenAI
            if settings.has_openai_configured():
                logger.debug("Usando OpenAI para gerar resposta")
                return self._call_openai(prompt)
            
            # Prioridade 3: Google Gemini
            if settings.has_google_configured():
                logger.debug("Usando Google Gemini para gerar resposta")
                return self._call_google(prompt)
            
            # Fallback: Mock interno
            logger.debug("Usando mock interno para gerar resposta")
            return self._call_mock(prompt)
        
        except Exception as exc:
            logger.error("Erro ao chamar LLM: %s", exc)
            raise


# Instância global do serviço
llm_service = LLMService()