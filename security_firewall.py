import re
from typing import Tuple

class IntentionFirewall:
    """
    Módulo de Segurança: Analisa saídas de LLMs e bloqueia comandos destrutivos.
    Atua como um filtro léxico de alta performance para governança de IA.
    """
    def __init__(self):
        # Lista expandida de padrões perigosos (Blacklist)
        # Inclui comandos de sistema (Linux/Windows) e SQL
        self.blocked_patterns = [
            # --- Comandos de Sistema Operacional ---
            r"\brm\s+-rf\b",             # Deleção recursiva forçada
            r"\bchmod\s+777\b",          # Permissão total insegura
            r"\bmkfs\b",                 # Formatação de sistemas de arquivos
            r">\s*/dev/(sd[a-z]|hd[a-z])", # Sobrescrita direta de discos
            r"\bshutdown\s",             # Desligamento do servidor
            r"\breboot\b",               # Reinicialização forçada
            r"\bkill\s+-9\b",            # Encerramento forçado de processos críticos
            
            # --- Comandos de Rede e Exfiltração ---
            r"\bwget\s+http",            # Download de scripts externos potencialmente maliciosos
            r"\bcurl\s+.*\|\s*bash\b",    # Execução direta de scripts da web (Pipe to Bash)
            
            # --- Comandos de Banco de Dados (SQL) ---
            r"\bDROP\s+TABLE\b",         # Exclusão de tabelas
            r"\bDELETE\s+FROM\b",        # Deleção massiva de registros
            r"\bTRUNCATE\s+TABLE\b",      # Esvaziamento rápido de tabelas
            r"\bALTER\s+USER\b",         # Modificação de privilégios de usuário
            r"\bGRANT\s+ALL\b"           # Concessão excessiva de permissões
        ]

    def analyze(self, llm_output: str) -> Tuple[bool, str]:
        """
        Analisa a string gerada pelo LLM em busca de padrões proibidos.
        Retorna uma tupla (is_safe, status_message).
        """
        if not llm_output or not llm_output.strip():
            return False, "Bloqueado: A saída do LLM está vazia ou é inválida."

        # Itera sobre os padrões da blacklist usando Regex
        for pattern in self.blocked_patterns:
            # O uso de re.IGNORECASE evita que variações de caixa (Ex: Drop Table) burlem o filtro [cite: 163, 165]
            if re.search(pattern, llm_output, re.IGNORECASE):
                # Retorna o status para alimentar a auditoria do TCC [cite: 52]
                return False, f"Padrão de risco detectado: {pattern}"

        # Se nenhum padrão for encontrado, a saída é considerada segura para execução
        return True, "Seguro"

# Instância global para integração com o servidor FastAPI principal
firewall = IntentionFirewall()