"""
=============================================================================
Projeto: Middleware de Governança e Segurança para Agentes de IA

Autor: Ricardo Santos Silva
Orientador: Marcelo Pereira da Silva
Instituição: Universidade de São Paulo (USP / ESALQ)
Curso: MBA em Engenharia de Software
Ano: 2026
=============================================================================
"""

import streamlit as st
import requests

# Configuração da página
st.set_page_config(page_title="Governança de IA", page_icon="🛡️")
st.title("🛡️ Chat Seguro - Middleware de Governança")
st.caption("Protótipo de validação TCC MBA USP/Esalq")

# URL da sua API FastAPI
API_URL = "http://localhost:8089/ask-ai"

# Inicializa o histórico do chat na sessão
if "messages" not in st.session_state:
    st.session_state.messages = []

# Exibe o histórico de mensagens na tela
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Campo de entrada de texto do usuário
if prompt := st.chat_input("Digite um comando (ex: listar arquivos)"):
    
    # 1. Adiciona a mensagem do usuário no chat
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 2. Faz a requisição para a sua API FastAPI
    with st.chat_message("assistant"):
        with st.spinner("Analisando intenção no Firewall..."):
            try:
                response = requests.post(API_URL, json={"prompt": prompt})
                dados = response.json()
                
                # Se a API retornar 200 (Seguro)
                if response.status_code == 200:
                    comando = dados['llm_output']
                    resposta_ia = f"✅ **Aprovado:** `{comando}`\n\n*(Latência: {dados['firewall_latency_ms']}ms)*"
                    st.success(resposta_ia)
                    
                    # ---- NOVO: IMPLEMENTAÇÃO PÓS-FIREWALL (Simulação de Execução) ----
                    with st.expander("⚙️ Ver resultado da execução do comando", expanded=True):
                        st.info(f"Executando no ambiente simulado: `{comando}`")
                        
                        comando_upper = comando.upper()
                        
                        # Simulação de listar arquivos
                        if "LS" in comando_upper or "DIR" in comando_upper:
                            st.code("documento_tcc_mba.pdf\nrelatorio_riscos.csv\nmain.py\nsecurity_firewall.py", language="bash")
                        
                        # Simulação de verificação de rede (ping)
                        elif "PING" in comando_upper or "REDE" in prompt.upper():
                            st.code("PING google.com (142.250.190.46): 56 data bytes\n64 bytes from 142.250.190.46: icmp_seq=0 ttl=116 time=14.2 ms\n64 bytes from 142.250.190.46: icmp_seq=1 ttl=116 time=15.1 ms", language="bash")
                        
                        # Simulação de data
                        elif "DATE" in comando_upper or "DATA" in prompt.upper():
                            st.code("Sun Aug 16 12:34:47 -03 2026", language="bash")
                            
                        # Simulação de banco de dados (SQL)
                        elif "SELECT" in comando_upper:
                            # Tabela fictícia sendo desenhada nativamente
                            st.dataframe([
                                {"id": 1, "nome": "Ricardo", "cargo": "Engenheiro de Software", "acesso": "Admin"},
                                {"id": 2, "nome": "Renata", "cargo": "Analista", "acesso": "Padrão"}
                            ])
                        
                        # Fallback para outros comandos seguros
                        else:
                            st.code("Processo executado com sucesso.\n(0 bytes retornados)", language="bash")
                    # ------------------------------------------------------------------
                
                # Se a API retornar 403 (Bloqueado)
                elif response.status_code == 403:
                    resposta_ia = f"🚨 **BLOQUEADO:** {dados['security_status']}\n\n*(Latência: {dados['firewall_latency_ms']}ms)*"
                    st.error(resposta_ia)
                
                else:
                    resposta_ia = f"Erro inesperado: {dados.get('message', 'Erro desconhecido')}"
                    st.warning(resposta_ia)
                    
            except Exception as e:
                resposta_ia = f"Falha ao conectar com a API: {e}"
                st.error(resposta_ia)

        # Salva a resposta da IA no histórico (para manter no balão de chat)
        st.session_state.messages.append({"role": "assistant", "content": resposta_ia})