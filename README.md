# Middleware de Governança e Segurança para Agentes de IA

**Trabalho de Conclusão de Curso (TCC) — MBA USP/Esalq em Engenharia de Software**

Este repositório contém o código-fonte e os logs de auditoria de um *middleware* de segurança dinâmico (Firewall de Intenções). O sistema atua como uma camada de governança que intercepta, analisa e classifica o nível de risco de comandos gerados por agentes autônomos de Inteligência Artificial antes de sua execução em sistemas operacionais ou bancos de dados relacionais.

🎯 **Objetivo do Projeto**
Mitigar os riscos críticos associados à autonomia de agentes de IA (como injeção de *prompt* indireta, sequestro de intenções e agência excessiva). O sistema assegura que infraestruturas corporativas operem sob o perímetro de *Zero Trust* (Confiança Zero), utilizando uma abordagem híbrida de defesa em profundidade.

🛠️ **Principais Funcionalidades**

*   **Esteira de Tripla Validação:** Inspeção progressiva dividida em três motores:
    *   **Motor Léxico:** Expressões regulares (Regex) de altíssima velocidade aplicadas sob o princípio *fail-fast* para barrar comandos destrutivos explícitos (ex: `DROP TABLE`, `rm -rf`).
    *   **Motor Sintático:** Análise via Árvore de Sintaxe Abstrata (AST) utilizando `sqlparse` para desconstruir e expor comandos maliciosos aninhados ou ofuscados.
    *   **Motor Semântico (*LLM-as-a-judge*):** Integração com a API DeepSeek. Um modelo de linguagem secundário atua exclusivamente como juiz de cibersegurança para detectar anomalias comportamentais complexas e evasões semânticas.
*   **Engenharia de Resiliência:** Implementação da biblioteca `Tenacity` com políticas de repetição automática (*retries*) e recuo exponencial (*exponential backoff*) para garantir estabilidade contra falhas de rede ou estrangulamento de cotas da API (HTTP 429/404).
*   **Proteção contra Denial of Service (DoS):** Bloqueio imediato (HTTP 422) de *payloads* que excedam o limite estrito de 10.000 caracteres, protegendo a memória do servidor.
*   **Auditoria e Telemetria:** Geração contínua de logs e status de bloqueio (HTTP 403) para rastreabilidade de incidentes.

📂 **Estrutura do Projeto**
A arquitetura de código foi fundamentada no padrão estrutural **Proxy de Proteção**.

*   `main.py` / `FastAPIController`: Exposição da API utilizando o framework assíncrono FastAPI.
*   `security_firewall.py`: O núcleo orquestrador contendo os métodos progressivos de higienização (léxica, sintática e chamadas semânticas).
*   `llm_service.py`: Abstração de comunicação com a IA externa e gestão de resiliência.
*   `tcc_validator.py`: Motor de testes automatizados responsável por disparar a massa de dados experimental.
*   `frontend.py`: Interface gráfica interativa (Chat) desenvolvida em Streamlit para demonstração da PoC.
*   `Dockerfile` e `docker-compose.yml`: Scripts de conteinerização garantindo isolamento da aplicação sob privilégio mínimo de SO (usuário `appuser`).

🚀 **Como Executar**

**Pré-requisitos:**
*   [Docker](https://www.docker.com/) instalado.
*   Chave de API ativa (DeepSeek, OpenAI ou Google Gemini).
*   Python 3.10+ (para rodar a interface visual localmente).

### 1. Inicializando a API (Backend via Docker)

1. Clone o repositório:
   ```bash
   git clone https://github.com/Ricardoskarline/tcc.git
   cd tcc
   ```

2. Configure sua chave de API editando o arquivo `.env` ou passando como variável de ambiente.

3. Construa a imagem isolada do sistema:
   ```bash
   docker build -t intention-firewall .
   ```

4. Suba o contêiner expondo a porta correta:
   ```bash
   docker run -p 8089:8089 intention-firewall
   ```

5. A API estará disponível e aguardando conexões na porta `8089`. Acesse `http://localhost:8089/docs` para interagir com o *Swagger* gerado automaticamente.

### 2. Inicializando a Interface Gráfica (Frontend)

O projeto inclui um protótipo de chat interativo desenvolvido em Streamlit para demonstrar a atuação do *middleware* em tempo real.

1. Abra um **novo terminal** na pasta do projeto.

2. Instale as dependências da interface (caso não estejam no seu ambiente local):
   ```bash
   pip install streamlit requests
   ```

3. Inicie o servidor do frontend:
   ```bash
   streamlit run frontend.py
   ```

4. O seu navegador abrirá automaticamente em `http://localhost:8501` exibindo a interface do "Chat Seguro". Toda instrução enviada por ali passará primeiro pelo nosso Firewall de Intenções!

📈 **Resultados Experimentais**
O sistema foi submetido a um teste de estresse transacional rigoroso, processando **3.000 cenários** emulados (1.500 operações benignas cotidianas e 1.500 vetores de ataque ofuscados).

Os resultados estatísticos finais comprovaram a viabilidade operacional do *middleware*:

*   **Acurácia Global:** 85,50% na interceptação de comandos.
*   **Falsos Positivos (FP):** 0 (zero bloqueios indevidos em tráfego benigno, garantindo a continuidade de negócios).
*   **Latência Média:** ~815 milissegundos por transação. Um *trade-off* FinOps altamente viável, visto que o bloqueio léxico antecipado economiza tokens e o custo temporal é irrisório se comparado ao Tempo Médio de Recuperação (MTTR) de um desastre cibernético.

---
**Autores:** Ricardo Santos Silva e Marcelo Pereira da Silva  
**Instituição:** USP/Esalq — MBA em Engenharia de Software
