Middleware de Governança e Segurança para Agentes de IA
Prova de Conceito (PoC) — TCC MBA USP/Esalq em Engenharia de Software
Este repositório contém o código-fonte de um middleware de segurança desenvolvido como Prova de Conceito para o Trabalho de Conclusão de Curso (TCC) do MBA em Engenharia de Software da USP/Esalq. O sistema atua como uma camada de governança que intercepta e analisa comandos gerados por agentes de Inteligência Artificial antes de sua execução em sistemas operacionais ou bancos de dados.

🎯 Objetivo do Projeto
O objetivo central é mitigar os riscos associados à autonomia de agentes de IA, prevenindo a execução de comandos destrutivos ou inseguros através de um Firewall de Intenções baseado em análise léxica de alta performance.

🛠️ Principais Funcionalidades
Interceptação de Saída (Output Interception): Diferente de firewalls de input, este sistema valida o que a IA decidiu fazer, garantindo que comandos técnicos perigosos sejam bloqueados independentemente do prompt original.

Firewall Léxico Otimizado: Implementação de padrões Regex pré-compilados que garantem uma redução de latência em torno de 56% em comparação com compilações em tempo de execução.

Proteção contra Denial of Service (DoS): O middleware rejeita payloads que excedam 10.000 caracteres, protegendo a infraestrutura de ataques de negação de serviço por processamento.

Auditoria e Conformidade: Registro persistente de todas as ameaças bloqueadas no arquivo firewall_audit.log, permitindo rastreabilidade total de tentativas de injeção ou falhas da IA.

Validação Estatística: Script integrado para medição de latência média, desvio padrão e acurácia global da ferramenta.

📂 Estrutura do Repositório
main.py: Implementação do servidor principal utilizando FastAPI e o fluxo de interceptação.

security_firewall.py: O núcleo de segurança com a lógica de filtragem e a blacklist de padrões de risco.

tcc_validator.py: Ferramenta de testes automatizados que valida a acurácia do middleware contra uma massa de dados de ataques e comandos seguros.

setup_tcc.ps1: Script de automação para configuração do ambiente virtual (venv) e instalação de dependências no Windows.

🚀 Como Executar
Pré-requisitos
Python 3.10 ou superior.

Ambiente Windows para execução do script de setup facilitado.

Instalação
Clone o repositório:

Bash
git clone https://github.com/Ricardoskarline/tcc.git
cd tcc
Configure o ambiente e instale as dependências:

PowerShell
# Execute o script de setup (requer permissão de execução no PowerShell)
.\setup_tcc.ps1
Testes e Validação
Para gerar os resultados estatísticos apresentados no TCC:

Bash
python tcc_validator.py
Inicialização da API
Bash
python main.py
A API estará disponível em http://localhost:8089 e a documentação interativa (Swagger) em /docs.

📈 Resultados Esperados
Nos testes realizados, a solução apresentou:

Acurácia: 100% na detecção dos cenários maliciosos simulados.

Eficiência: Latência de processamento de segurança inferior a 1ms por requisição.

Autor: Ricardo Silva

Instituição: USP/Esalq — MBA em Engenharia de Software
