#!/bin/bash

# ===================================================================================
# SCRIPT DE INICIALIZAÇÃO DE SERVIÇOS APACHE AIRFLOW 
# ===================================================================================
# DESCRIÇÃO:
# Este script orquestra a inicialização segura e robusta dos componentes do Apache Airflow
# (Webserver, Scheduler, Worker, Flower) em um ambiente Docker Compose. Ele garante
# que as dependências críticas (PostgreSQL e Redis) estejam prontas e que
# variáveis de ambiente essenciais para segurança (como a chave do Vault)
# estejam definidas antes de iniciar os serviços.
#
# ARQUITETURA DE INICIALIZAÇÃO:
# - Orquestração de Dependências: Garante a ordem de inicialização de DB e Cache.
# - Validação de Variáveis de Ambiente: Previne a inicialização com configurações de segurança incompletas.
# - Setup Inicial: Realiza `airflow db upgrade` e criação de usuário admin no Webserver.
# - Modularidade: Funções dedicadas para clareza e reuso.
#
# COMPONENTES AFETADOS:
# - Apache Airflow Webserver: Interface de usuário e APIs.
# - Apache Airflow Scheduler: Orquestrador de DAGs.
# - Apache Airflow Worker (Celery): Executores de tarefas.
# - Flower: Interface de monitoramento de workers Celery.
# - PostgreSQL: Banco de dados de metadados do Airflow.
# - Redis: Backend de fila para Celery.
#
# SEGURANÇA E ROBUSTEZ:
# - Pre-verificação da chave secreta do Vault para evitar falhas em tempo de execução.
# - Espera ativa por serviços essenciais (DB e Redis) para garantir conectividade.
# - Tratamento de erro para criação de usuário admin (permissivo, evita falhas em re-execuções).
# - Logs claros durante o processo de inicialização.
# ===================================================================================

# Define o comportamento do script:
# -e: Sai imediatamente se um comando retornar um status de saída diferente de zero.
# -u: Trata variáveis não definidas como erro e sai.
# -o pipefail: O status de saída de um pipeline é o status de saída do último comando que não seja zero.
set -euo pipefail

# ---
# FUNÇÕES DE VALIDAÇÃO E ESPERA POR SERVIÇOS
# ---

# Função para verificar se a variável de ambiente da chave secreta foi definida
check_secret_key() {
    # Verifica se a variável SECURITY_VAULT_SECRET_KEY está vazia
    if [ -z "${SECURITY_VAULT_SECRET_KEY}" ]; then
        echo "ERRO: A variável de ambiente SECURITY_VAULT_SECRET_KEY não está definida."
        echo "Por favor, defina-a no arquivo .env antes de iniciar o ambiente para garantir a segurança do Vault."
        exit 1 # Sai do script com erro
    fi
    echo "Variável de ambiente SECURITY_VAULT_SECRET_KEY verificada com sucesso."
}

# Função para aguardar o banco de dados (PostgreSQL) e o cache (Redis) estarem prontos
wait_for_services() {
    echo "Aguardando o serviço PostgreSQL iniciar..."
    # Loop para verificar a conectividade da porta do PostgreSQL
    # 'nc -z' testa se a porta está aberta. 'postgres' é o nome padrão do serviço Docker.
    while ! nc -z postgres 5432; do 
      echo "PostgreSQL não está pronto, aguardando..."
      sleep 1 # Espera 1 segundo antes de tentar novamente
    done
    echo "PostgreSQL iniciado e acessível."

    echo "Aguardando o serviço Redis iniciar..."
    # Loop para verificar a conectividade da porta do Redis
    # 'redis' é o nome padrão do serviço Docker.
    while ! nc -z redis 6379; do 
      echo "Redis não está pronto, aguardando..."
      sleep 1 # Espera 1 segundo antes de tentar novamente
    done
    echo "Redis iniciado e acessível."
}

# ---
# LÓGICA PRINCIPAL DE INICIALIZAÇÃO POR TIPO DE SERVIÇO
# O script recebe o tipo de serviço como primeiro argumento ($1)
# ---

case "$1" in
  webserver)
    # Comandos específicos para o serviço Webserver do Airflow
    check_secret_key      # Garante a chave de segurança
    wait_for_services     # Aguarda dependências
    echo "Inicializando o banco de dados de metadados do Airflow (db upgrade)..."
    airflow db upgrade    # Atualiza o schema do banco de dados do Airflow
    echo "Criando usuário admin padrão do Airflow (admin/admin)..."
    # Tenta criar o usuário admin. '|| true' previne que o script falhe
    # se o usuário já existir (o que é comum em reinícios).
    airflow users create --username admin --password admin --firstname Admin --lastname User --role Admin --email admin@example.com || true
    echo "Iniciando o Airflow Webserver..."
    exec airflow webserver # Inicia o webserver (exec substitui o processo atual)
    ;;
  scheduler)
    # Comandos específicos para o serviço Scheduler do Airflow
    check_secret_key      # Garante a chave de segurança
    wait_for_services     # Aguarda dependências
    echo "Aguardando um pequeno atraso (10s) antes de iniciar o Scheduler para garantir que o Webserver configure o DB..."
    sleep 10              # Pequeno atraso para garantir que o db upgrade do webserver terminou
    echo "Iniciando o Airflow Scheduler..."
    exec airflow scheduler # Inicia o scheduler
    ;;
  worker)
    # Comandos específicos para o serviço Worker do Airflow (Celery)
    check_secret_key      # Garante a chave de segurança
    wait_for_services     # Aguarda dependências
    echo "Aguardando um pequeno atraso (10s) antes de iniciar o Worker..."
    sleep 10              # Pequeno atraso para garantir que o scheduler/webserver estejam operacionais
    echo "Iniciando o Airflow Celery Worker..."
    exec airflow celery worker # Inicia o worker Celery
    ;;
  flower)
    # Comandos específicos para o serviço Flower (monitoramento Celery)
    check_secret_key      # Garante a chave de segurança
    wait_for_services     # Aguarda dependências
    echo "Aguardando um pequeno atraso (10s) antes de iniciar o Flower..."
    sleep 10              # Pequeno atraso
    echo "Iniciando o Airflow Celery Flower..."
    exec airflow celery flower # Inicia o Flower
    ;;
  *)
    # Caso nenhum argumento corresponda, executa o comando passado diretamente
    echo "Comando desconhecido ou argumentos adicionais. Executando: '$@'"
    exec "$@"
    ;;
esac
