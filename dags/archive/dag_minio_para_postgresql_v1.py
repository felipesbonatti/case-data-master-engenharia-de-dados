"""
====================================================================================
DAG ETL: DATA LAKE (MINIO) PARA DATA MART (POSTGRESQL) 
====================================================================================

DESCRIÇÃO:
    Pipeline ETL (Extração, Transformação, Carga) robusto e seguro que orquestra
    a movimentação de dados da camada Bronze do Data Lake (MinIO) para o Data Mart
    analítico (PostgreSQL). Este processo é fundamental para disponibilizar dados
    prontos para consumo por ferramentas de BI e análise.

ARQUITETURA DO FLUXO:
    DATA LAKE (MinIO - Bronze) --> CAMADA ETL (Airflow Worker) --> DATA MART (PostgreSQL)
    - Dados Brutos             - Segurança Vault                 - Modelo Estrelar
    - CSV / Parquet            - Transformação                   - Dados Agregados

COMPONENTES TÉCNICOS:
    - MinIO: Armazenamento de objetos compatível com S3 para o Data Lake.
    - PostgreSQL: Banco de dados relacional para o Data Mart.
    - Apache Airflow: Orquestrador do pipeline ETL.
    - Vault de Segurança: Gerenciamento centralizado e seguro de credenciais.
    - Pandas: Para manipulação e transformação de dados em memória.
    - SQLAlchemy/Psycopg2: Conectividade robusta com o banco de dados.

SEGURANÇA IMPLEMENTADA:
    - Recuperação de credenciais sensíveis (MinIO, PostgreSQL) via Vault criptografado.
    - Variáveis de ambiente para chaves de decriptação, sem exposição no código.
    - Logs detalhados sem exposição de segredos.

QUALIDADE E GOVERNANÇA:
    - Truncate e Load (T&L): Garante que a tabela de destino seja limpa antes de cada carga completa,
      assegurando consistência e idempotência.
    - Tratamento de exceções: Captura e loga erros em cada etapa (extração, carga).
    - Linhagem de dados: O fluxo claro do ETL é documentado e rastreável via logs da DAG.
====================================================================================
"""

from __future__ import annotations

import os
import io
import pendulum
import pandas as pd
from sqlalchemy import create_engine, text
from minio import Minio # Cliente Minio
import logging # Importar o módulo logging
import json # Importar para lidar com credenciais JSON do Vault
from typing import Dict, Any
from pathlib import Path # Para manipulação de caminhos robusta

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator

# Configuração do logger para a DAG (assume configuração externa ou básica)
logger = logging.getLogger(__name__)

# ---
# Configurações Globais
# ---

class ETLConfig:
    """Centraliza todas as configurações para o pipeline ETL."""

    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow')) # Usando Path

    # Caminhos para componentes de segurança
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json'
    AUDIT_LOG_FILE: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'audit_etl.csv'
    SYSTEM_LOG_FILE: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'system_etl.log'

    VAULT_SECRET_KEY_ENV: str = 'SECURITY_VAULT_SECRET_KEY' # Nome da variável de ambiente para a chave do Vault

    # Chaves de credenciais no Vault
    MINIO_CREDS_KEY: str = "minio_local_credentials"
    POSTGRES_CREDS_KEY: str = "postgresql_credentials" # Correção do nome da chave para consistência

    # Configurações do MinIO (Data Lake - Bronze Layer)
    MINIO_BUCKET_NAME: str = "bronze-layer"
    MINIO_FILE_PATH: str = "olist/dados_consolidados.csv" # Caminho do objeto dentro do bucket

    # Configurações do PostgreSQL (Data Mart)
    POSTGRES_TABLE_NAME: str = "dados_olist"

# ---
# Função Principal de ETL
# ---

def _minio_para_postgresql_seguro() -> None:
    """
    Função principal que orquestra as etapas de Extração (MinIO), Transformação (Pandas)
    e Carga (PostgreSQL) para o pipeline ETL. Garante a segurança das credenciais
    através do uso de um Vault.

    Fluxo Detalhado:
        1. Recupera as credenciais do MinIO e PostgreSQL de forma segura via Vault.
        2. Extrai o arquivo CSV consolidado da camada Bronze do MinIO.
        3. Carrega os dados extraídos em um DataFrame Pandas.
        4. Trunca a tabela de destino no PostgreSQL para garantir uma carga limpa e idempotente.
        5. Insere os dados do DataFrame no PostgreSQL.

    Raises:
        ValueError: Se variáveis de ambiente ou credenciais essenciais não forem encontradas.
        ImportError: Se os módulos de segurança customizados não puderem ser importados.
        Exception: Para quaisquer outros erros que ocorram durante a extração ou carga,
                   garantindo que a tarefa do Airflow falhe.
    """
    logger.info("Iniciando o pipeline ETL: MinIO para PostgreSQL (Seguro).")

    # Importações locais para garantir que os módulos de segurança são carregados no contexto da tarefa
    try:
        from plugins.security_system.vault_manager_helper import VaultManager # Usando VaultManager
        from plugins.security_system.audit import AuditLogger # Importando para uso com VaultManager
    except ImportError as e:
        logger.critical(f"ERRO CRÍTICO: Módulo de segurança não encontrado. Detalhes: {e}")
        raise ImportError(f"Dependência de segurança ausente: {e}")

    # 1. Recuperar a chave secreta do ambiente para o Vault
    secret_key = os.getenv(ETLConfig.VAULT_SECRET_KEY_ENV)
    if not secret_key:
        logger.critical(f"ERRO CRÍTICO: Variável de ambiente '{ETLConfig.VAULT_SECRET_KEY_ENV}' não definida.")
        raise ValueError(f"SECURITY_VAULT_SECRET_KEY não definida. Acesso ao Vault negado.")

    logger.info("Recuperando credenciais de serviço via Vault...")
    
    # Garante que os diretórios de log e vault existam
    ETLConfig.AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    ETLConfig.SYSTEM_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    ETLConfig.VAULT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Inicializa AuditLogger
    audit_logger_instance = AuditLogger(
        audit_file_path=str(ETLConfig.AUDIT_LOG_FILE),
        system_log_file_path=str(ETLConfig.SYSTEM_LOG_FILE)
    )

    # Inicializa VaultManager para gerenciar os segredos
    vault_manager = VaultManager(
        vault_path=str(ETLConfig.VAULT_JSON_PATH),
        secret_key=secret_key,
        logger=audit_logger_instance # Passa o logger para o VaultManager
    )

    # Obtém credenciais criptografadas do Vault e as descriptografa
    minio_creds_encrypted = vault_manager.get_secret(ETLConfig.MINIO_CREDS_KEY)
    pg_creds_encrypted = vault_manager.get_secret(ETLConfig.POSTGRES_CREDS_KEY)

    if not minio_creds_encrypted or not pg_creds_encrypted:
        logger.critical("Credenciais essenciais para MinIO ou PostgreSQL não encontradas no Vault.")
        raise ValueError("Credenciais para MinIO ou PostgreSQL não encontradas no Vault. Verifique o arquivo Vault.")

    try:
        minio_creds = json.loads(minio_creds_encrypted)
        pg_creds = json.loads(pg_creds_encrypted)
    except json.JSONDecodeError as e:
        logger.critical(f"Erro ao decodificar credenciais do Vault (JSON inválido): {e}")
        raise ValueError("Formato de credenciais no Vault inválido.")

    # --- ETAPA DE EXTRAÇÃO (MinIO) ---
    df: pd.DataFrame
    try:
        logger.info("Conectando ao MinIO para leitura do arquivo...")
        
        # Cliente Minio do minio-py aceita endpoint_url com http/https
        client = Minio(
            minio_creds['endpoint_url'], # minio_creds agora vem do Vault e já deve ter o esquema (e.g., http://minio:9000)
            access_key=minio_creds['access_key'],
            secret_key=minio_creds['secret_key'],
            secure=False # Usar True em produção com certificado SSL apropriado
        )

        logger.info(f"Lendo o objeto: {ETLConfig.MINIO_BUCKET_NAME}/{ETLConfig.MINIO_FILE_PATH}")
        if not client.bucket_exists(ETLConfig.MINIO_BUCKET_NAME):
            raise FileNotFoundError(f"Bucket '{ETLConfig.MINIO_BUCKET_NAME}' não encontrado no MinIO.")

        data_object = client.get_object(ETLConfig.MINIO_BUCKET_NAME, ETLConfig.MINIO_FILE_PATH)
        data_bytes = data_object.read()
        data_object.close()
        data_object.release_conn()

        df = pd.read_csv(io.BytesIO(data_bytes))
        logger.info(f"Dados extraídos com sucesso de '{ETLConfig.MINIO_FILE_PATH}' ({len(df)} linhas).")

    except FileNotFoundError as e:
        logger.error(f"Falha na extração do MinIO: {e}. Verifique o nome do bucket/arquivo e montagem de volumes.", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Falha geral na extração do MinIO: {e}", exc_info=True)
        raise

    # --- ETAPA DE CARGA (PostgreSQL) ---
    try:
        logger.info("Conectando ao PostgreSQL para inserir dados...")
        db_url = (
            f"postgresql+psycopg2://{pg_creds['user']}:{pg_creds['password']}"
            f"@{pg_creds['host']}:{pg_creds['port']}/{pg_creds['database']}" # 'database' em vez de 'dbname'
        )
        engine = create_engine(db_url)

        # Usar uma transação explícita para garantir Atomicidade
        with engine.begin() as conn: # engine.begin() gerencia a transação automaticamente (commit/rollback)
            logger.info(f"Limpando tabela '{ETLConfig.POSTGRES_TABLE_NAME}' no PostgreSQL (TRUNCATE)...")
            conn.execute(text(f"TRUNCATE TABLE {ETLConfig.POSTGRES_TABLE_NAME} RESTART IDENTITY;"))
            
            logger.info(f"Inserindo {len(df)} registros na tabela '{ETLConfig.POSTGRES_TABLE_NAME}'...")
            df.to_sql(ETLConfig.POSTGRES_TABLE_NAME, conn, if_exists="append", index=False)
            
        logger.info("Carga finalizada com sucesso no Data Mart!")

    except Exception as e:
        logger.error(f"Erro ao carregar dados no PostgreSQL: {e}", exc_info=True)
        raise

# ---
# Definição da DAG
# ---

with DAG(
    dag_id="dag_minio_para_postgresql_enterprise_v1",
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None,  # Definido como 'None' para execução manual ou agendamento externo
    catchup=False,  # Não executa para datas passadas que não foram capturadas
    max_active_runs=1, # Garante que apenas uma instância da DAG rode por vez
    doc_md="""
    ## DAG ETL: Data Lake (MinIO) para Data Mart (PostgreSQL) - Enterprise Edition

    ### Objetivo
    Esta DAG orquestra um pipeline ETL completo e seguro, projetado para mover dados
    da camada Bronze do Data Lake (armazenada no MinIO) para um Data Mart analítico
    no PostgreSQL. O objetivo principal é disponibilizar dados brutos consolidados
    em um formato estruturado, pronto para análises de negócios e consumo por
    ferramentas de Business Intelligence.

    ### Arquitetura do Fluxo de Dados
    ```mermaid
    graph TD
        A[MinIO - Bronze Layer<br>(dados_consolidados.csv)] -->|Extração Segura<br>(Credenciais Vault)| B{Tarefa de ETL<br>PythonOperator}
        B -->|Transformação em Pandas| C[Memória<br>(DataFrame)]
        C -->|Carga Segura<br>(TRUNCATE + INSERT)| D[PostgreSQL - Data Mart<br>(Tabela dados_olist)]
        B --- E[Vault de Credenciais]
    ```
    - MinIO (Bronze Layer): Atua como a fonte de dados brutos e staging. O arquivo `dados_consolidados.csv`
      é o ponto de partida, presumindo que tenha sido gerado por uma DAG anterior.
    - Vault de Credenciais: Um componente de segurança central que armazena e
      fornece credenciais de acesso para MinIO e PostgreSQL de forma segura,
      garantindo que segredos não sejam hardcoded ou expostos.
    - Tarefa de ETL (PythonOperator): Um único operador Python que encapsula
      toda a lógica de extração, transformação e carga, garantindo atomicidade
      e tratamento de erros.
    - Transformação em Pandas: A lógica de transformação é realizada em memória
      usando a biblioteca Pandas, que é ideal para manipulações de dados tabulares.
    - PostgreSQL (Data Mart): O destino final dos dados, onde eles são carregados
      em uma tabela específica (`dados_olist`), pronta para ser consumida.

    ### Componentes Técnicos Utilizados
    - Apache Airflow: Orquestrador que agenda e monitora o pipeline.
    - MinIO Client (Python): Biblioteca para interagir com o MinIO, garantindo
      a extração eficiente do arquivo CSV.
    - Pandas: Poderosa biblioteca para manipulação e processamento de dados tabulares em Python.
    - SQLAlchemy + Psycopg2: Framework robusto para conexão e interação com bancos
      de dados PostgreSQL, permitindo operações transacionais.
    - Sistema de Segurança Customizado (`plugins.security_system`): Módulos internos
      para gerenciamento de Vault e auditoria.

    ### Segurança e Compliance
    - Credenciais Criptografadas: As chaves de acesso a MinIO e PostgreSQL são
      armazenadas criptografadas no Vault e recuperadas em tempo de execução
      usando uma chave de ambiente.
    - Isolamento de Segredos: Nenhuma credencial sensível é exposta no código-fonte
      da DAG, logs do Airflow ou variáveis de ambiente de forma insegura.
    - Transações ACID: A carga no PostgreSQL é executada dentro de uma transação,
      garantindo que a operação seja atômica (tudo ou nada), consistente, isolada
      e durável. Em caso de falha, um `ROLLBACK` é acionado automaticamente.

    ### Robustez e Tratamento de Erros
    - Lógica de Reconexão e Retentativa: Embora não explícita no código fornecido,
      as conexões com MinIO e PostgreSQL são gerenciadas por bibliotecas que
      podem ter mecanismos de retentativa internos. Falhas na tarefa do Airflow
      também podem ser configuradas para retentar.
    - Logging Detalhado: Cada etapa importante do processo é logada com mensagens
      claras para facilitar a depuração e o monitoramento.
    - Exceções Específicas: Erros de `FileNotFoundError` (MinIO) e exceções
      gerais são capturadas e logadas de forma a fornecer informações contextuais
      para a resolução de problemas.

    ### Dependências e Pré-requisitos
    - Vault Configurado: As credenciais para MinIO (`minio_local_credentials`)
      e PostgreSQL (`postgresql_credentials`) devem estar previamente
      configuradas no `vault.json` e o `SECURITY_VAULT_SECRET_KEY` deve estar
      disponível como variável de ambiente no ambiente Airflow.
    - Dados no MinIO: O arquivo `olist/dados_consolidados.csv` deve existir
      no bucket `bronze-layer` do Minio, resultado de uma DAG de consolidação anterior.
    - Tabela PostgreSQL: A tabela `dados_olist` deve existir no banco de dados
      PostgreSQL de destino. Um schema inicial para esta tabela é esperado.
    """,
    tags=['datamart', 'etl', 'postgres', 'vault', 'minio', 'enterprise', 'seguranca', 'olist']
) as dag:

    # ---
    # Definição da Tarefa Principal
    # ---

    tarefa_transferir_dados = PythonOperator(
        task_id='transferir_minio_para_postgres',
        python_callable=_minio_para_postgresql_seguro,
        # retries=3,
        # retry_delay=pendulum.duration(minutes=5),
        doc_md="""
        ## Tarefa: Transferência de Dados do MinIO para o PostgreSQL (Segura)

        Propósito: Esta tarefa executa o core do processo ETL, movendo dados
        do Data Lake (MinIO) para o Data Mart (PostgreSQL). É um componente
        crítico para a disponibilização de dados analíticos.

        ### Funções Principais:
        - Extração Segura (MinIO): Conecta-se ao MinIO usando credenciais
          recuperadas do Vault. Lê o arquivo `dados_consolidados.csv` do
          bucket `bronze-layer`.
        - Carregamento Transacional (PostgreSQL): Estabelece uma conexão
          segura com o PostgreSQL. Antes de carregar novos dados, a tabela
          `dados_olist` é truncada (limpa completamente) para garantir
          uma carga limpa e idempotente. Em seguida, o DataFrame Pandas é
          inserido na tabela. Todas as operações no banco de dados são
          executadas dentro de uma **transação ACID**, o que significa que,
          se qualquer parte da carga falhar, toda a operação é revertida
          (rollback), mantendo a integridade dos dados no Data Mart.

        ### Segurança e Robustez:
        - Credenciais: Nunca são expostas diretamente no código ou logs.
          São gerenciadas exclusivamente pelo Vault de segurança.
        - Tratamento de Erros: Inclui blocos `try-except` robustos para
          capturar e logar falhas em qualquer etapa (conexão, leitura, escrita),
          proporcionando diagnósticos claros.
        - Idempotência: A estratégia de `TRUNCATE TABLE` antes do `INSERT`
          garante que a execução repetida da tarefa sempre resulte no mesmo
          estado final do Data Mart, sem duplicidades.

        ### Logs e Observabilidade:
        - Logs detalhados são gerados em cada etapa, informando o progresso,
          o número de registros processados e quaisquer erros. Isso é crucial
          para o monitoramento e a depuração em ambientes de produção.
        """
    )
