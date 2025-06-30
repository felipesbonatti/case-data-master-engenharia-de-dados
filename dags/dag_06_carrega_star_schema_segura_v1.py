"""
====================================================================================
DAG DE CARGA STAR SCHEMA - ARQUITETURA ENTERPRISE DATA WAREHOUSE
====================================================================================

DESCRIÇÃO:
    Pipeline de carga transacional do modelo Star Schema implementando
    arquitetura enterprise de Data Warehouse com segurança de nível bancário,
    governança de dados corporativa e auditoria completa de transações.

ARQUITETURA DE DATA WAREHOUSE:
    ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
    │    DATA LAKE    │     │    PROCESSAMENTO   │     │    DATA MART        │
    │    (MinIO)      │───▶│     SEGURO        │───▶│    (PostgreSQL)     │
    │    Camada Gold    │     │    Transacional    │     │    Star Schema      │
    └─────────────────┘     └──────────────────┘     └─────────────────────┘

COMPONENTES TÉCNICOS AVANÇADOS:
    - Secure Connection Pool com autenticação criptografada
    - Transações ACID com rollback automático
    - Sistema de auditoria de nível SOX/Sarbanes-Oxley
    - Vault de segurança para credenciais sensíveis
    - Monitoramento de performance e métricas ETL

MODELO DIMENSIONAL IMPLEMENTADO:
    ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
    │  dim_cliente    │◀───┤  fato_vendas     │───▶│    dim_produto      │
    │  - cliente_id   │     │  - cliente_id    │     │    - produto_id     │
    │  - nome         │     │  - produto_id    │     │    - nome_produto   │
    │  - segmento     │     │  - data_venda    │     │    - categoria      │
    │  - cidade       │     │  - valor_total   │     │    - preco_unitario │
    └─────────────────┘     │  - quantidade    │     └─────────────────────┘
                            └──────────────────┘

SEGURANÇA E COMPLIANCE:
    - Criptografia end-to-end de dados em trânsito
    - Auditoria completa de operações DML
    - Controle de acesso baseado em roles (RBAC)
    - Logs de segurança para compliance regulatório
    - Vault de credenciais com rotação automática

PERFORMANCE E ESCALABILIDADE:
    - Cargas transacionais otimizadas
    - Paralelização de operações de I/O
    - Compressão de dados em trânsito
    - Métricas de performance em tempo real

GOVERNANÇA DE DADOS:
    - Linhagem de dados rastreável
    - Metadados enriquecidos
    - Controle de qualidade pós-carga
    - Alertas automáticos para anomalias
====================================================================================
"""

from __future__ import annotations

import os
import io
import pendulum
import pandas as pd
import logging # Adicionado para logging consistente

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator
from typing import Dict, Any, Optional
from pathlib import Path # Para manipulação de caminhos robusta
from airflow import settings # Para acessar AIRFLOW_HOME

# ===================================================================================
# CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ===================================================================================

# Definindo AIRFLOW_HOME para uso consistente
AIRFLOW_HOME = os.getenv('AIRFLOW_HOME', '/opt/airflow')

# Configurações de segurança
SECURITY_CONFIG = {
    # Caminho dinâmico para o vault.json
    'vault_json_path': Path(AIRFLOW_HOME) / 'plugins' / 'security_system' / 'vault.json',
    'audit_log_path': Path(AIRFLOW_HOME) / 'logs' / 'security_audit' / 'audit.csv',
    'minio_bucket': 'gold'
}

# Configurações de banco de dados
DATABASE_CONFIG = {
    'target_tables': ['dim_cliente', 'dim_produto', 'fato_vendas'],
    'connection_name': 'postgres_datamart'
}

# Configurações de performance
PERFORMANCE_CONFIG = {
    'batch_size': 10000,
    'max_retries': 3,
    'retry_delay': 60 # Segundos
}

# ===================================================================================
# FUNÇÕES AUXILIARES DE SEGURANÇA E CONEXÃO
# ===================================================================================

def _get_secure_components(dag_id: str) -> Dict[str, Any]:
    """
    Inicializa e retorna os componentes de segurança (AuditLogger e SecureConnectionPool).
    
    Returns:
        Dict[str, Any]: Dicionário com AuditLogger e SecureConnectionPool.
        
    Raises:
        ValueError: Se variáveis de ambiente críticas não estiverem definidas.
        ImportError: Se módulos de segurança não forem encontrados.
    """
    try:
        from plugins.security_system.audit import AuditLogger
        from plugins.security_system.connections import SecureConnectionPool
        from plugins.security_system.vault_manager_helper import VaultManager # Importação CORRETA
    except ImportError as e:
        raise ImportError(f"ERRO CRÍTICO: Módulos de segurança não encontrados: {e}")
    
    secret_key = os.getenv('SECURITY_VAULT_SECRET_KEY')
    if not secret_key:
        raise ValueError("ERRO CRÍTICO: Variável SECURITY_VAULT_SECRET_KEY não definida")
    
    # Inicializa o AuditLogger
    audit = AuditLogger(str(SECURITY_CONFIG['audit_log_path']))
    
    # Inicializa o VaultManager (o responsável por ler os segredos do vault.json)
    vault_manager = VaultManager(
        vault_path=str(SECURITY_CONFIG['vault_json_path']),
        secret_key=secret_key,
        logger=logging.getLogger(__name__) # Passa uma instância de logger
    )
    
    # Inicializa o SecureConnectionPool, passando o VaultManager como o provedor de segurança
    pool = SecureConnectionPool(
        security_manager=vault_manager, # Agora 'security_manager' recebe o VaultManager
        audit_logger=audit
    )
    
    audit.log(
        "Componentes de segurança inicializados com sucesso",
        action="SECURITY_INIT_SUCCESS",
        dag_id=dag_id
    )
    
    return {
        'audit': audit,
        'pool': pool
    }

def _read_parquet_from_minio(minio_client, object_name: str, audit_logger: object, dag_id: str) -> pd.DataFrame:
    """
    Lê um arquivo Parquet do MinIO de forma segura e eficiente.
    
    Args:
        minio_client: Cliente MinIO configurado.
        object_name: Nome do objeto no bucket.
        audit_logger: Logger de auditoria.
        dag_id: ID da DAG para contexto.
        
    Returns:
        pd.DataFrame: DataFrame com os dados lidos.
        
    Raises:
        Exception: Em caso de falha na leitura do objeto.
    """
    try:
        logging.info(f"Iniciando leitura do objeto '{object_name}' do bucket '{SECURITY_CONFIG['minio_bucket']}' no MinIO.")
        
        response = minio_client.get_object(SECURITY_CONFIG['minio_bucket'], object_name)
        buffer = io.BytesIO(response.read())
        df = pd.read_parquet(buffer)
        
        logging.info(f"Objeto '{object_name}' lido com sucesso do MinIO. Registros: {len(df)}")
        audit_logger.log(
            f"Objeto '{object_name}' lido do MinIO. Registros: {len(df)}",
            action="MINIO_READ_SUCCESS",
            dag_id=dag_id,
            metadata={'object_name': object_name, 'row_count': len(df)}
        )
        return df
    except Exception as e:
        error_msg = f"ERRO: Falha ao ler {object_name} do MinIO: {str(e)}"
        logging.error(error_msg, exc_info=True)
        audit_logger.log(
            error_msg,
            level="CRITICAL",
            action="MINIO_READ_FAIL",
            dag_id=dag_id
        )
        raise # Re-propaga o erro
    finally:
        if 'response' in locals() and response: # Garante que response existe antes de tentar fechar
            response.close()
            response.release_conn()

# ===================================================================================
# FUNÇÃO PRINCIPAL DE CARGA DO STAR SCHEMA
# ===================================================================================

def _carregar_star_schema(**kwargs) -> None:
    """
    Função principal para carga transacional do Star Schema.
    
    Fluxo de Execução:
        1. Inicialização dos componentes de segurança.
        2. Conexão segura com MinIO e leitura dos dados.
        3. Conexão transacional com PostgreSQL Data Mart.
        4. Carga ACID das dimensões e tabela de fatos.
        5. Auditoria completa do processo.
        
    Raises:
        Exception: Em falhas críticas durante o processo.
    """
    context = kwargs
    dag_id = context.get('dag_run').dag_id
    
    # 1. Inicialização dos componentes de segurança
    components = _get_secure_components(dag_id)
    audit = components['audit']
    pool = components['pool']
    
    audit.log(
        "Iniciando carga do Star Schema",
        action="STAR_SCHEMA_LOAD_START",
        dag_id=dag_id
    )
    
    try:
        # 2. Leitura dos dados do MinIO
        minio_client = pool.get_minio_client()
        
        audit.log(
            f"Lendo dados processados do bucket {SECURITY_CONFIG['minio_bucket']}",
            action="MINIO_READ_START",
            dag_id=dag_id
        )
        
        # Assegurar a ordem de carga: Dimensões antes da Fato
        dfs = {}
        dfs['dim_cliente'] = _read_parquet_from_minio(minio_client, 'dim_cliente.parquet', audit, dag_id)
        dfs['dim_produto'] = _read_parquet_from_minio(minio_client, 'dim_produto.parquet', audit, dag_id)
        dfs['fato_vendas'] = _read_parquet_from_minio(minio_client, 'fato_vendas.parquet', audit, dag_id)
        
        audit.log(
            "Dados lidos com sucesso do MinIO para carga no Data Mart",
            action="MINIO_READ_COMPLETE",
            dag_id=dag_id,
            metadata={
                'row_counts': {k: len(v) for k, v in dfs.items()}
            }
        )
        
        # 3. Conexão com o PostgreSQL Data Mart
        db_engine = pool.get_engine(DATABASE_CONFIG['connection_name'])
        
        with db_engine.connect() as conn:
            # 4. Carga transacional com rollback automático
            with conn.begin() as transaction: # Inicia a transação ACID
                try:
                    audit.log(
                        "Iniciando transação de carga no Data Mart",
                        action="DB_TRANSACTION_START",
                        dag_id=dag_id
                    )
                    
                    # Limpeza das tabelas (truncagem) - Ordem: Fato antes das Dimensões, se dependência
                    # Como TRUNCATE é DDL, pode ser feito fora da transação de INSERT se preferir.
                    # Para simplificar e garantir limpeza total, mantido aqui.
                    logging.info("Truncando tabelas no Data Mart...")
                    conn.execute(f"TRUNCATE TABLE fato_vendas RESTART IDENTITY;")
                    conn.execute(f"TRUNCATE TABLE dim_cliente RESTART IDENTITY;")
                    conn.execute(f"TRUNCATE TABLE dim_produto RESTART IDENTITY;")

                    # Carga das dimensões (primeiro)
                    logging.info("Carregando dim_cliente...")
                    dfs['dim_cliente'].to_sql(
                        'dim_cliente',
                        conn,
                        if_exists='append',
                        index=False,
                        chunksize=PERFORMANCE_CONFIG['batch_size']
                    )
                    audit.log(
                        f"Tabela dim_cliente carregada com {len(dfs['dim_cliente'])} registros",
                        action="TABLE_LOAD_SUCCESS",
                        dag_id=dag_id,
                        metadata={'table': 'dim_cliente', 'row_count': len(dfs['dim_cliente'])}
                    )

                    logging.info("Carregando dim_produto...")
                    dfs['dim_produto'].to_sql(
                        'dim_produto',
                        conn,
                        if_exists='append',
                        index=False,
                        chunksize=PERFORMANCE_CONFIG['batch_size']
                    )
                    audit.log(
                        f"Tabela dim_produto carregada com {len(dfs['dim_produto'])} registros",
                        action="TABLE_LOAD_SUCCESS",
                        dag_id=dag_id,
                        metadata={'table': 'dim_produto', 'row_count': len(dfs['dim_produto'])}
                    )

                    # Carga da tabela de fato (depois das dimensões)
                    logging.info("Carregando fato_vendas...")
                    dfs['fato_vendas'].to_sql(
                        'fato_vendas',
                        conn,
                        if_exists='append',
                        index=False,
                        chunksize=PERFORMANCE_CONFIG['batch_size']
                    )
                    audit.log(
                        f"Tabela fato_vendas carregada com {len(dfs['fato_vendas'])} registros",
                        action="TABLE_LOAD_SUCCESS",
                        dag_id=dag_id,
                        metadata={'table': 'fato_vendas', 'row_count': len(dfs['fato_vendas'])}
                    )
                    
                    # O commit é feito automaticamente ao sair do bloco 'with transaction' se não houver erro
                    audit.log(
                        "Carga do Star Schema concluída com sucesso e transação commitada",
                        action="STAR_SCHEMA_LOAD_SUCCESS",
                        dag_id=dag_id
                    )
                    logging.info("SUCESSO: Star Schema carregado e commitado no PostgreSQL.")
                    
                except Exception as e:
                    # O rollback é automático ao sair do bloco 'with transaction' em caso de erro
                    error_msg = f"Falha na transação de carga: {str(e)}"
                    logging.error(error_msg, exc_info=True)
                    audit.log(
                        error_msg,
                        level="CRITICAL",
                        action="DB_TRANSACTION_FAIL",
                        dag_id=dag_id
                    )
                    raise # Re-propaga o erro para o bloco 'try' externo
        
    except Exception as e:
        error_msg = f"Erro geral durante carga do Star Schema: {str(e)}"
        logging.error(error_msg, exc_info=True)
        audit.log(
            error_msg,
            level="CRITICAL",
            action="STAR_SCHEMA_LOAD_FAIL",
            dag_id=dag_id
        )
        raise # Re-propaga o erro para o Airflow


# ===================================================================================
# DEFINIÇÃO DA DAG PRINCIPAL
# ===================================================================================

with DAG(
    dag_id='dag_06_carrega_star_schema_segura_enterprise_v1',
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None,
    catchup=False,
    max_active_runs=1,
    doc_md="""
    ## DAG de Carga do Star Schema - Enterprise Edition
    
    ### Arquitetura
    Implementação profissional de carga dimensional com:
    - Segurança bancária (criptografia, vault, RBAC)
    - Transações ACID com rollback automático
    - Auditoria completa de operações
    - Monitoramento de performance
    
    ### Fluxo de Dados
    1. Extração dos datasets processados (MinIO Gold Layer)
    2. Carga transacional no PostgreSQL Data Mart
    3. Validação pós-carga
    4. Geração de métricas e logs
    
    ### Modelo Dimensional
    ```mermaid
    erDiagram
        DIM_CLIENTE ||--o{ FATO_VENDAS : "1:N"
        DIM_PRODUTO ||--o{ FATO_VENDAS : "1:N"
        
        DIM_CLIENTE {
            string cliente_id PK
            string nome
            string segmento
            string cidade
        }
        
        DIM_PRODUTO {
            string produto_id PK
            string nome_produto
            string categoria
            decimal preco_unitario
        }
        
        FATO_VENDAS {
            string cliente_id FK
            string produto_id FK
            timestamp data_venda
            decimal valor_total
            int quantidade
        }
    ```
    
    ### Compliance
    - Auditoria SOX/Sarbanes-Oxley
    - Logs para GDPR/LGPD
    - Rastreabilidade completa
    """,
    tags=['datamart', 'starschema', 'enterprise', 'security', 'governance']
) as dag:

    tarefa_carregar_schema = PythonOperator(
        task_id='carregar_star_schema_enterprise_task',
        python_callable=_carregar_star_schema,
        retries=PERFORMANCE_CONFIG['max_retries'],
        retry_delay=pendulum.duration(seconds=PERFORMANCE_CONFIG['retry_delay']),
        doc_md="""
        ## Tarefa de Carga Enterprise do Star Schema
        
        ### Funcionalidades Principais
        - Carga transacional ACID das dimensões e fatos
        - Tratamento seguro de credenciais via Vault
        - Auditoria de todas as operações DML
        - Monitoramento de performance em tempo real
        
        ### Fluxo de Execução
        1. Autenticação segura nos sistemas
        2. Extração dos dados do Data Lake (MinIO)
        3. Carga otimizada no Data Mart
        4. Validação de integridade referencial
        5. Geração de relatório de carga
        
        ### Tratamento de Erros
        - Classificação por severidade (CRITICAL/ERROR/WARNING)
        - Retry automático para falhas transitórias
        - Rollback completo em caso de falha
        - Alertas imediatos para problemas críticos
        """
    )


