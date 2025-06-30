import pandas as pd
import psycopg2
import os
import sys
import logging
import json # Para desserializar credenciais JSON do Vault
from pathlib import Path # Para manipulação de caminhos robusta
from typing import Dict, Any, Optional # Para type hinting

# Configuração do logger 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Adiciona o diretorio dos plugins ao path para encontrar o security_system.
# Isso e crucial se o script for executado diretamente e nao pelo ambiente Airflow,
# onde os plugins ja estariam no PYTHONPATH.
plugins_path = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins')))
if str(plugins_path) not in sys.path:
    sys.path.insert(0, str(plugins_path))

# Importações dos módulos de segurança customizados.
# Em caso de falha, o script deve encerrar ou usar fallbacks seguros.
try:
    from security_system.vault_manager_helper import VaultManager # Usar VaultManager
    from security_system.audit import AuditLogger
    from security_system.exceptions import ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError
except ImportError as e:
    logger.critical(f"ERRO CRITICO: Modulos de seguranca customizados nao encontrados. Detalhes: {e}")
    logger.critical("Certifique-se de que 'plugins/security_system' esta no PYTHONPATH ou no diretorio de plugins do Airflow.")
    sys.exit(1) # Sai com codigo de erro se modulos criticos nao forem carregados


"""
====================================================================================
SCRIPT STANDALONE: POPULACAO DO STAR SCHEMA
====================================================================================

DESCRICAO:
    Este script Python standalone e responsavel por popular as tabelas de dimensao
    e fato de um Data Mart modelado como Star Schema. Ele simula a etapa final
    de carga de dados analiticos, extraindo dados de arquivos CSV locais (simulando
    a Camada Gold do Data Lake) e inserindo-os de forma segura em um banco de dados
    PostgreSQL. A seguranca e uma prioridade, utilizando um Vault para credenciais.

OBJETIVO PRINCIPAL:
    - Conectar-se de forma segura a um banco de dados PostgreSQL (Data Mart).
    - Ler dados de arquivos CSV que representam as fontes para dimensoes e fatos.
    - Popular as tabelas `dim_cliente`, `dim_produto` e `fato_vendas`.
    - Garantir a idempotencia das insercoes usando `ON CONFLICT DO NOTHING`.

ARQUITETURA DO FLUXO DE DADOS:
    DATA LAKE (Local CSV - Gold) --> SCRIPT DE POPULACAO STAR SCHEMA --> DATA MART (PostgreSQL)
    - Clientes                         - dim_cliente
    - Produtos                         - dim_produto
    - Vendas                           - fato_vendas

COMPONENTES TECNICOS:
    - `pandas`: Para leitura eficiente de arquivos CSV.
    - `psycopg2`: Driver Python para conexao e interacao com PostgreSQL.
    - `plugins.security_system.vault_manager_helper.VaultManager`: Para acesso seguro as credenciais.
    - `plugins.security_system.audit.AuditLogger`: Para registro de eventos de seguranca.

SEGURANCA E CONFORMIDADE:
    - Credenciais Zero-Exposure: As credenciais do PostgreSQL sao obtidas do Vault
      em tempo de execucao, nunca hardcoded.
    - Auditoria: As operacoes de conexao e falhas sao logadas pelo sistema de auditoria.
    - Idempotencia: As operacoes `INSERT ... ON CONFLICT DO NOTHING` evitam duplicacao
      de registros em caso de re-execucao do script.

INSTRUCOES DE USO:
    1.  Configurar Vault: Execute `scripts/setup_vault_secrets.py` para popular o Vault
        com as credenciais PostgreSQL (chave esperada: `postgres_indicativos_credentials`).
        Certifique-se de que `SECURITY_VAULT_SECRET_KEY` esteja definida no ambiente.
    2.  Tabelas Existentes: As tabelas `dim_cliente`, `dim_produto` e `fato_vendas`
        devem existir no banco de dados PostgreSQL, com seus schemas definidos.
    3.  Caminhos dos Dados: Ajuste `StarSchemaConfig.DATA_BASE_PATH` para o local
        onde os arquivos CSV (`olist_customers_dataset.csv`, `olist_products_dataset.csv`,
        `dados_consolidados.csv`) estao localizados.
    4.  Execucao: Execute este script. Ex: `python3 [caminho_para_este_script]/popula_star_schema.py`
====================================================================================
"""

# ---
# CONFIGURACOES GLOBAIS
# ---
class StarSchemaConfig:
    """Centraliza as configuracoes para a populacao do Star Schema."""

    # Variavel de ambiente para a chave mestra do Vault (CRITICA!)
    SECRET_KEY: Optional[str] = os.getenv('SECURITY_VAULT_SECRET_KEY')

    # Caminhos para componentes do sistema de seguranca customizado (relativos a AIRFLOW_HOME se aplicavel)
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json' # Caminho do Vault JSON
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'star_schema_audit.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'star_schema_system.log'

    # Chave do Vault para credenciais PostgreSQL do Data Mart
    PG_CREDS_KEY: str = "postgres_indicativos_credentials" # Nome da chave consistente

    # Caminho base para os arquivos CSV de origem 
    DATA_BASE_PATH: Path = Path(os.getenv('STAR_SCHEMA_DATA_PATH', 'data/olist')) 

    # Nomes dos arquivos CSV de origem
    CUSTOMERS_FILE: str = 'olist_customers_dataset.csv'
    PRODUCTS_FILE: str = 'olist_products_dataset.csv'
    CONSOLIDATED_SALES_FILE: str = 'dados_consolidados.csv'

    # Nomes das tabelas no Data Mart (PostgreSQL)
    DIM_CLIENTE_TABLE: str = 'dim_cliente'
    DIM_PRODUTO_TABLE: str = 'dim_produto'
    FATO_VENDAS_TABLE: str = 'fato_vendas'

# ---
# FUNCOES AUXILIARES
# ---

def _get_db_connection() -> psycopg2.extensions.connection:
    """
    Obtem uma conexao segura com o banco de dados PostgreSQL (Data Mart)
    utilizando credenciais recuperadas do Vault.

    Retorna:
        psycopg2.extensions.connection: Uma instancia de conexao ativa com o PostgreSQL.

    Levanta:
        ValueError: Se a SECRET_KEY do Vault nao estiver definida.
        ConfigurationError: Se as credenciais PG nao forem encontradas ou forem invalidas no Vault.
        SecureConnectionError: Para falhas ao estabelecer a conexao com o banco de dados.
    """
    logger.info("Iniciando obtencao de conexao segura com o PostgreSQL.")

    # Inicializa AuditLogger para logar operacoes de seguranca
    try:
        # Garante que os diretorios de log existam antes de inicializar o logger
        StarSchemaConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        StarSchemaConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = AuditLogger(
            audit_file_path=str(StarSchemaConfig.AUDIT_LOG_PATH),
            system_log_file_path=str(StarSchemaConfig.SYSTEM_LOG_PATH)
        )
        logger.info("AuditLogger inicializado para _get_db_connection.")
    except Exception as e:
        logger.error(f"Nao foi possivel inicializar AuditLogger para _get_db_connection: {e}. Auditoria de conexao sera limitada.", exc_info=True)
        class NoOpAuditLogger: # Fallback
            def log(self, *args, **kwargs): pass
            def info(self, *args, **kwargs): pass
            def def critical(self, *args, **kwargs): pass
            def error(self, *args, **kwargs): pass
        audit_logger = NoOpAuditLogger() # type: ignore

    if not StarSchemaConfig.SECRET_KEY:
        error_msg = "ERRO CRITICO: A variavel de ambiente 'SECURITY_VAULT_SECRET_KEY' nao esta definida."
        audit_logger.critical(error_msg, action="VAULT_KEY_MISSING")
        logger.critical(error_msg)
        raise ValueError(error_msg)

    try:
        # Inicializa VaultManager para acessar o Vault
        # Garante que o diretorio do vault.json exista
        StarSchemaConfig.VAULT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        vault_manager = VaultManager( # Usando VaultManager
            vault_path=str(StarSchemaConfig.VAULT_JSON_PATH),
            secret_key=StarSchemaConfig.SECRET_KEY,
            logger=audit_logger # Passa o AuditLogger para o VaultManager
        )
        audit_logger.info("VaultManager inicializado para _get_db_connection.", action="SECURITY_MANAGER_INIT")

        # Recupera as credenciais PostgreSQL do Vault
        audit_logger.log("Recuperando credenciais PostgreSQL do Vault.", action="GET_PG_CREDS_FROM_VAULT")
        pg_creds_encrypted = vault_manager.get_secret(StarSchemaConfig.PG_CREDS_KEY)

        if not pg_creds_encrypted:
            error_msg = f"Credenciais '{StarSchemaConfig.PG_CREDS_KEY}' nao encontradas ou invalidas no Vault."
            audit_logger.critical(error_msg, action="PG_CREDS_MISSING", error_message=error_msg)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)
        
        try:
            pg_creds = json.loads(pg_creds_encrypted) # Desserializa o JSON
        except json.JSONDecodeError as e:
            error_msg = f"Erro ao decodificar credenciais PostgreSQL do Vault (JSON invalido): {e}"
            audit_logger.critical(error_msg, action="PG_CREDS_JSON_ERROR", error_message=str(e), stack_trace_needed=True)
            logger.critical(error_msg, exc_info=True)
            raise ConfigurationError(error_msg)

        # Adapta a chave 'database' para 'dbname' se necessario para psycopg2
        if 'dbname' not in pg_creds and 'database' in pg_creds:
            pg_creds['dbname'] = pg_creds.pop('database')

        # Verifica chaves obrigatorias
        required_keys = ["host", "port", "dbname", "user", "password"]
        missing_keys = [key for key in required_keys if key not in pg_creds or not pg_creds[key]]
        if missing_keys:
            error_msg = f"Credenciais PostgreSQL incompletas no Vault (faltando: {', '.join(missing_keys)})."
            audit_logger.critical(error_msg, action="PG_CREDS_INCOMPLETE", error_message=error_msg)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)

        # Estabelece a conexao com o banco de dados PostgreSQL
        conn = psycopg2.connect(
            host=pg_creds['host'],
            port=pg_creds['port'],
            dbname=pg_creds['dbname'],
            user=pg_creds['user'],
            password=pg_creds['password']
        )
        # Teste de conexao basico
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        
        audit_logger.log("Conexao PostgreSQL obtida com sucesso.", action="PG_CONN_SUCCESS", service="PostgreSQL")
        logger.info("Conexao PostgreSQL estabelecida e autenticada com sucesso.")
        return conn

    except (ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError) as e:
        logger.error(f"Erro de seguranca/configuracao ao obter conexao PostgreSQL: {e}", exc_info=True)
        raise # Re-lanca a excecao customizada
    except psycopg2.Error as e:
        error_msg = f"Erro ao conectar ao PostgreSQL (psycopg2): {e}"
        audit_logger.critical(error_msg, action="PG_CONN_FAIL", service="PostgreSQL", error_message=str(e), stack_trace_needed=True)
        logger.critical(error_msg, exc_info=True)
        raise SecureConnectionError(error_msg) # Re-lanca como erro de conexao segura
    except Exception as e:
        logger.critical(f"Erro inesperado ao obter conexao PostgreSQL: {e}", exc_info=True)
        raise SecureConnectionError(f"Erro inesperado na conexao PostgreSQL: {e}")

def _load_csv_data(file_name: str) -> pd.DataFrame:
    """
    Carrega dados de um arquivo CSV especifico.

    Args:
        file_name (str): O nome do arquivo CSV a ser carregado (e.g., 'customers.csv').

    Retorna:
        pd.DataFrame: Um DataFrame Pandas contendo os dados do CSV.

    Levanta:
        FileNotFoundError: Se o arquivo nao for encontrado.
        pd.errors.EmptyDataError: Se o arquivo estiver vazio.
        Exception: Para outros erros de leitura do CSV.
    """
    file_path = StarSchemaConfig.DATA_BASE_PATH / file_name
    logger.info(f"Carregando dados de: {file_path}")

    if not file_path.exists():
        logger.critical(f"ERRO: Arquivo nao encontrado em '{file_path}'.")
        raise FileNotFoundError(f"Arquivo nao encontrado: {file_path}")
    
    if file_path.stat().st_size == 0:
        logger.error(f"ERRO: Arquivo '{file_path}' esta vazio.")
        raise pd.errors.EmptyDataError(f"Arquivo vazio: {file_path}")

    try:
        df = pd.read_csv(file_path)
        logger.info(f"Dados de '{file_name}' carregados com {len(df)} registros.")
        return df
    except Exception as e:
        logger.critical(f"Erro ao carregar o arquivo CSV '{file_name}': {e}", exc_info=True)
        raise

def inserir_dados_star_schema():
    """
    Popula as tabelas de dimensao (`dim_cliente`, `dim_produto`) e a tabela de fato
    (`fato_vendas`) do Star Schema no Data Mart PostgreSQL.

    O script le dados de arquivos CSV, realiza transformacoes basicas (como
    remover duplicatas para dimensoes) e insere os dados usando `ON CONFLICT DO NOTHING`
    para garantir idempotencia.
    """
    logger.info("Iniciando a populacao do Star Schema no Data Mart.")
    conn: Optional[psycopg2.extensions.connection] = None
    cursor: Optional[psycopg2.extensions.cursor] = None # Inicializar cursor como Optional
    
    try:
        # 1. Estabelece conexao com o banco de dados
        conn = _get_db_connection()
        # Define o cursor para que as operacoes sejam comitadas ou revertidas juntas
        cursor = conn.cursor()  
        logger.info("Conexao com o Data Mart estabelecida.")

        # 2. Popula a dimensao cliente
        logger.info(f"Populando tabela '{StarSchemaConfig.DIM_CLIENTE_TABLE}'...")
        df_cliente = _load_csv_data(StarSchemaConfig.CUSTOMERS_FILE).drop_duplicates(subset=['customer_id'])
        for _, row in df_cliente.iterrows():
            # Inserir ou ignorar se ja existir
            cursor.execute(
                f"""
                INSERT INTO {StarSchemaConfig.DIM_CLIENTE_TABLE} (cliente_id, nome, cidade, estado)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cliente_id) DO NOTHING;
                """,
                (row['customer_id'], row.get('customer_unique_id', 'N/A'), row['customer_city'], row['customer_state']) # Assumindo 'nome' = 'customer_unique_id'
            )
        logger.info(f"Populada {len(df_cliente)} linhas para '{StarSchemaConfig.DIM_CLIENTE_TABLE}'.")

        # 3. Popula a dimensao produto
        logger.info(f"Populando tabela '{StarSchemaConfig.DIM_PRODUTO_TABLE}'...")
        df_produto = _load_csv_data(StarSchemaConfig.PRODUCTS_FILE).drop_duplicates(subset=['product_id'])
        for _, row in df_produto.iterrows():
            cursor.execute(
                f"""
                INSERT INTO {StarSchemaConfig.DIM_PRODUTO_TABLE} (produto_id, nome_produto, categoria, preco_unitario)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (produto_id) DO NOTHING;
                """,
                (row['product_id'], row.get('product_category_name', 'N/A'), row.get('product_category_name', 'N/A'), row.get('product_weight_g', 0)) # Assumindo categoria e preco_unitario
            )
        logger.info(f"Populada {len(df_produto)} linhas para '{StarSchemaConfig.DIM_PRODUTO_TABLE}'.")

        # 4. Popula a tabela fato de vendas
        logger.info(f"Populando tabela '{StarSchemaConfig.FATO_VENDAS_TABLE}'...")
        # Filtra linhas com valores nulos essenciais para a fato
        df_fato = _load_csv_data(StarSchemaConfig.CONSOLIDATED_SALES_FILE).dropna(subset=['order_id', 'customer_id', 'product_id', 'price', 'order_purchase_timestamp'])
        
        for _, row in df_fato.iterrows():
            # Para a demo, o id_tempo e fixo. Em um cenario real, `id_tempo` seria populado
            # a partir de uma dimensao de tempo, baseando-se na data da venda.
            # Assumindo que 'order_purchase_timestamp' pode ser usado como data_venda
            # e 'price' como valor, 'order_item_id' como quantidade
            
            # Formata timestamp para o formato esperado pelo PostgreSQL
            data_venda = pd.to_datetime(row['order_purchase_timestamp']).strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute(
                f"""
                INSERT INTO {StarSchemaConfig.FATO_VENDAS_TABLE} (
                    order_id, customer_id, product_id, data_venda, valor_total, quantidade
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (order_id) DO NOTHING;
                """,
                (
                    row['order_id'],
                    row['customer_id'],
                    row['product_id'],
                    data_venda,
                    row['price'], # Assumindo price e o valor total para a demo
                    row.get('order_item_id', 1) # Assumindo order_item_id como quantidade, default 1
                )
            )
        logger.info(f"Populada {len(df_fato)} linhas para '{StarSchemaConfig.FATO_VENDAS_TABLE}'.")
            
        # 5. Confirma todas as insercoes no banco
        conn.commit()
        logger.info("Dados do Star Schema inseridos e transacao comitada com sucesso!")
        sys.exit(0) # Sai com sucesso

    except (FileNotFoundError, pd.errors.EmptyDataError) as e:
        logger.critical(f"ERRO DE DADOS: {e}. Verifique os arquivos CSV de origem.", exc_info=True)
        if conn:
            conn.rollback() # Garante rollback em erro de dados antes do final
        sys.exit(1) # Sai com erro
    except (ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError) as e:
        logger.critical(f"ERRO CRITICO DE SEGURANCA/CONEXAO: {e}", exc_info=True)
        if conn:
            conn.rollback()
        sys.exit(1) # Sai com erro
    except psycopg2.Error as e:
        logger.critical(f"ERRO DE BANCO DE DADOS PostgreSQL: {e}", exc_info=True)
        if conn:
            conn.rollback() # Em caso de erro no DB, faz rollback
        sys.exit(1) # Sai com erro
    except Exception as e:
        logger.critical(f"ERRO INESPERADO ao inserir dados no Star Schema: {e}", exc_info=True)
        if conn:
            conn.rollback() # Em caso de erro inesperado, faz rollback
        sys.exit(1) # Sai com erro
    finally:
        # Garante que a conexao e o cursor sejam fechados com seguranca
        if cursor: # Verifica se o cursor foi criado
            cursor.close()
        if conn:
            conn.close()
        logger.info("Conexao com o Data Mart encerrada.")
        logger.info("Populacao do Star Schema finalizada.")

# ---
# PONTO DE ENTRADA PRINCIPAL
# ---
if __name__ == "__main__":
    # Garante que os diretorios de log existam antes de qualquer inicializacao de logger
    StarSchemaConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    StarSchemaConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    inserir_dados_star_schema()
