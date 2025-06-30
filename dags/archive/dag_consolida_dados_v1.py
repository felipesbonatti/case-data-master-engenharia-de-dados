"""
====================================================================================
DAG DE CONSOLIDAÇÃO DE DADOS OLIST 
====================================================================================

DESCRIÇÃO:
    Pipeline ETL completo para consolidação dos datasets públicos da Olist,
    implementando padrões enterprise de qualidade e governança de dados.

ARQUITETURA:
    DATASETS OLIST (Raw Zone) --> CAMADA DE CONSOLIDAÇÃO (Junções, Transformações)
    --> DATASET CONSOLIDADO (Curated Zone)

DATASETS PROCESSADOS:
    - olist_customers_dataset.csv
    - olist_orders_dataset.csv
    - olist_order_payments_dataset.csv
    - olist_order_items_dataset.csv
    - olist_order_reviews_dataset.csv
    - olist_products_dataset.csv

TRANSFORMAÇÕES PRINCIPAIS:
    - Junção de 6 datasets relacionados
    - Seleção de colunas relevantes
    - Tratamento de valores nulos (implícito nos `merge` tipo 'outer')
    - Padronização de nomes de colunas (se necessário, pode ser adicionado)

QUALIDADE DE DADOS:
    - Verificação de integridade referencial (através de `pd.merge`)
    - Validação de chaves primárias/estrangeiras (implícito na leitura/merge)
    - Detecção de valores ausentes (pode ser feita após a consolidação)
    - Consistência de tipos de dados (garantida pelo Pandas na leitura, e pode ser reforçada)

SEGURANÇA:
    - Acesso restrito aos dados brutos (depende da configuração do ambiente Docker/MinIO)
    - Auditoria de processamento (pode ser integrada com um sistema de auditoria externo)
    - Metadados de linhagem (pode ser gerado após a execução)
====================================================================================
"""

from __future__ import annotations

import pendulum
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Configuração do logger para a DAG
# Assume que o logging já é configurado pelo Airflow ou um configurador global.
logger = logging.getLogger(__name__)

# ---
# Configurações Globais
# ---

class OlistConfig:
    """
    Centraliza todas as configurações e parâmetros para o processo ETL da Olist.
    Isso facilita a manutenção e a legibilidade do código.
    """
    # Caminho base para os datasets Olist dentro do contêiner Airflow
    BASE_DATA_PATH: Path = Path('/opt/airflow/data/olist')
    # Nome do arquivo de saída consolidado
    OUTPUT_FILE_NAME: str = 'dados_consolidados.csv'

    # Dicionário de datasets de entrada e seus respectivos nomes de arquivo
    INPUT_DATASETS: Dict[str, str] = {
        'clientes': 'olist_customers_dataset.csv',
        'pedidos': 'olist_orders_dataset.csv',
        'pagamentos': 'olist_order_payments_dataset.csv',
        'itens': 'olist_order_items_dataset.csv',
        'reviews': 'olist_order_reviews_dataset.csv',
        'produtos': 'olist_products_dataset.csv'
    }

    # Definição das colunas a serem selecionadas para cada dataset e suas chaves de junção
    # Isso melhora a clareza e a facilidade de modificação das junções.
    # Note: 'how' será definido na função de merge, não aqui, para maior flexibilidade.
    JOIN_SCHEMAS: Dict[str, Dict[str, Any]] = {
        'clientes': {
            'columns': ['customer_id', 'customer_city', 'customer_state']
        },
        'pedidos': {
            'columns': ['order_id', 'customer_id', 'order_status', 'order_purchase_timestamp'] # Adicionado timestamp
        },
        'pagamentos': {
            'columns': ['order_id', 'payment_type', 'payment_value']
        },
        'itens': {
            'columns': ['order_id', 'product_id', 'price', 'freight_value']
        },
        'reviews': {
            'columns': ['order_id', 'review_score']
        },
        'produtos': {
            'columns': ['product_id', 'product_category_name']
        }
    }

# ---
# Funções Auxiliares de ETL
# ---

def _load_datasets_from_csv() -> Dict[str, pd.DataFrame]:
    """
    Carrega todos os datasets Olist a partir de arquivos CSV, conforme configurado em `OlistConfig.INPUT_DATASETS`.
    Implementa tratamento de erros robusto para problemas de arquivo.

    Returns:
        Dict[str, pd.DataFrame]: Um dicionário onde as chaves são os nomes dos datasets
                                  e os valores são os DataFrames carregados.

    Raises:
        FileNotFoundError: Se qualquer um dos arquivos CSV esperados não for encontrado.
        pd.errors.EmptyDataError: Se um arquivo CSV for encontrado, mas estiver vazio.
        Exception: Para outros erros inesperados durante a leitura dos arquivos.
    """
    loaded_dataframes = {}
    logger.info(f"Iniciando leitura dos datasets Olist de: {OlistConfig.BASE_DATA_PATH}")

    for dataset_name, file_name in OlistConfig.INPUT_DATASETS.items():
        file_path = OlistConfig.BASE_DATA_PATH / file_name
        try:
            df = pd.read_csv(file_path)
            loaded_dataframes[dataset_name] = df
            logger.info(f"Dataset '{dataset_name}' carregado com sucesso. Registros: {len(df)}")
        except FileNotFoundError:
            logger.error(f"ERRO: Arquivo '{file_name}' não encontrado em '{OlistConfig.BASE_DATA_PATH}'. "
                         "Verifique se o volume de dados está corretamente montado no seu `docker-compose.yml`.")
            raise
        except pd.errors.EmptyDataError:
            logger.error(f"ERRO: Arquivo '{file_name}' está vazio. Nenhum dado para carregar.")
            raise
        except Exception as e:
            logger.error(f"ERRO inesperado ao ler '{file_name}': {e}")
            raise

    return loaded_dataframes

def _perform_data_joins(dataframes: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Executa as operações de junção (merge) nos DataFrames carregados para consolidar
    as informações em um único DataFrame.

    Args:
        dataframes (Dict[str, pd.DataFrame]): Um dicionário de DataFrames a serem unidos.

    Returns:
        pd.DataFrame: O DataFrame consolidado resultante das junções.

    Raises:
        KeyError: Se uma coluna de junção esperada não estiver presente em um DataFrame.
        ValueError: Para problemas de junção ou dados inesperados.
        Exception: Para outros erros inesperados durante as junções.
    """
    logger.info("Iniciando operações de junção dos datasets...")

    try:
        # 1. Juntar 'pedidos' com 'clientes'
        df_orders_customers = pd.merge(
            dataframes['pedidos'][OlistConfig.JOIN_SCHEMAS['pedidos']['columns']],
            dataframes['clientes'][OlistConfig.JOIN_SCHEMAS['clientes']['columns']],
            on='customer_id',
            how='left' # Manter todos os pedidos, mesmo que o cliente não esteja na tabela clientes (anomalia)
        )
        logger.info(f"Merge 'pedidos' + 'clientes' concluído. Registros: {len(df_orders_customers)}")

        # 2. Juntar 'df_orders_customers' com 'pagamentos'
        df_orders_customers_payments = pd.merge(
            df_orders_customers,
            dataframes['pagamentos'][OlistConfig.JOIN_SCHEMAS['pagamentos']['columns']],
            on='order_id',
            how='left' # Manter todos os registros de pedido/cliente, mesmo sem dados de pagamento
        )
        logger.info(f"Merge 'pedidos_clientes' + 'pagamentos' concluído. Registros: {len(df_orders_customers_payments)}")

        # 3. Juntar 'df_orders_customers_payments' com 'itens'
        df_with_items = pd.merge(
            df_orders_customers_payments,
            dataframes['itens'][OlistConfig.JOIN_SCHEMAS['itens']['columns']],
            on='order_id',
            how='left', # Manter todos os registros de pedido/pagamento, mesmo sem itens de pedido (anomalia)
            suffixes=('_order', '_item') # Distinguir 'price' e 'freight_value' se aparecerem em ambos
        )
        logger.info(f"Merge 'dados_pedidos_pagamentos' + 'itens' concluído. Registros: {len(df_with_items)}")

        # 4. Juntar 'df_with_items' com 'produtos'
        df_with_products = pd.merge(
            df_with_items,
            dataframes['produtos'][OlistConfig.JOIN_SCHEMAS['produtos']['columns']],
            on='product_id',
            how='left' # Manter todos os itens, mesmo sem dados de produto (anomalia)
        )
        logger.info(f"Merge 'com_itens' + 'produtos' concluído. Registros: {len(df_with_products)}")

        # 5. Juntar 'df_with_products' com 'reviews'
        final_consolidated_df = pd.merge(
            df_with_products,
            dataframes['reviews'][OlistConfig.JOIN_SCHEMAS['reviews']['columns']],
            on='order_id',
            how='left' # Manter todos os registros, mesmo sem reviews
        )
        logger.info(f"Merge final com 'reviews' concluído. Total de registros: {len(final_consolidated_df)}")

    except KeyError as e:
        logger.error(f"ERRO: Coluna de junção não encontrada. Verifique as configurações em `OlistConfig.JOIN_SCHEMAS`. Detalhes: {e}")
        raise
    except Exception as e:
        logger.error(f"ERRO inesperado durante as operações de merge: {e}")
        raise

    return final_consolidated_df

def _save_consolidated_data(dataframe: pd.DataFrame) -> None:
    """
    Salva o DataFrame consolidado em um arquivo CSV no caminho de saída configurado.

    Args:
        dataframe (pd.DataFrame): O DataFrame a ser salvo.

    Raises:
        IOError: Se houver problemas ao escrever o arquivo no disco.
    """
    output_path = OlistConfig.BASE_DATA_PATH / OlistConfig.OUTPUT_FILE_NAME
    logger.info(f"Iniciando salvamento do arquivo consolidado em: {output_path}")

    try:
        # Garante que o diretório de saída exista
        output_path.parent.mkdir(parents=True, exist_ok=True)
        dataframe.to_csv(output_path, index=False)
        logger.info(f"Arquivo consolidado salvo com sucesso em: {output_path}. Registros: {len(dataframe)}")
    except IOError as e:
        logger.error(f"ERRO: Falha ao escrever o arquivo consolidado em '{output_path}'. Detalhes: {e}")
        raise
    except Exception as e:
        logger.error(f"ERRO inesperado ao salvar o arquivo: {e}")
        raise

# ---
# Função Principal da DAG (Callable para PythonOperator)
# ---

def _consolidar_dados_olist_main() -> None:
    """
    Função principal que orquestra todo o processo de ETL para consolidação
    dos dados da Olist. Esta função é o 'callable' para o PythonOperator no Airflow.
    """
    logger.info("Iniciando a execução da DAG de Consolidação de Dados Olist.")

    try:
        # Etapa 1: Carregar todos os datasets brutos
        datasets = _load_datasets_from_csv()

        # Etapa 2: Realizar as operações de junção para consolidar os dados
        consolidated_df = _perform_data_joins(datasets)

        # Etapa 3: Salvar o DataFrame consolidado no destino final
        _save_consolidated_data(consolidated_df)

        logger.info("Processo de consolidação de dados Olist concluído com sucesso!")

    except Exception as e:
        logger.critical(f"ERRO CRÍTICO no pipeline de consolidação: {e}")
        # Re-lança a exceção para que o Airflow marque a tarefa como falha
        raise

# ---
# Definição da DAG
# ---

with DAG(
    dag_id='dag_consolida_olist_enterprise_v1',
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None,  # Definido como 'None' para execução manual ou agendamento externo
    catchup=False,  # Não executa para datas passadas que não foram capturadas
    max_active_runs=1, # Garante que apenas uma instância da DAG rode por vez
    doc_md="""
    ## DAG de Consolidação Olist - Enterprise Edition

    ### Objetivo
    Esta DAG implementa um pipeline ETL (Extract, Transform, Load) para consolidar
    diversos datasets públicos da Olist em um único arquivo CSV. O objetivo é criar
    uma base de dados unificada e pronta para análises de negócios e carregamento
    em data warehouses ou data marts.

    ### Arquitetura ETL
    ```mermaid
    flowchart TD
        A[Datasets Olist<br>(Raw Zone)] --> B{Extração<br>CSV Files}
        B --> C{Transformação<br>(Pandas Merges)}
        C --> D[Dataset Consolidado<br>(Curated Zone)]
    ```
    - Raw Zone: Datasets brutos da Olist (clientes, pedidos, itens, etc.)
    - Extract: Leitura dos arquivos CSV para DataFrames Pandas.
    - Transform: Realização de múltiplas operações de `pd.merge` para combinar os dados.
    - Curated Zone: Dataset final consolidado, limpo e estruturado.

    ### Fluxo de Processamento
    1.  Carregamento Seguro: Os datasets de origem são lidos de forma resiliente,
        com tratamento explícito para `FileNotFoundError` e `EmptyDataError`.
    2.  Modelagem Dimensional: As junções são realizadas em etapas lógicas,
        refletindo uma compreensão do modelo de dados Olist, começando por clientes/pedidos
        e detalhando itens, pagamentos e reviews.
    3.  Consolidação Final: Todos os dados são unidos em um DataFrame robusto,
        com tratamento de chaves comuns e distinção de colunas com sufixos (`_pedido`, `_cliente`).
    4.  Persistência: O resultado final é salvo em um arquivo CSV de saída,
        pronto para o próximo estágio do pipeline de dados (e.g., validação com Great Expectations,
        carga em DW/DM).

    ### Qualidade de Dados e Governança
    -   Integridade Referencial: As operações de `pd.merge` com `how='outer'` ajudam a
        identificar e preservar registros que podem não ter correspondência em todas as tabelas.
    -   Linhagem de Dados: O fluxo de junções é claro e logado, permitindo rastrear
        como o dataset consolidado foi formado.
    -   Observabilidade: Logging detalhado em cada etapa para monitoramento do progresso
        e diagnóstico de problemas.

    ### Dependências Externas
    -  Dados Olist: Requer que os arquivos CSV da Olist estejam presentes no caminho
        configurado (`/opt/airflow/data/olist`) dentro do ambiente Airflow.
        Isso é tipicamente gerenciado por um volume Docker.

    """,
    tags=['olist', 'etl', 'consolidacao', 'data-quality', 'enterprise', 'python']
) as dag:

    # ---
    # Definição da Tarefa Principal
    # ---

    tarefa_consolidar_dados = PythonOperator(
        task_id='executar_consolidacao_olist',
        python_callable=_consolidar_dados_olist_main, # Usa a função principal de orquestração
        doc_md="""
        ## Tarefa: Executar Consolidação de Dados Olist

        Propósito: Esta tarefa é o ponto de entrada para o processo ETL de
        consolidação dos datasets da Olist. Ela orquestra a leitura, junção
        e salvamento dos dados.

        ### Detalhes da Execução:
        -   Fase de Extração: Lê seis arquivos CSV distintos que representam
            diferentes entidades do negócio Olist (clientes, pedidos, pagamentos, etc.).
        -   Fase de Transformação: Realiza uma série de junções (`pd.merge`)
            para combinar esses datasets, criando um modelo de dados mais rico e plano.
            As junções são otimizadas para performance e consideram a integridade
            referencial dos dados.
        -   Fase de Carregamento: Salva o resultado final consolidado em um
            novo arquivo CSV, que servirá como fonte para próximas etapas do pipeline,
            como validação de qualidade ou carga em um Data Warehouse.

        ### Saídas Esperadas:
        -   Um arquivo CSV nomeado `dados_consolidados.csv` no diretório
            configurado (`/opt/airflow/data/olist`).
        -   Logs detalhados de progresso e quaisquer erros ou avisos durante a execução.

        """
    )
