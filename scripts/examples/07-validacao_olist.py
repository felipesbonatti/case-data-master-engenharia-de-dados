#!/usr/bin/env python3

import great_expectations as ge
import sys
import os # Necessario para os.getenv
import logging
from pathlib import Path
from typing import Dict, Any

"""
====================================================================================
SCRIPT STANDALONE DE VALIDACAO DE DADOS COM GREAT EXPECTATIONS
====================================================================================

DESCRICAO:
    Este script Python e uma ferramenta independente projetada para realizar validacoes de
    qualidade de dados no dataset consolidado (`dados_consolidados.csv`), utilizando
    a biblioteca Great Expectations. Ele simula um Quality Gate pre-carga,
    garantindo que os dados atendem a um conjunto de expectativas de qualidade
    antes de serem promovidos para estagios mais criticos do pipeline, como um Data Mart.

OBJETIVO PRINCIPAL:
    - Carregar um dataset de dados consolidados.
    - Definir um conjunto formal de expectativas de qualidade de dados.
    - Executar as validacoes e reportar o resultado de forma clara.
    - Servir como um ponto de controle automatizado para a qualidade dos dados.

COMPONENTES TECNICOS:
    - `great_expectations`: Biblioteca principal para definicao e execucao de expectativas.
    - `pandas` (integrado via GE): Para manipulacao interna do DataFrame.
    - `pathlib`: Para manipulacao de caminhos de arquivo de forma segura e idiomatica.
    - `logging`: Para registrar o status da execucao e quaisquer erros,
      oferecendo rastreabilidade e depuracao facilitada.

EXPECTATIVAS IMPLEMENTADAS (EXEMPLOS):
    - Integridade de Chave Primaria: `order_id` nao deve conter valores nulos.
    - Consistencia de Dominio: `order_status` deve estar restrito a um conjunto
      predefinido de valores validos.

ROBUSTEZ E TRATAMENTO DE ERROS:
    - Verificacao de Arquivo: Confirma a existencia do arquivo de dados antes do carregamento.
    - Saida Controlada: O script termina com um codigo de saida (`sys.exit(1)` para falha, `0` para sucesso)
      que pode ser interpretado por orquestradores (como Airflow) ou scripts shell.
    - Logging Detalhado: Mensagens claras para cada etapa (carregamento, definicao, execucao, resultado).
====================================================================================
"""

# Configuração do logger para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---
# Configuracoes do Script
# Centraliza variaveis configuraveis para facil manutencao.
# ---

class ValidationConfig:
    """Configuracoes para o script de validacao de dados."""
    
    # Caminho para os dados consolidados.
    # Em um ambiente de Airflow, este caminho seria `/opt/airflow/data/olist/dados_consolidados.csv`.
    # Para execucao standalone, pode ser ajustado via variavel de ambiente `DATA_PATH_TO_VALIDATE`.
    DATA_PATH: Path = Path(os.getenv('DATA_PATH_TO_VALIDATE', 'data/olist/dados_consolidados.csv'))

    # Expectativas a serem aplicadas.
    # Para demonstracao, estao hardcoded, mas em um cenario real seriam carregadas de um arquivo JSON
    # ou de um Data Catalog gerenciado pelo Great Expectations.
    EXPECTATIONS_DEFINITIONS: Dict[str, Dict[str, Any]] = {
        "order_id_not_null": {
            "column": "order_id",
            "expectation_type": "expect_column_values_to_not_be_null",
            "description": "order_id nao deve conter valores nulos (chave primaria e identificador unico de pedido)."
        },
        "order_status_valid_set": {
            "column": "order_status",
            "expectation_type": "expect_column_values_to_be_in_set",
            "value_set": ["delivered", "shipped", "canceled", "invoiced", "processing", "approved", "unavailable", "created"],
            "description": "order_status deve conter apenas valores reconhecidos e validos para o ciclo de vida do pedido."
        },
        "price_not_negative": {
            "column": "price",
            "expectation_type": "expect_column_values_to_be_between",
            "min_value": 0,
            "max_value": None, # Sem limite superior
            "description": "price (preco do item) nao deve ser negativo."
        },
        "freight_value_positive": {
            "column": "freight_value",
            "expectation_type": "expect_column_values_to_be_between",
            "min_value": 0,
            "max_value": None,
            "description": "freight_value (valor do frete) nao deve ser negativo."
        }
    }

# ---
# Funcao Principal de Validacao
# Encapsula a logica principal para reutilizacao e clareza.
# ---

def validate_consolidated_data() -> None:
    """
    Executa o processo de validacao de qualidade de dados no dataset consolidado
    usando Great Expectations.

    Este processo inclui:
    1.  Carregamento do dataset a partir do caminho configurado.
    2.  Definicao e aplicacao de um conjunto de expectativas.
    3.  Execucao das validacoes e obtencao do resultado.
    4.  Relatorio do status final e codigo de saida.

    Raises:
        SystemExit: O script termina com codigo de saida 1 (erro) se a validacao falhar,
                    ou 0 (sucesso) se todas as expectativas forem atendidas.
        FileNotFoundError: Se o arquivo de dados consolidado nao for encontrado.
        Exception: Para outros erros inesperados durante o processo.
    """
    logger.info("Iniciando o script de validacao de dados com Great Expectations.")

    # 1. Carregamento do dataset
    data_file_path = ValidationConfig.DATA_PATH
    logger.info(f"Carregando dados de: {data_file_path}...")
    
    try:
        df = ge.read_csv(data_file_path)
        logger.info(f"Dataset carregado com sucesso. Total de registros: {len(df)}.")
    except FileNotFoundError:
        error_msg = f"ERRO: Arquivo nao encontrado em '{data_file_path}'."
        logger.critical(error_msg)
        logger.critical("Certifique-se de que a DAG 'dag_consolida_olist_enterprise_v1' foi executada primeiro e o arquivo foi gerado.")
        sys.exit(1) # Sai com codigo de erro
    except Exception as e:
        error_msg = f"ERRO INESPERADO ao carregar o arquivo '{data_file_path}': {e}"
        logger.critical(error_msg, exc_info=True)
        sys.exit(1) # Sai com codigo de erro

    # 2. Definicao e aplicacao das expectativas
    logger.info("Definindo e aplicando expectativas de qualidade dos dados...")
    

    for key, exp_def in ValidationConfig.EXPECTATIONS_DEFINITIONS.items():
        try:
            # Chama a funcao de expectativa dinamicamente
            expectation_func = getattr(df, exp_def["expectation_type"])
            
            # Constroi os argumentos da expectativa, excluindo 'expectation_type' e 'description'
            args = {k: v for k, v in exp_def.items() if k not in ["expectation_type", "description"]}
            args["result_format"] = "SUMMARY" # Formato de resultado padrao para conciseness
            
            result = expectation_func(**args)
            
            if result.success:
                logger.info(f"Regra '{key}': '{exp_def['description']}' - PASSED")
            else:
                logger.warning(f"Regra '{key}': '{exp_def['description']}' - FAILED. Detalhes: {result.results[0].get('unexpected_count', 'N/A')} inesperados.")

        except AttributeError:
            logger.error(f"Expectation type '{exp_def['expectation_type']}' para regra '{key}' nao encontrada no Great Expectations.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Erro ao definir/aplicar expectativa '{key}': {e}", exc_info=True)
            sys.exit(1)


    # 3. Execucao das validacoes
    logger.info("Executando validacao final com base nas regras definidas...")
    validation_result = df.validate()

    # 4. Relatorio do status final
    logger.info("Validacao finalizada. Exibindo resultado resumido.")
    logger.info("Validacao finalizada. Resultado resumido:")
    logger.info(validation_result) # O Great Expectations tem uma otima representacao em string


    # 5. Saida controlada
    if not validation_result["success"]:
        final_message = "VALIDACAO FALHOU: Uma ou mais regras de qualidade de dados foram violadas. Reveja os dados e o relatorio detalhado."
        logger.error(final_message)
        sys.exit(1) # Sai com codigo de erro para indicar falha
    else:
        final_message = "VALIDACAO APROVADA: Todos os testes de qualidade passaram com sucesso. Os dados estao prontos para o proximo estagio."
        logger.info(final_message)
        sys.exit(0) # Sai com codigo de sucesso

# ---
# Ponto de Entrada do Script
# ---

if __name__ == "__main__":
    # Define o caminho do arquivo de dados para execucao standalone.

    try:
        validate_consolidated_data()
    except Exception:
        # Captura qualquer excecao nao tratada na funcao principal para sair com codigo de erro
        logger.critical("O script de validacao de dados terminou com um erro critico.")
        sys.exit(1) # Garante que o script saia com erro se algo inesperado acontecer
