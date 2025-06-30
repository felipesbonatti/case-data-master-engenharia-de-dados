#!/usr/bin/env python3

import fastavro
import pandas as pd
import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List

"""
====================================================================================
SCRIPT STANDALONE DE CONVERSAO DE DADOS: CSV PARA AVRO 
====================================================================================

DESCRICAO:
    Este script Python e uma ferramenta independente projetada para converter
    arquivos CSV de dados para o formato Apache Avro. Ele demonstra praticas
    robustas de transformacao de dados para um ambiente enterprise, garantindo
    portabilidade, compressao e compatibilidade com ecossistemas de Big Data.

OBJETIVO PRINCIPAL:
    - Ler dados de um arquivo CSV.
    - Converter esses dados para o formato Apache Avro, usando um schema predefinido.
    - Persistir os dados convertidos em um novo arquivo Avro.

COMPONENTES TECNICOS:
    - `fastavro`: Biblioteca de alta performance para leitura e escrita de arquivos Avro.
    - `pandas`: Para manipulacao e transformacao eficiente de dados tabulares.
    - `os` / `pathlib`: Para operacoes de sistema de arquivos e gerenciamento de diretorios.
    - `logging`: Para registrar o status da execucao e quaisquer erros,
      oferecendo rastreabilidade e depuracao facilitada.

ROBUSTEZ E TRATAMENTO DE ERROS:
    - Verificacao de Arquivo: Confirma a existencia e o tamanho do arquivo CSV de entrada.
    - Saida Controlada: O script termina com um codigo de saida (`sys.exit(1)` para falha, `0` para sucesso)
      que pode ser interpretado por orquestradores (como Airflow) ou scripts shell.
    - Logging Detalhado: Mensagens claras para cada etapa (carregamento, conversao, salvamento).
====================================================================================
"""

# Configuração do logger para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---
# Configuracoes do Script
# Centraliza variaveis configuraveis para facil manutencao.
# ---

class AvroConversionConfig:
    """Configuracoes para a conversao de CSV para Avro."""

    # Caminho base para os arquivos de entrada e saida.
    # Em um ambiente Airflow, este caminho seria `/opt/airflow/data/indicadores`.
    # Para execucao standalone, pode ser ajustado via variavel de ambiente `IPCA_DATA_DIR`.
    BASE_DIR: Path = Path(os.getenv('IPCA_DATA_DIR', 'data/indicadores'))

    # Nome do arquivo CSV de entrada
    INPUT_CSV_FILE_NAME: str = "ipca_coletado.csv"

    # Nome do arquivo Avro de saida
    OUTPUT_AVRO_FILE_NAME: str = "ipca.avro"

    # Definicao do schema Avro para os dados do IPCA.
    # E fundamental que este schema reflita a estrutura e os tipos de dados do DataFrame.
    AVRO_SCHEMA: Dict[str, Any] = {
        "type": "record",
        "name": "IPCA",
        "fields": [
            {"name": "data", "type": "string"}, # Data da coleta do IPCA
            {"name": "valor", "type": "string"} # Valor do IPCA (mantido como string para flexibilidade de numeros decimais)
        ]
    }

# ---
# Funcao Principal de Conversao
# Encapsula a logica principal para reutilizacao e clareza.
# ---

def convert_csv_to_avro() -> None:
    """
    Converte um arquivo CSV de dados do IPCA para o formato Apache Avro.

    Este processo inclui:
    1.  Verificacao da existencia do arquivo CSV de entrada.
    2.  Leitura do CSV para um DataFrame Pandas.
    3.  Conversao do DataFrame para uma lista de dicionarios (registros Avro).
    4.  Escrita dos registros para um arquivo Avro usando o schema definido.

    Raises:
        SystemExit: O script termina com codigo de saida 1 (erro) se a conversao falhar.
        FileNotFoundError: Se o arquivo CSV de entrada nao for encontrado.
        pd.errors.EmptyDataError: Se o arquivo CSV de entrada estiver vazio.
        Exception: Para quaisquer outros erros inesperados durante o processo.
    """
    logger.info("Iniciando o script de conversao de CSV para Avro.")

    # Constroi os caminhos completos dos arquivos de entrada e saida
    input_csv_path: Path = AvroConversionConfig.BASE_DIR / AvroConversionConfig.INPUT_CSV_FILE_NAME
    output_avro_path: Path = AvroConversionConfig.BASE_DIR / AvroConversionConfig.OUTPUT_AVRO_FILE_NAME

    # 1. Verifica a existencia do arquivo CSV de entrada
    logger.info(f"Verificando arquivo CSV de entrada: {input_csv_path}")
    logger.info(f"Lendo CSV de: {input_csv_path}") # Log substituindo print

    if not input_csv_path.exists():
        error_msg = f"ERRO: Arquivo CSV nao encontrado em '{input_csv_path}'."
        logger.critical(error_msg)
        logger.critical("Certifique-se de que a DAG de coleta do IPCA ou o script standalone 'ipca_coleta_standalone.py' foi executado primeiro.")
        sys.exit(1) # Sai com codigo de erro
    
    if input_csv_path.stat().st_size == 0:
        error_msg = f"ERRO: Arquivo CSV encontrado em '{input_csv_path}' esta vazio. Nenhum dado para converter."
        logger.error(error_msg)
        sys.exit(1) # Sai com codigo de erro

    # 2. Le o CSV para um DataFrame Pandas
    try:
        df_ipca = pd.read_csv(input_csv_path)
        logger.info(f"CSV lido com sucesso. Total de registros: {len(df_ipca)}.")
        if df_ipca.empty:
            logger.warning("O DataFrame lido do CSV esta vazio. O arquivo Avro resultante tambem estara vazio.")
    except pd.errors.EmptyDataError:
        error_msg = f"ERRO: O arquivo CSV '{input_csv_path}' esta vazio. Nao ha dados para converter para Avro."
        logger.error(error_msg)
        sys.exit(1)
    except Exception as e:
        error_msg = f"ERRO INESPERADO ao ler o arquivo CSV '{input_csv_path}': {e}"
        logger.critical(error_msg, exc_info=True)
        sys.exit(1)

    # 3. Converte o DataFrame para uma lista de dicionarios (registros Avro)
    # E importante garantir que os nomes das colunas do DataFrame correspondam aos nomes dos campos no schema Avro.
    # O Fastavro espera uma lista de dicionarios, onde cada dicionario e um registro.
    records: List[Dict[str, Any]] = df_ipca.to_dict(orient="records")
    logger.info(f"DataFrame convertido para {len(records)} registros Avro.")

    # 4. Escreve os registros para um arquivo Avro
    logger.info(f"Convertendo registros para Avro e salvando em: {output_avro_path}")
    logger.info("Convertendo registros para Avro...") # Log substituindo print
    
    try:
        # Garante que o diretorio de saida para o arquivo Avro exista
        output_avro_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_avro_path, "wb") as avro_file:
            fastavro.writer(avro_file, AvroConversionConfig.AVRO_SCHEMA, records)
        logger.info(f"Conversao concluida. Arquivo Avro salvo com sucesso em: {output_avro_path}")
        logger.info(f"Conversao concluida. Arquivo salvo em: {output_avro_path}") # Log substituindo print
    except Exception as e:
        error_msg = f"ERRO INESPERADO ao escrever o arquivo Avro em '{output_avro_path}': {e}"
        logger.critical(error_msg, exc_info=True)
        sys.exit(1)

# ---
# Ponto de Entrada do Script
# ---

if __name__ == "__main__":
    # Define o caminho base dos dados para execucao standalone.

    try:
        convert_csv_to_avro()
    except Exception:
        # Captura qualquer excecao nao tratada na funcao principal para sair com codigo de erro
        logger.critical("O script de conversao para Avro terminou com um erro critico.")
        sys.exit(1) # Garante que o script saia com erro se algo inesperado acontecer
