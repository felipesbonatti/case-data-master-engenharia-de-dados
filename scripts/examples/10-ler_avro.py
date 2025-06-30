import fastavro
import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List

# Configuração do logger 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

"""
====================================================================================
SCRIPT STANDALONE DE LEITURA DE DADOS: AVRO 
====================================================================================

DESCRICAO:
    Este script Python e uma ferramenta independente projetada para ler
    dados gravados no formato Apache Avro. Ele demonstra a capacidade de
    consumir dados em um formato otimizado para Data Lakes e pipelines
    de Big Data, garantindo integridade de schema e eficiencia na leitura.

OBJETIVO PRINCIPAL:
    - Ler dados de um arquivo Avro especificado.
    - Exibir uma amostra dos registros lidos para verificacao.
    - Validar a integridade basica da leitura do arquivo Avro.

COMPONENTES TECNICOS:
    - `fastavro`: Biblioteca de alta performance para leitura de arquivos Avro.
    - `os` / `pathlib`: Para operacoes de sistema de arquivos e gerenciamento de caminhos.
    - `logging`: Para registrar o status da execucao e quaisquer erros,
      oferecendo rastreabilidade e depuracao facilitada.

ROBUSTEZ E TRATAMENTO DE ERROS:
    - Verificacao de Arquivo: Confirma a existencia do arquivo Avro de entrada.
    - Saida Controlada: O script termina com um codigo de saida (`sys.exit(1)` para falha, `0` para sucesso)
      que pode ser interpretado por orquestradores (como Airflow) ou scripts shell.
    - Logging Detalhado: Mensagens claras para cada etapa (leitura, processamento, resultado).
====================================================================================
"""

# ---
# Configuracoes do Script
# Centraliza variaveis configuraveis para facil manutencao.
# ---

class AvroReaderConfig:
    """Configuracoes para a leitura de arquivos Avro."""

    # Caminho para o arquivo Avro de entrada.
    # Em um ambiente Airflow, este caminho seria `/opt/airflow/data/indicadores/ipca.avro`.
    # Para execucao standalone, pode ser ajustado via variavel de ambiente `IPCA_AVRO_PATH`.
    AVRO_FILE_PATH: Path = Path(os.getenv('IPCA_AVRO_PATH', 'data/indicadores/ipca.avro'))

    # Numero de registros de amostra para exibir.
    SAMPLE_RECORDS_COUNT: int = 3

# ---
# Funcao Principal de Leitura
# Encapsula a logica principal para reutilizacao e clareza.
# ---

def read_avro_data() -> None:
    """
    Le dados de um arquivo Apache Avro e exibe uma amostra dos registros.

    Este processo inclui:
    1.  Verificacao da existencia do arquivo Avro de entrada.
    2.  Leitura dos registros Avro usando o `fastavro.reader`.
    3.  Exibicao de uma amostra dos registros e contagem total.

    Raises:
        SystemExit: O script termina com codigo de saida 1 (erro) se a leitura falhar.
        FileNotFoundError: Se o arquivo Avro de entrada nao for encontrado.
        Exception: Para quaisquer outros erros inesperados durante o processo.
    """
    logger.info("Iniciando o script de leitura de dados Avro.")

    avro_file_path: Path = AvroReaderConfig.AVRO_FILE_PATH
    logger.info(f"Lendo arquivo Avro de: {avro_file_path}")

    if not avro_file_path.exists():
        error_msg = f"ERRO: Arquivo Avro nao encontrado em '{avro_file_path}'. " \
                    "Execute o script de escrita Avro primeiro (e.g., '09-escrever_avro.py')."
        logger.critical(error_msg)
        sys.exit(1)

    # Leitura dos registros Avro com tratamento de erro
    try:
        with open(avro_file_path, "rb") as avro_file:
            reader = fastavro.reader(avro_file)
            registros = list(reader)

        logger.info(f"Total de registros lidos: {len(registros)}")
        logger.info(f"Amostra de registros (os {AvroReaderConfig.SAMPLE_RECORDS_COUNT} primeiros):")
        for i, r in enumerate(registros[:AvroReaderConfig.SAMPLE_RECORDS_COUNT]):
            logger.info(f"  - Registro {i+1}: {r}")

        logger.info("Leitura do arquivo Avro concluida com sucesso.")
        sys.exit(0)

    except FileNotFoundError: # Captura FileNotFoundError explicitamente, embora ja tratada acima
        error_msg = f"ERRO: Arquivo Avro nao encontrado em '{avro_file_path}'. Isso nao deveria acontecer apos a verificacao inicial."
        logger.critical(error_msg)
        sys.exit(1)
    except Exception as e:
        error_msg = f"ERRO ao ler o arquivo Avro: {e}"
        logger.critical(error_msg, exc_info=True)
        sys.exit(1)

# ---
# Ponto de Entrada do Script
# ---

if __name__ == "__main__":
    # Define o caminho do arquivo Avro para execucao standalone.

    try:
        read_avro_data()
    except SystemExit: # Captura SystemExit se for levantado por sys.exit()
        raise # Re-lanca para manter o comportamento de saida
    except Exception: # Captura qualquer outra excecao inesperada
        logger.critical("O script de leitura Avro terminou com um erro critico.")
        sys.exit(1)
