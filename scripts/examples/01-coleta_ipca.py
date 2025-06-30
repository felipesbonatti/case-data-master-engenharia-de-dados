import requests
import pandas as pd
import os
import logging
from pathlib import Path
from datetime import datetime 

"""
====================================================================================
SCRIPT STANDALONE DE COLETA DE DADOS: IPCA (BANCO CENTRAL) 
====================================================================================

DESCRICAO:
    Este script Python e uma ferramenta independente projetada para coletar
    dados historicos do Indice Nacional de Precos ao Consumidor Amplo (IPCA)
    diretamente da API publica do Banco Central do Brasil (Serie SGS 433).
    Ele demonstra praticas robustas de coleta de dados para um ambiente enterprise,
    incluindo tratamento de erros de rede e persistencia segura em disco.

OBJETIVO PRINCIPAL:
    - Extrair dados do IPCA de uma fonte externa confiavel.
    - Transformar os dados brutos (JSON) em um formato tabular (DataFrame Pandas).
    - Persistir os dados coletados em um arquivo CSV, pronto para consumo por
      pipelines de dados a jusante (e.g., Data Lake, Data Mart).

FONTE DE DADOS:
    - Banco Central do Brasil (Serie Historica SGS 433).

COMPONENTES TECNICOS:
    - `requests`: Para realizar requisicoes HTTP seguras a API.
    - `pandas`: Para manipulacao e transformacao eficiente dos dados.
    - `os` / `pathlib`: Para operacoes de sistema de arquivos e gerenciamento de diretorios.
    - `logging`: Para registrar o status da execucao e quaisquer erros,
      oferecendo rastreabilidade e depuracao facilitada.

ROBUSTEZ E TRATAMENTO DE ERROS:
    - Validacao de Resposta HTTP: `response.raise_for_status()` verifica o status
      da requisicao HTTP, levantando um erro para codigos de status invalidos (e.g., 4xx, 5xx).
    - Timeout Configuravel: Um limite de tempo e imposto a requisicao para evitar
      bloqueios em caso de lentidao ou indisponibilidade da API.
    - Tratamento de Excecoes Abrangente: Captura e loga diversos tipos de erros
      (rede, JSON, I/O), fornecendo mensagens claras para diagnostico.
    - Criacao de Diretorios: Garante que o diretorio de saida exista antes de tentar
      salvar o arquivo, prevenindo erros de I/O.
====================================================================================
"""

# Configuração do logger para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---
# Configuracoes do Script
# Centraliza variaveis configuraveis para facil manutencao
# ---

class IPCAConfig:
    """Configuracoes para a coleta de dados do IPCA."""
    
    # URL da API publica do Banco Central para o IPCA (Serie SGS 433)
    API_URL: str = "https://api.bcb.gov.br/dados/serie/bcdata.sgs.433/dados?formato=json"
    
    # Timeout para a requisicao HTTP (em segundos)
    REQUEST_TIMEOUT: int = 15 # Aumentado para 15s para maior tolerancia a rede

    # Diretorio de saida para o arquivo CSV.
    # Em um ambiente Airflow, este caminho seria /opt/airflow/data/indicadores.
    # Para execucao standalone, pode ser definido via variavel de ambiente IPCA_OUTPUT_DIR
    # ou ajustado diretamente.
    OUTPUT_BASE_DIR: Path = Path(os.getenv('IPCA_OUTPUT_DIR', 'data/indicadores'))
    
    # Nome do arquivo de saida
    OUTPUT_FILE_NAME: str = "ipca_standalone.csv"

# ---
# Funcao Principal de Coleta
# Encapsula a logica principal para reutilizacao e clareza
# ---

def collect_ipca_data() -> None:
    """
    Coleta dados historicos do IPCA da API do Banco Central do Brasil,
    processa-os e salva-os em um arquivo CSV.

    Este processo inclui:
    1.  Verificacao e criacao do diretorio de saida.
    2.  Realizacao da requisicao HTTP a API.
    3.  Tratamento de erros de rede e resposta HTTP.
    4.  Conversao da resposta JSON em um DataFrame Pandas.
    5.  Persistencia do DataFrame em um arquivo CSV.

    Raises:
        requests.exceptions.RequestException: Para erros relacionados a requisicao HTTP.
        json.JSONDecodeError: Se a resposta da API nao for um JSON valido.
        pd.errors.EmptyDataError: Se os dados coletados resultarem em um DataFrame vazio.
        OSError: Para problemas de sistema de arquivos ao criar diretorios ou salvar o arquivo.
        Exception: Para quaisquer outros erros inesperados.
    """
    logger.info("Iniciando o script de coleta de dados do IPCA.")

    # 1. Preparar o diretorio de saida
    output_directory = IPCAConfig.OUTPUT_BASE_DIR
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
        logger.info(f"Diretorio de saida '{output_directory}' verificado/criado com sucesso.")
    except OSError as e:
        logger.critical(f"ERRO CRITICO: Falha ao criar o diretorio de saida '{output_directory}': {e}", exc_info=True)
        # Nao usar print() para consistencia com logging
        raise # Re-lanca para parar a execucao

    output_file_path = output_directory / IPCAConfig.OUTPUT_FILE_NAME
    logger.info(f"O arquivo de saida sera salvo em: {output_file_path}")

    # 2. Realizar a requisicao HTTP
    logger.info(f"Coletando dados do IPCA de: {IPCAConfig.API_URL}")
    logger.info(f"Coletando dados do IPCA de: {IPCAConfig.API_URL}") # Duplicado por um print anterior, mas mantido para log

    try:
        response = requests.get(IPCAConfig.API_URL, timeout=IPCAConfig.REQUEST_TIMEOUT)
        response.raise_for_status() # Levanta um HTTPError para 4xx/5xx responses

        # 3. Processar a resposta JSON
        dados_ipca = response.json()
        
        if not dados_ipca:
            logger.warning("A API retornou uma lista vazia de dados IPCA. O arquivo de saida pode estar vazio.")
            # Nao usar print()
            
        # 4. Transformar os dados em DataFrame
        df_ipca = pd.DataFrame(dados_ipca)
        logger.info(f"Dados do IPCA transformados em DataFrame. Registros: {len(df_ipca)}")

        # 5. Salvar como CSV
        df_ipca.to_csv(output_file_path, index=False, encoding='utf-8')
        logger.info(f"Dados do IPCA salvos com sucesso em: {output_file_path}. Total de registros: {len(df_ipca)}.")
        logger.info(f"Dados do IPCA salvos com sucesso em: {output_file_path}") # Duplicado por um print anterior, mas mantido para log

    except requests.exceptions.Timeout:
        logger.error(f"ERRO DE CONEXAO: A requisicao ao Banco Central excedeu o tempo limite de {IPCAConfig.REQUEST_TIMEOUT} segundos.", exc_info=True)
        # Nao usar print()
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"ERRO DE REQUISICAO HTTP ao coletar dados do IPCA: {e}", exc_info=True)
        # Nao usar print()
        raise
    except json.JSONDecodeError:
        logger.error(f"ERRO DE DADOS: A resposta da API do Banco Central nao e um JSON valido. Resposta: {response.text[:200]}...", exc_info=True)
        # Nao usar print()
        raise
    except pd.errors.EmptyDataError:
        logger.warning(f"AVISO: O DataFrame do IPCA esta vazio. Nenhum dado sera salvo no CSV.")
        # Nao usar print()
        # Nao re-lanca EmptyDataError para permitir que o script finalize sem falha critica.
    except Exception as e:
        logger.critical(f"ERRO INESPERADO ao coletar dados do IPCA: {e}", exc_info=True)
        # Nao usar print()
        raise

# ---
# Ponto de Entrada do Script
# ---

if __name__ == "__main__":
    # Define o diretorio de saida para execucao standalone.

    try:
        collect_ipca_data()
    except Exception:
        # Captura qualquer excecao nao tratada na funcao principal para sair com codigo de erro
        logger.critical("O script de coleta do IPCA terminou com um erro critico.")
        sys.exit(1) # Sai com codigo de erro para indicar falha
