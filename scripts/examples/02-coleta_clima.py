import requests
import pandas as pd
import os
import logging
from pathlib import Path
from datetime import datetime
import json # Importar para lidar com erros de JSON na resposta da API

"""
====================================================================================
SCRIPT STANDALONE DE COLETA DE DADOS: CLIMA (OPENWEATHERMAP) 
====================================================================================

DESCRICAO:
    Este script Python e uma ferramenta independente para coletar dados climaticos
    atuais de multiplas cidades brasileiras utilizando a API publica da OpenWeatherMap.
    Ele demonstra as melhores praticas de coleta de dados de APIs externas em um
    contexto enterprise, incluindo tratamento seguro de chaves de API (com placeholder
    para demonstracao) e persistencia eficiente dos dados.

OBJETIVO PRINCIPAL:
    - Extrair informacoes climaticas (temperatura, condicao, etc.) de cidades-alvo.
    - Transformar os dados brutos (JSON) em um formato tabular (DataFrame Pandas).
    - Persistir os dados coletados em um arquivo CSV, pronto para consumo por
      pipelines de dados a jusante (e.g., Data Lake, Data Mart).

FONTE DE DADOS:
    - OpenWeatherMap API (Current Weather Data).

COMPONENTES TECNICOS:
    - `requests`: Para realizar requisicoes HTTP seguras e eficientes a API.
    - `pandas`: Para manipulacao e transformacao dos dados coletados.
    - `os` / `pathlib`: Para operacoes de sistema de arquivos, garantindo
      a criacao de diretorios e o salvamento do arquivo.
    - `logging`: Para registrar o status da execucao e quaisquer erros,
      oferecendo rastreabilidade e depuracao facilitada.

SEGURANCA (PARA AMBIENTE DE DEMONSTRACAO):
    - A `API_KEY` e um placeholder neste script. Em um ambiente de producao,
      ela seria obtida de forma segura de um Vault de Segredos
      (como demonstrado nas DAGs do Airflow), nunca hardcoded.

ROBUSTEZ E TRATAMENTO DE ERROS:
    - Validacao de Resposta HTTP: `response.raise_for_status()` verifica o status
      da requisicao HTTP, levantando um erro para codigos de status invalidos.
    - Timeout Configuravel: Um limite de tempo e imposto a requisicao para evitar
      bloqueios em caso de lentidao ou indisponibilidade da API.
    - Tratamento de Excecoes Abrangente: Captura e loga diversos tipos de erros
      (rede, JSON, I/O), fornecendo mensagens claras para diagnostico.
    - Criacao de Diretorios: Garante que o diretorio de saida exista antes de tentar
      salvar o arquivo.
====================================================================================
"""

# Configuração do logger para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---
# Configuracoes do Script
# Centraliza variaveis configuraveis para facil manutencao e ajuste de ambiente.
# ---

class WeatherConfig:
    """Configuracoes para a coleta de dados climaticos."""
    
    # === CHAVE DA API (Preencher apenas para demonstracao local) ===
    # EM PRODUCAO: NUNCA HARDCODE UMA CHAVE DE API AQUI!
    # Obtenha-a de um Vault de Segredos (e.g., Vault, AWS Secrets Manager, Azure Key Vault).
    API_KEY: str = os.getenv("OPENWEATHER_API_KEY", "SUA_CHAVE_API_OPENWEATHERMAP_AQUI_OU_VIA_ENV")

    # URL base da API OpenWeatherMap para dados climaticos atuais
    API_BASE_URL: str = "https://api.openweathermap.org/data/2.5/weather"
    
    # Timeout para a requisicao HTTP (em segundos)
    REQUEST_TIMEOUT: int = 15 # Tempo limite para cada requisicao de cidade

    # Cidades-alvo da coleta com seus respectivos codigos da OpenWeatherMap
    CITIES_TARGET: dict[str, int] = {
        "São Paulo": 3448439,
        "Rio de Janeiro": 3451190,
        "Belo Horizonte": 3470127,
        "Porto Alegre": 3452925,
        "Recife": 3390760
    }

    # Diretorio de saida para o arquivo CSV.
    # E CRITICO que este caminho seja ajustado para o ambiente de execucao.
    # Em um ambiente Airflow, isso seria '/opt/airflow/data/clima'.
    # Usai uma variavel de ambiente como um fallback mais robusto para a localizacao.
    OUTPUT_BASE_DIR: Path = Path(os.getenv('WEATHER_OUTPUT_DIR', 'data/clima'))
    
    # Nome do arquivo de saida
    OUTPUT_FILE_NAME: str = "clima_standalone.csv"

# ---
# Funcao Principal de Coleta
# Encapsula a logica principal para reutilizacao e clareza.
# ---

def collect_weather_data() -> None:
    """
    Coleta dados climaticos atuais de cidades predefinidas usando a API da OpenWeatherMap,
    processa-os e salva-os em um arquivo CSV.

    Este processo inclui:
    1.  Verificacao da chave de API.
    2.  Preparacao do diretorio de saida.
    3.  Loop para coletar dados de cada cidade com tratamento de erros por cidade.
    4.  Conversao dos dados coletados em um DataFrame Pandas.
    5.  Persistencia do DataFrame em um arquivo CSV.

    Raises:
        ValueError: Se a API_KEY nao for fornecida ou for o placeholder.
        requests.exceptions.RequestException: Para erros relacionados a requisicao HTTP.
        json.JSONDecodeError: Se a resposta da API nao for um JSON valido.
        OSError: Para problemas de sistema de arquivos.
        Exception: Para quaisquer outros erros inesperados.
    """
    logger.info("Iniciando o script de coleta de dados climaticos.")

    # 1. Verificacao da chave de API (para ambiente de demonstracao)
    if "SUA_CHAVE_API_OPENWEATHERMAP_AQUI" in WeatherConfig.API_KEY or not WeatherConfig.API_KEY.strip():
        error_msg = "ERRO: A API_KEY da OpenWeatherMap nao foi substituida ou esta vazia. Por favor, forneca uma chave valida."
        logger.critical(error_msg)
        # Nao usar print() para consistencia de logging
        raise ValueError(error_msg)
    else:
        logger.info("API_KEY da OpenWeatherMap carregada (para fins de demonstracao).")

    # 2. Preparar o diretorio de saida
    output_directory = WeatherConfig.OUTPUT_BASE_DIR
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
        logger.info(f"Diretorio de saida '{output_directory}' verificado/criado com sucesso.")
    except OSError as e:
        logger.critical(f"ERRO CRITICO: Falha ao criar o diretorio de saida '{output_directory}': {e}", exc_info=True)
        # Nao usar print()
        raise # Re-lanca para parar a execucao

    output_file_path = output_directory / WeatherConfig.OUTPUT_FILE_NAME
    logger.info(f"O arquivo de saida sera salvo em: {output_file_path}")

    all_cities_data = [] # Lista para armazenar dados de todas as cidades
    logger.info("Iniciando coleta de dados climaticos...") 

    # 3. Loop principal de coleta por cidade
    for city_name, city_code in WeatherConfig.CITIES_TARGET.items():
        logger.info(f"-> Coletando dados para {city_name} (codigo: {city_code})...")
        # Nao usar print()
        
        try:
            url = (
                f"{WeatherConfig.API_BASE_URL}?"
                f"id={city_code}&appid={WeatherConfig.API_KEY}&lang=pt_br&units=metric"
            )
            response = requests.get(url, timeout=WeatherConfig.REQUEST_TIMEOUT)
            response.raise_for_status() # Levanta um HTTPError para 4xx/5xx responses
            
            weather_data = response.json()
            
            all_cities_data.append({
                "cidade": city_name,
                "temperatura": weather_data["main"]["temp"],
                "condicao": weather_data["weather"][0]["description"],
                "umidade": weather_data["main"]["humidity"],
                "pressao": weather_data["main"]["pressure"],
                "velocidade_vento": weather_data["wind"]["speed"],
                "data_coleta": datetime.now().isoformat() # Adiciona timestamp da coleta
            })
            logger.info(f"-> Dados para {city_name} coletados com sucesso.")

        except requests.exceptions.Timeout:
            logger.error(f"-> ERRO DE CONEXAO para {city_name}: Excedeu o tempo limite de {WeatherConfig.REQUEST_TIMEOUT} segundos.", exc_info=True)
            # Nao usar print()
        except requests.exceptions.RequestException as e:
            logger.error(f"-> ERRO HTTP para {city_name}: {e}", exc_info=True)
            # Nao usar print()
        except json.JSONDecodeError:
            logger.error(f"-> ERRO DE DADOS para {city_name}: Resposta da API invalida (nao e JSON).", exc_info=True)
            # Nao usar print()
        except KeyError as e:
            logger.error(f"-> ERRO DE PARSE para {city_name}: Estrutura de dados da API inesperada. Chave ausente: {e}", exc_info=True)
            # Nao usar print()
        except Exception as e:
            logger.critical(f"-> ERRO INESPERADO ao coletar para {city_name}: {e}", exc_info=True)
            # Nao usar print()

    # 4. Convertendo os dados coletados para DataFrame
    if all_cities_data:
        df_clima = pd.DataFrame(all_cities_data)
        logger.info(f"Dados climaticos de {len(df_clima)} cidades transformados em DataFrame.")

        # 5. Salvando em disco
        try:
            df_clima.to_csv(output_file_path, index=False, encoding='utf-8')
            logger.info(f"Dados climaticos salvos com sucesso em: {output_file_path}. Registros: {len(df_clima)}.")
            # Nao usar print()
        except OSError as e:
            logger.critical(f"ERRO CRITICO: Falha ao salvar o arquivo CSV '{output_file_path}': {e}", exc_info=True)
            # Nao usar print()
            raise # Re-lanca para parar a execucao
        except Exception as e:
            logger.critical(f"ERRO INESPERADO ao salvar dados climaticos: {e}", exc_info=True)
            # Nao usar print()
            raise
    else:
        logger.warning("Nenhum dado climatico foi coletado com sucesso. O arquivo CSV nao sera gerado.")
        # Nao usar print()

# ---
# Ponto de Entrada do Script
# ---

if __name__ == "__main__":
    # Define o diretorio de saida para execucao standalone.

    try:
        collect_weather_data()
    except Exception:
        # Captura qualquer excecao nao tratada na funcao principal para sair com codigo de erro
        logger.critical("O script de coleta de dados climaticos terminou com um erro critico.")
        import sys
        sys.exit(1) # Sai com codigo de erro para indicar falha
