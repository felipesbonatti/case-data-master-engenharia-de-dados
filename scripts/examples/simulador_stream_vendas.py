#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import time
import sys
import os
import logging
from queue import Queue
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

"""
====================================================================================
SIMULADOR DE STREAM DE VENDAS - DEMONSTRACAO 
====================================================================================

DESCRICAO:
    Este script Python simula um stream de dados de vendas em tempo real,
    lendo eventos de um arquivo CSV local (`dados_consolidados.csv`) e
    enviando-os para uma fila em memoria (`Queue`). Ele serve como uma fonte
    de dados para demonstracoes de processamento de stream, permitindo que
    outros processadores (como o `processador_stream_vendas.py`) consumam
    esses eventos de forma continua.

OBJETIVO PRINCIPAL:
    - Simular a geracao de eventos de vendas em tempo real a partir de um dataset estatico.
    - Publicar eventos em uma fila Python `Queue` para consumo por um processador.
    - Demonstrar a preparacao de dados para um pipeline de streaming.

ARQUITETURA DO SIMULADOR:
    Dataset CSV (dados_consolidados.csv) --> Fila de Eventos (Python Queue)
    - Eventos Enfileirados

COMPONENTES TECNICOS:
    - `csv`: Para leitura eficiente de arquivos CSV.
    - `queue.Queue`: Uma fila thread-safe para comunicacao entre o simulador e o processador.
    - `datetime`: Para adicionar timestamps de evento.
    - `time`: Para simular delays de streaming.
    - `pathlib.Path`: Para gerenciamento robusto de caminhos de arquivo.

SEGURANCA E ROBUSTEZ (DO SIMULADOR):
    - Validacao de Arquivos: Verifica a existencia e permissoes de leitura do arquivo CSV.
    - Validacao de Colunas: Garante que as colunas essenciais (`customer_state`, `price`) existam no CSV.
    - Tratamento de Dados: Converte tipos de dados e trata valores ausentes nas linhas do CSV.
    - Limite de Eventos: Permite controlar o volume de dados simulados.
    - Delay Configuravel: Simula um fluxo de dados com espacamento de tempo realista.

INSTRUCOES DE USO:
    1.  Arquivo de Origem: Certifique-se de que o arquivo `dados_consolidados.csv`
        esta disponivel no caminho configurado (`SimuladorConfig.CSV_PATH`).
        Este arquivo e geralmente gerado por uma DAG de consolidacao de dados.
    2.  Execucao: Execute este script em um terminal separado. Ele continuara
        enviando eventos para a fila.
        Ex: `python3 [caminho_para_este_script]/simulador_stream_vendas.py`
    3.  Consumo: Outro script (e.g., `processador_stream_vendas.py`) pode entao
        importar `fila_eventos` e comecar a consumir os dados.
====================================================================================
"""

# Configuração de Logging para o simulador
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d')
logger = logging.getLogger(__name__)

# Fila compartilhada para eventos de vendas.
# Esta fila sera importada por outros scripts que consomem o stream.
fila_eventos: Queue[Dict[str, Any]] = Queue()

# ---
# CONFIGURACOES DO SIMULADOR
# ---
class SimuladorConfig:
    """Centraliza as configuracoes para o simulador de stream de vendas."""

    # Caminho base do AIRFLOW_HOME, usado para resolver caminhos de dados.
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    
    # Caminho completo para o arquivo CSV de origem dos dados.
    CSV_PATH: Path = AIRFLOW_HOME / 'data' / 'olist' / 'dados_consolidados.csv'

    # Limite de eventos a serem enviados. Se 0 ou None, enviara todos os eventos do CSV.
    LIMITE_EVENTOS: Optional[int] = 30

    # Atraso em segundos entre o envio de cada evento para simular um stream.
    DELAY_STREAMING: float = 0.5 # segundos


# ---
# FUNCOES DO SIMULADOR
# ---

def validar_arquivo_csv() -> bool:
    """
    Valida se o arquivo CSV de origem existe e se possui permissoes de leitura.

    Retorna:
        bool: True se o arquivo for valido e acessivel, False caso contrario.
    """
    logger.info(f"Validando arquivo CSV de origem: {SimuladorConfig.CSV_PATH}")
    
    if not SimuladorConfig.CSV_PATH.exists():
        logger.critical(f"ERRO: Arquivo CSV nao encontrado em '{SimuladorConfig.CSV_PATH}'")
        logger.critical("Verifique se o script de consolidacao de dados foi executado e o arquivo gerado.")
        return False
    
    # Verifica permissao de leitura
    if not os.access(SimuladorConfig.CSV_PATH, os.R_OK):
        logger.critical(f"ERRO: Sem permissao de leitura para o arquivo: {SimuladorConfig.CSV_PATH}")
        logger.critical("Verifique as permissoes do sistema de arquivos.")
        return False
    
    logger.info("Arquivo CSV validado e acessivel.")
    return True

def simular_stream_vendas() -> int:
    """
    Simula um stream de vendas, lendo eventos de um arquivo CSV e
    enviando-os para a fila de eventos (`fila_eventos`).

    Retorna:
        int: O numero total de eventos enviados para a fila.
    """
    logger.info("Iniciando simulador de stream de vendas...")
    logger.info(f"Arquivo fonte: {SimuladorConfig.CSV_PATH}")
    logger.info(f"Limite de eventos: {SimuladorConfig.LIMITE_EVENTOS if SimuladorConfig.LIMITE_EVENTOS else 'Nenhum'}")
    logger.info("-" * 50)
    
    eventos_enviados = 0
    
    try:
        with open(SimuladorConfig.CSV_PATH, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Valida se as colunas necessarias existem no CSV
            required_columns = ['customer_state', 'price', 'order_id', 'timestamp'] # Incluido 'order_id' e 'timestamp'
            missing_columns = [col for col in required_columns if col not in reader.fieldnames]
            
            if missing_columns:
                logger.critical(f"ERRO: Colunas obrigatorias nao encontradas no CSV: {missing_columns}")
                logger.critical(f"Colunas disponiveis: {reader.fieldnames}")
                return 0
            
            for row_num, row in enumerate(reader):
                if SimuladorConfig.LIMITE_EVENTOS is not None and eventos_enviados >= SimuladorConfig.LIMITE_EVENTOS:
                    logger.info(f"Limite de {SimuladorConfig.LIMITE_EVENTOS} eventos atingido. Encerrando simulacao.")
                    break
                
                try:
                    # Validacao e conversao segura dos dados do evento
                    # Usar .get() com fallback para evitar KeyError
                    price_str = row.get("price")
                    customer_state_str = row.get("customer_state")
                    order_id_str = row.get("order_id")
                    original_timestamp_str = row.get("timestamp")

                    price = float(price_str) if price_str else 0.0
                    state = customer_state_str.strip() if customer_state_str else "UNKNOWN"
                    order_id = order_id_str.strip() if order_id_str else f"GEN_ID_{eventos_enviados+1}"
                    # Usa o timestamp original do CSV se existir, senao usa o tempo de agora
                    timestamp = original_timestamp_str if original_timestamp_str else datetime.now().isoformat()
                    
                    event_payload = {
                        "timestamp": timestamp,
                        "customer_state": state,
                        "price": price,
                        "order_id": order_id, # Adicionado order_id
                        "event_sequence_id": eventos_enviados + 1 # ID sequencial para auditoria
                    }
                    
                    fila_eventos.put(event_payload)
                    logger.info(f"Evento {eventos_enviados + 1:02d} (ID: {order_id}): Estado={state:<2} | Valor=R$ {price:>8.2f}")
                    
                    eventos_enviados += 1
                    
                    # Simula delay de streaming
                    time.sleep(SimuladorConfig.DELAY_STREAMING)
                    
                except (ValueError, KeyError, TypeError) as e:
                    logger.warning(f"Linha {row_num + 1} ignorada devido a dados invalidos: {e}. Linha: {row}", exc_info=True)
                    logger.warning(f"Linha {row_num + 1} ignorada (dados invalidos): {e}")
                    # Continua para a proxima linha
                    continue
                except KeyboardInterrupt:
                    # Permite Ctrl+C para parar 
                    logger.info("Simulacao interrompida pelo usuario (Ctrl+C).")
                    logger.info("Simulacao interrompida pelo usuario.")
                    break
                    
    except FileNotFoundError: 
        logger.critical(f"ERRO: Arquivo nao encontrado: {SimuladorConfig.CSV_PATH}", exc_info=True)
        return 0
    except Exception as e:
        logger.critical(f"ERRO INESPERADO durante a simulacao do stream: {e}", exc_info=True)
        logger.critical(f"ERRO INESPERADO: {e}")
        return 0
        
    logger.info("-" * 50)
    logger.info(f"Simulacao concluida!")
    logger.info(f"Total de eventos enviados: {eventos_enviados}")
    logger.info(f"Eventos restantes na fila (se o limite foi atingido antes da leitura completa): {fila_eventos.qsize()}")
    
    return eventos_enviados

# ---
# PONTO DE ENTRADA PRINCIPAL DO SCRIPT
# ---
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("      SIMULADOR DE STREAM DE VENDAS - DEMONSTRACAO TECNICA")
    logger.info("=" * 60)
    
    # Validacao inicial do arquivo CSV
    if not validar_arquivo_csv():
        sys.exit(1) # Sai se o arquivo nao for valido
    
    # Executa a simulacao
    eventos_enviados = simular_stream_vendas()
    
    if eventos_enviados > 0:
        logger.info(f"Simulacao executada com sucesso!")
        logger.info(f"A fila 'fila_eventos' contem {fila_eventos.qsize()} eventos para serem processados por outro script.")
    else:
        logger.critical(f"Falha na simulacao. Nenhum evento foi enviado ou ocorreram erros criticos.")
        sys.exit(1)
