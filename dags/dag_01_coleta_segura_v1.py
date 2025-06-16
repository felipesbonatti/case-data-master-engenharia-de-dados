# ===================================================================================
# DAG DE COLETA SEGURA COM AUDITORIA COMPLETA - DEMONSTRAÇÃO 
# ===================================================================================

# DESCRIÇÃO:
# Esta DAG orquestra a coleta de dados econômicos (IPCA) e meteorológicos 
# com integração completa ao sistema de segurança e auditoria corporativo,
# seguindo as melhores práticas de Engenharia de Dados.

# ARQUITETURA DE SEGURANÇA:
# 🔐 Gestão Centralizada de Segredos via Vault
# 📊 Sistema de Auditoria Completo com Rastreabilidade
# 🛡️ Logging Estruturado para Compliance
# ⚡ Processamento Paralelo Otimizado

# REQUISITOS TÉCNICOS:
# - Apache Airflow 2.x+
# - Sistema de Vault configurado com 'openweathermap_api_key'
# - Variável de ambiente: SECURITY_VAULT_SECRET_KEY
# - Estrutura de diretórios: logs/security_audit/ e data/

# FONTES DE DADOS:
# - IPCA: Banco Central do Brasil (API BCB)
# - Clima: OpenWeatherMap API
# ===================================================================================

from __future__ import annotations

import os
import pendulum
import requests
import pandas as pd
import logging # Adicionado para uso no logger
from datetime import datetime
from typing import Tuple, Dict, Any

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.context import Context

# ===================================================================================
# CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ===================================================================================

AIRFLOW_HOME = os.getenv('AIRFLOW_HOME', '/opt/airflow')

# Configurações de API
IPCA_API_URL = "https://api.bcb.gov.br/dados/serie/bcdata.sgs.433/dados?formato=json"
OPENWEATHER_BASE_URL = "http://api.openweathermap.org/data/2.5/weather"

# Configurações de cidades para coleta meteorológica
CIDADES_CONFIG = {
    "São Paulo": 3448439,
    "Rio de Janeiro": 3451190
}

# Timeouts e configurações de rede
REQUEST_TIMEOUT = 10


# ===================================================================================
# FUNÇÕES AUXILIARES E COMPONENTES DE SEGURANÇA
# ===================================================================================

def _get_security_components() -> Tuple[Any, Any]:
    """
    Inicializa e retorna os componentes do sistema de segurança (AuditLogger e VaultManager).
    
    Returns:
        Tuple[AuditLogger, VaultManager]: Componentes de auditoria e segurança do Vault.
        
    Raises:
        ValueError: Quando a chave secreta de criptografia do Vault não está configurada.
    """
    from plugins.security_system.audit import AuditLogger
    from plugins.security_system.vault_manager_helper import VaultManager # IMPORTAÇÃO CORRETA!
    
    SECRET_KEY = os.getenv('SECURITY_VAULT_SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError(
            "ERRO CRÍTICO: Variável de ambiente SECURITY_VAULT_SECRET_KEY não configurada para o Vault."
        )
    
    # Definição dinâmica de caminhos baseada no AIRFLOW_HOME
    AUDIT_LOG_PATH = os.path.join(AIRFLOW_HOME, 'logs', 'security_audit', 'audit.csv')
    SYSTEM_LOG_PATH = os.path.join(AIRFLOW_HOME, 'logs', 'security_audit', 'system.log')
    VAULT_JSON_PATH = os.path.join(AIRFLOW_HOME, 'plugins', 'security_system', 'vault.json') # Caminho corrigido para vault.json
    
    # Inicialização dos componentes de segurança
    audit_logger = AuditLogger(
        audit_file_path=AUDIT_LOG_PATH, 
        system_log_file_path=SYSTEM_LOG_PATH
    )
    
    # Instancia o VaultManager para gerenciar os segredos do vault.json
    vault_manager = VaultManager( # NOME DA VARIÁVEL AJUSTADO para vault_manager
        vault_path=VAULT_JSON_PATH, 
        secret_key=SECRET_KEY, 
        logger=logging.getLogger(__name__) # Passa uma instância de logger real
    )
    
    return audit_logger, vault_manager # Retorna o vault_manager


# ===================================================================================
# FUNÇÕES DE COLETA DE DADOS
# ===================================================================================

def _coleta_ipca(**context: Context) -> None:
    """
    Executa a coleta de dados do IPCA do Banco Central do Brasil.
    
    Funcionalidades:
        - Coleta dados históricos do IPCA via API BCB
        - Registra todas as operações no sistema de auditoria
        - Salva dados em formato CSV padronizado
        
    Args:
        context: Contexto de execução do Airflow
        
    Raises:
        Exception: Erros de conectividade ou processamento são logados e re-propagados
    """
    audit_logger, _ = _get_security_components() # O segundo retorno (VaultManager) não é usado aqui
    dag_id = context['dag_run'].dag_id
    
    audit_logger.log(
        "🚀 Iniciando processo de coleta de dados IPCA", 
        action="COLETA_IPCA_START", 
        dag_id=dag_id
    )
    
    try:
        # Preparação do ambiente de dados
        base_path = os.path.join(AIRFLOW_HOME, 'data', 'indicadores')
        os.makedirs(base_path, exist_ok=True)
        
        # Requisição à API do Banco Central
        response = requests.get(IPCA_API_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        
        # Processamento e persistência dos dados
        dataframe_ipca = pd.DataFrame(response.json())
        output_path = os.path.join(base_path, "ipca_coletado.csv")
        dataframe_ipca.to_csv(output_path, index=False)
        
        audit_logger.log(
            f"✅ Coleta IPCA finalizada com sucesso. Arquivo salvo em: {output_path}", 
            action="COLETA_IPCA_SUCCESS", 
            dag_id=dag_id
        )
        
    except Exception as error:
        audit_logger.log(
            f"❌ Falha crítica na coleta IPCA: {str(error)}", 
            level="ERROR", 
            action="COLETA_IPCA_FAIL", 
            dag_id=dag_id
        )
        raise


def _coleta_clima(**context: Context) -> None:
    """
    Executa a coleta de dados meteorológicos via OpenWeatherMap API.
    
    Funcionalidades:
        - Recupera chave de API do sistema Vault
        - Coleta dados meteorológicos de múltiplas cidades
        - Processa e estrutura dados em formato padronizado
        - Registra todas as operações no sistema de auditoria
        
    Args:
        context: Contexto de execução do Airflow
        
    Raises:
        ValueError: Quando a chave da API não está disponível no Vault
        Exception: Erros de conectividade ou processamento
    """
    audit_logger, vault_manager = _get_security_components() # Agora recebe o vault_manager
    dag_id = context['dag_run'].dag_id
    
    audit_logger.log(
        "🌤️ Iniciando processo de coleta de dados meteorológicos", 
        action="COLETA_CLIMA_START", 
        dag_id=dag_id
    )
    
    try:
        # Recuperação segura da chave de API usando o vault_manager
        api_key = vault_manager.get_secret("openweathermap_api_key")
        if not api_key:
            raise ValueError(
                "ERRO DE SEGURANÇA: Chave 'openweathermap_api_key' não encontrada no Vault ou falha na recuperação."
            )
        
        # Preparação do ambiente de dados
        base_path = os.path.join(AIRFLOW_HOME, 'data', 'clima')
        os.makedirs(base_path, exist_ok=True)
        
        # Coleta de dados meteorológicos por cidade
        dados_meteorologicos = []
        
        for nome_cidade, codigo_cidade in CIDADES_CONFIG.items():
            api_url = (
                f"{OPENWEATHER_BASE_URL}?id={codigo_cidade}"
                f"&appid={api_key}&units=metric&lang=pt"
            )
            
            response = requests.get(api_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            dados_clima = response.json()
            
            # Estruturação dos dados coletados
            registro_clima = {
                "cidade": nome_cidade,
                "temperatura": dados_clima["main"]["temp"],
                "condicao": dados_clima["weather"][0]["description"]
            }
            dados_meteorologicos.append(registro_clima)
        
        # Persistência dos dados coletados
        dataframe_clima = pd.DataFrame(dados_meteorologicos)
        output_path = os.path.join(base_path, "clima_coletado.csv")
        dataframe_clima.to_csv(output_path, index=False)
        
        audit_logger.log(
            f"✅ Coleta meteorológica finalizada com sucesso. "
            f"Cidades processadas: {len(CIDADES_CONFIG)}. Arquivo: {output_path}", 
            action="COLETA_CLIMA_SUCCESS", 
            dag_id=dag_id
        )
        
    except Exception as error:
        audit_logger.log(
            f"❌ Falha crítica na coleta meteorológica: {str(error)}", 
            level="ERROR", 
            action="COLETA_CLIMA_FAIL", 
            dag_id=dag_id
        )
        raise


# ===================================================================================
# DEFINIÇÃO DA DAG PRINCIPAL
# ===================================================================================

with DAG(
    dag_id='dag_01_coleta_segura_v1',
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None,
    catchup=False,
    doc_md="""
    ### 🔐 DAG de Coleta Segura com Auditoria Completa
    
    Objetivo: Demonstrar implementação profissional de pipeline de coleta de dados 
    com integração completa aos sistemas de segurança e auditoria corporativos.
    
    Fontes de Dados:
    - IPCA: Banco Central do Brasil (Série 433)
    - Meteorologia: OpenWeatherMap API (São Paulo e Rio de Janeiro)
    
    Recursos de Segurança:
    - ✅ Gestão centralizada de credenciais via Vault
    - ✅ Auditoria completa de todas as operações
    - ✅ Logging estruturado para compliance
    - ✅ Tratamento robusto de erros
    
    Arquitetura:
    - Processamento paralelo otimizado
    - Separação clara de responsabilidades
    - Configuração dinâmica de caminhos
    - Padrões de código enterprise
    """,
    tags=['ingestao', 'seguranca', 'auditoria', 'enterprise', 'compliance']
) as dag:
    
    # ===================================================================================
    # DEFINIÇÃO DAS TAREFAS (TASKS)
    # ===================================================================================
    
    tarefa_ipca = PythonOperator(
        task_id='coleta_ipca_segura_task',
        python_callable=_coleta_ipca,
        doc_md="""
        Coleta de Dados IPCA
        
        Responsável pela extração de dados do Índice de Preços ao Consumidor Amplo 
        diretamente da API do Banco Central do Brasil.
        
        - Fonte: api.bcb.gov.br
        - Série: 433 (IPCA)
        - Formato: JSON → CSV
        - Auditoria: Completa
        """
    )
    
    tarefa_clima = PythonOperator(
        task_id='coleta_clima_segura_task',
        python_callable=_coleta_clima,
        doc_md="""
        Coleta de Dados Meteorológicos
        
        Responsável pela extração de dados meteorológicos atuais das principais 
        cidades brasileiras via OpenWeatherMap API.
        
        - Fonte: OpenWeatherMap
        - Cidades: São Paulo, Rio de Janeiro
        - Dados: Temperatura, Condições
        - Segurança: Chave via Vault
        - Auditoria: Completa
        """
    )

# ===================================================================================
# CONFIGURAÇÃO DE DEPENDÊNCIAS
# ===================================================================================
# 
# NOTA ARQUITETURAL:
# As tarefas são executadas em paralelo para otimizar o tempo de processamento,
# já que não há dependência funcional entre a coleta de dados econômicos e meteorológicos.
# Esta abordagem maximiza a eficiência do pipeline e reduz o tempo total de execução.
#
# ===================================================================================
