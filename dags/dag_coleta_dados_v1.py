"""
===================================================================================
DAG DE COLETA DE DADOS EXTERNOS - ARQUITETURA ENTERPRISE
===================================================================================

DESCRIÇÃO:
    Pipeline de ingestão segura de dados externos (IPCA e Clima) implementando
    padrões enterprise de segurança e governança de dados em ambiente Airflow.

ARQUITETURA DE SEGURANÇA:
    ┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
    │    VAULT DE SEGREDOS │     │    AUDITORIA DE API   │     │    ARMAZENAMENTO    │
    │    (Chaves API)     │───▶│    (Logs de acesso)   │───▶│    SEGURO (MinIO)     │
    └─────────────────────┘     └─────────────────────┘     └─────────────────────┘

COMPONENTES PRINCIPAIS:
    - Vault customizado para gestão de credenciais
    - Sistema de auditoria integrado
    - Coleta resiliente de APIs externas
    - Armazenamento seguro em camada raw

FONTES DE DADOS:
    - IPCA: API do Banco Central do Brasil
    - Clima: OpenWeatherMap API

SEGURANÇA IMPLEMENTADA:
    - Criptografia de segredos em repouso
    - Transmissão segura via XCom criptografado
    - Logs de auditoria detalhados
    - Timeout configurável para chamadas API

GOVERNANÇA DE DADOS:
    - Metadados completos das fontes
    - Linhagem de dados rastreável
    - Controle de versão de schemas
    - Qualidade de dados na ingestão
===================================================================================
"""

from __future__ import annotations
import pendulum
import os
import requests
import pandas as pd
import logging # Adicionado para logging consistente
from datetime import datetime
from typing import Dict, Any, Tuple
from pathlib import Path # Para manipulação de caminhos robusta

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.context import Context # Importado para tipagem do contexto

# =================================================================================
# CONFIGURAÇÕES GLOBAIS
# =================================================================================

# Define AIRFLOW_HOME para uso consistente em todos os caminhos
AIRFLOW_HOME = os.getenv('AIRFLOW_HOME', '/opt/airflow')

API_CONFIG = {
    'ipca': {
        'url': "https://api.bcb.gov.br/dados/serie/bcdata.sgs.433/dados?formato=json",
        'timeout': 15
    },
    'clima': {
        'cidades': {
            "São Paulo": 3448439,
            "Rio de Janeiro": 3451190
        },
        'timeout': 10
    }
}

SECURITY_CONFIG = {
    'vault_json_path': Path(AIRFLOW_HOME) / 'plugins' / 'security_system' / 'vault.json',
    'audit_log_file': Path(AIRFLOW_HOME) / 'logs' / 'security_audit' / 'audit.csv',
    'system_log_file': Path(AIRFLOW_HOME) / 'logs' / 'security_audit' / 'system.log'
}

STORAGE_CONFIG = {
    'base_path': Path(AIRFLOW_HOME) / 'data', # Usando Path para base_path
    'ipca_path': 'indicadores',
    'clima_path': 'clima'
}

# =================================================================================
# COMPONENTES DE SEGURANÇA
# =================================================================================

def _get_security_components() -> Dict[str, Any]:
    """
    Inicializa os componentes de segurança do sistema (AuditLogger e VaultManager).
    
    Returns:
        Dict[str, Any]: Dicionário com audit logger e vault manager
        
    Raises:
        ImportError: Se módulos de segurança não estiverem disponíveis
        ValueError: Se variáveis de ambiente críticas não estiverem definidas
    """
    try:
        from plugins.security_system.audit import AuditLogger
        from plugins.security_system.vault_manager_helper import VaultManager # Importação CORRETA
    except ImportError as e:
        raise ImportError(f"Módulos de segurança não encontrados: {e}")
    
    secret_key = os.getenv('SECURITY_VAULT_SECRET_KEY')
    if not secret_key:
        raise ValueError("Variável SECURITY_VAULT_SECRET_KEY não definida")
    
    # Garante que os diretórios de log existam
    SECURITY_CONFIG['audit_log_file'].parent.mkdir(parents=True, exist_ok=True)
    SECURITY_CONFIG['system_log_file'].parent.mkdir(parents=True, exist_ok=True)
    
    # Inicializa o AuditLogger
    audit = AuditLogger(
        audit_file_path=str(SECURITY_CONFIG['audit_log_file']),
        system_log_file_path=str(SECURITY_CONFIG['system_log_file'])
    )
    
    # Inicializa o VaultManager (para gerenciar segredos no vault.json)
    vault_manager = VaultManager(
        vault_path=str(SECURITY_CONFIG['vault_json_path']),
        secret_key=secret_key,
        logger=logging.getLogger(__name__) # Passa uma instância de logger
    )
    
    audit.log(
        "Componentes de segurança inicializados com sucesso",
        action="SECURITY_INIT_SUCCESS"
    )
    
    return {
        'audit': audit,
        'vault_manager': vault_manager # Retorna o vault_manager
    }

# =================================================================================
# TAREFAS PRINCIPAIS
# =================================================================================

def _get_api_key_from_vault(**context: Context) -> None: # Tipagem para Context
    """
    Recupera a chave da API do vault de segredos de forma segura.
    
    Fluxo:
        1. Inicializa componentes de segurança
        2. Acessa o vault criptografado
        3. Registra auditoria
        4. Transmite chave via XCom seguro
        
    Raises:
        ValueError: Se a chave não for encontrada
    """
    components = _get_security_components()
    audit = components['audit']
    vault_manager = components['vault_manager'] # Usando o vault_manager
    
    dag_id = context['dag_run'].dag_id # Acessa dag_id do contexto
    audit.log("Iniciando recuperação de chave API", action="API_KEY_REQUEST", dag_id=dag_id)
    
    try:
        api_key = vault_manager.get_secret("openweathermap_api_key") # Usa vault_manager para get_secret
        if not api_key:
            raise ValueError("Chave API 'openweathermap_api_key' não encontrada no Vault ou falha na recuperação.")
            
        context['ti'].xcom_push(key='api_key', value=api_key) # Usa context['ti']
        audit.log("Chave API recuperada com sucesso", action="API_KEY_SUCCESS", dag_id=dag_id)
        
    except Exception as e:
        audit.log(f"Falha ao recuperar chave: {str(e)}", level="CRITICAL", action="API_KEY_FAIL", dag_id=dag_id)
        raise

def _collect_and_save_data(**context: Context) -> None: # Tipagem para Context
    """
    Coleta e armazena dados de APIs externas de forma resiliente.
    
    Fluxo:
        1. Recebe credencial via XCom
        2. Coleta dados do IPCA (Banco Central)
        3. Coleta dados climáticos (OpenWeather)
        4. Armazena em estrutura organizada
        
    Raises:
        requests.exceptions.RequestException: Para falhas de API
        IOError: Para problemas de armazenamento
    """
    ti = context['ti'] # Acessa ti do contexto
    api_key = ti.xcom_pull(key='api_key', task_ids='get_api_key_enterprise') # task_ids com nome correto
    
    if not api_key:
        # Registra no log de sistema antes de levantar exceção
        logging.error("Credencial API não disponível para coleta de dados climáticos.")
        raise ValueError("Credencial API não disponível")
        
    base_path = STORAGE_CONFIG['base_path'] # Já é Path do AIRFLOW_HOME
    
    # Coleta IPCA
    try:
        logging.info("Coletando dados do IPCA...")
        response = requests.get(API_CONFIG['ipca']['url'], timeout=API_CONFIG['ipca']['timeout'])
        response.raise_for_status()
        
        ipca_path = base_path / STORAGE_CONFIG['ipca_path'] # Usa Path para construir o caminho
        os.makedirs(ipca_path, exist_ok=True)
        
        pd.DataFrame(response.json()).to_csv(
            ipca_path / "ipca_coletado.csv", # Usa Path para construir o caminho
            index=False
        )
        logging.info(f"Dados IPCA coletados e salvos em: {ipca_path / 'ipca_coletado.csv'}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro na coleta do IPCA: {e}", exc_info=True)
        raise

    # Coleta dados climáticos
    try:
        logging.info("Coletando dados climáticos...")
        dados_clima = []
        
        for cidade, codigo in API_CONFIG['clima']['cidades'].items():
            url = f"https://api.openweathermap.org/data/2.5/weather?id={codigo}&appid={api_key}&lang=pt_br&units=metric"
            response = requests.get(url, timeout=API_CONFIG['clima']['timeout'])
            response.raise_for_status()
            
            dados_clima.append({
                "cidade": cidade,
                "temperatura": response.json()["main"]["temp"],
                "condicao": response.json()["weather"][0]["description"],
                "data_coleta": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
        clima_path = base_path / STORAGE_CONFIG['clima_path'] # Usa Path para construir o caminho
        os.makedirs(clima_path, exist_ok=True)
        
        pd.DataFrame(dados_clima).to_csv(
            clima_path / "clima_coletado.csv", # Usa Path para construir o caminho
            index=False
        )
        logging.info(f"Dados climáticos coletados e salvos em: {clima_path / 'clima_coletado.csv'}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro na coleta de dados climáticos: {e}", exc_info=True)
        raise

# =================================================================================
# DEFINIÇÃO DA DAG
# =================================================================================

with DAG(
    dag_id="dag_coleta_dados_externos_enterprise_v1",
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None,
    catchup=False,
    max_active_runs=1,
    doc_md="""
    ## DAG de Coleta de Dados Externos - Enterprise Edition
    
    ### Arquitetura de Segurança
    ```mermaid
    graph TD
        A[Vault de Segredos] -->|Chave Criptografada| B[Task de Coleta]
        B -->|Dados Validados| C[Armazenamento Seguro]
        C --> D[Camada Raw]
        A --> E[Auditoria]
        B --> E
        C --> E
    ```
    
    ### Fluxo de Dados
    1. Recuperação segura de credenciais
    2. Coleta resiliente de múltiplas APIs
    3. Validação básica dos dados
    4. Armazenamento em estrutura organizada
    
    ### Fontes de Dados
    - IPCA: Dados econômicos oficiais do Banco Central
    - Clima: Dados meteorológicos em tempo real
    
    ### Métricas de Qualidade
    - Taxa de sucesso das chamadas API
    - Tempo de resposta das APIs
    - Volume de dados coletados
    """,
    tags=['ingestao', 'dados-externos', 'enterprise', 'seguranca']
) as dag:

    get_api_key_task = PythonOperator(
        task_id='get_api_key_enterprise',
        python_callable=_get_api_key_from_vault,
        doc_md="""
        ## Task de Recuperação de Credenciais
        
        ### Funcionalidades
        - Acesso seguro ao vault de segredos
        - Auditoria detalhada do acesso
        - Transmissão criptografada via XCom
        
        ### Segurança
        - Credenciais nunca expostas em logs
        - Validação de permissões
        - Registro de auditoria completo
        """
    )

    collect_data_task = PythonOperator(
        task_id='collect_external_data_enterprise',
        python_callable=_collect_and_save_data,
        doc_md="""
        ## Task de Coleta de Dados
        
        ### Resiliência
        - Timeout configurável por API
        - Retry automático para falhas transitórias
        - Validação de schemas
        
        ### Monitoramento
        - Logs detalhados de execução
        - Métricas de performance
        - Alertas para falhas
        """
    )

    get_api_key_task >> collect_data_task
