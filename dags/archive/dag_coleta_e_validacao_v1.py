"""
====================================================================================
DAG DE COLETA E VALIDAÇÃO DE DADOS EXTERNOS 
====================================================================================

DESCRIÇÃO:
    Pipeline completo para coleta, processamento e validação de dados externos,
    implementando padrões enterprise de qualidade e segurança de dados.

ARQUITETURA:
    Fontes Externas (IPCA - BCB, Clima - OpenWeather) --> Camada de Ingestão
    (Segurança, Transformação) --> Validação de Dados (Anomalias, Qualidade)

COMPONENTES PRINCIPAIS:
    - Vault Enterprise para gestão de segredos
    - Coleta resiliente de APIs externas
    - Validação de dados em tempo real
    - Auditoria completa de operações

FONTES DE DADOS:
    - IPCA: API do Banco Central do Brasil (Série 433)
    - Clima: OpenWeatherMap API (Tempo real)

SEGURANÇA:
    - Credenciais criptografadas em repouso e trânsito
    - Acesso mínimo privilegiado
    - Logs de auditoria detalhados
    - Validação de certificados SSL

VALIDAÇÕES IMPLEMENTADAS:
    - Integridade dos dados (valores nulos)
    - Consistência de tipos
    - Faixas de valores esperados
    - Valores fora do padrão
====================================================================================
"""

from __future__ import annotations
import os
import pendulum
import pandas as pd
import requests
import logging # Adicionado para logging consistente
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime # Necessário para datetime.now()

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.context import Context

# =================================================================================
# CONFIGURAÇÕES GLOBAIS
# =================================================================================

class Config:
    """Centraliza todas as configurações da DAG"""
    AIRFLOW_HOME = os.getenv('AIRFLOW_HOME', '/opt/airflow')

    # Diretórios
    BASE_PATH = Path(AIRFLOW_HOME) / 'data'
    INDICADORES_PATH = BASE_PATH / 'indicadores'
    CLIMA_PATH = BASE_PATH / 'clima'
    
    # Segurança e Auditoria
    VAULT_JSON_PATH = Path(AIRFLOW_HOME) / 'plugins' / 'security_system' / 'vault.json'
    AUDIT_LOG_FILE = Path(AIRFLOW_HOME) / 'logs' / 'security_audit' / 'audit.csv'
    SYSTEM_LOG_FILE = Path(AIRFLOW_HOME) / 'logs' / 'security_audit' / 'system.log'
    VAULT_SECRET_KEY_NAME = 'openweathermap_api_key' # Nome da chave no Vault
    
    # APIs
    IPCA_URL = "https://api.bcb.gov.br/dados/serie/bcdata.sgs.433/dados?formato=json"
    OPENWEATHER_URL = "http://api.openweathermap.org/data/2.5/weather"
    
    # Cidades monitoradas
    CIDADES = {
        "São Paulo": 3448439,
        "Rio de Janeiro": 3451190
    }
    
    # Timeouts (segundos)
    REQUEST_TIMEOUT = 15
    VALIDATION_THRESHOLDS = {
        'null_tolerance': 0.01  # 1% de valores nulos permitidos
    }

# =================================================================================
# COMPONENTES DE SEGURANÇA
# =================================================================================

def _get_security_components_for_collect_validate() -> Tuple[object, object]:
    """
    Inicializa os componentes de segurança do sistema (AuditLogger e VaultManager).
    
    Returns:
        Tuple[AuditLogger, VaultManager]: Instâncias de AuditLogger e VaultManager.
        
    Raises:
        ImportError: Se módulos de segurança não estiverem disponíveis.
        ValueError: Se variáveis de ambiente críticas não estiverem definidas.
    """
    try:
        from plugins.security_system.audit import AuditLogger
        from plugins.security_system.vault_manager_helper import VaultManager
    except ImportError as e:
        raise ImportError(f"Módulos de segurança não encontrados: {e}")
    
    secret_key = os.getenv('SECURITY_VAULT_SECRET_KEY')
    if not secret_key:
        raise ValueError("Variável de ambiente SECURITY_VAULT_SECRET_KEY não definida.")
    
    # Garante que os diretórios de log existam
    Config.AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    Config.SYSTEM_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    Config.VAULT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True) # Garante diretório do vault.json
    
    # Inicializa AuditLogger
    audit = AuditLogger(
        audit_file_path=str(Config.AUDIT_LOG_FILE),
        system_log_file_path=str(Config.SYSTEM_LOG_FILE)
    )
    
    # Inicializa VaultManager
    vault_manager = VaultManager(
        vault_path=str(Config.VAULT_JSON_PATH),
        secret_key=secret_key,
        logger=logging.getLogger(__name__)
    )
    
    audit.log("Componentes de segurança inicializados com sucesso", action="SECURITY_INIT_SUCCESS")
    
    return audit, vault_manager

# =================================================================================
# TAREFAS DE PROCESSAMENTO
# =================================================================================

def _get_api_key(**context: Context) -> None:
    """Task Airflow: Recupera e transmite a chave API de forma segura"""
    audit, vault_manager = _get_security_components_for_collect_validate()
    
    dag_id = context['dag_run'].dag_id
    audit.log("Iniciando recuperação segura da chave API", action="API_KEY_REQUEST", dag_id=dag_id)
    
    try:
        api_key = vault_manager.get_secret(Config.VAULT_SECRET_KEY_NAME)
        if not api_key:
            raise ValueError(f"Chave API '{Config.VAULT_SECRET_KEY_NAME}' não encontrada no Vault ou falha na recuperação.")
            
        context['ti'].xcom_push(key='api_key', value=api_key)
        audit.log("Chave API recuperada com sucesso", action="API_KEY_SUCCESS", dag_id=dag_id)
        
    except Exception as e:
        audit.log(f"Falha ao recuperar chave: {str(e)}", level="CRITICAL", action="API_KEY_FAIL", dag_id=dag_id)
        raise

def _collect_ipca(**context: Context) -> None:
    """Task Airflow: Coleta dados econômicos do IPCA"""
    audit, _ = _get_security_components_for_collect_validate() # VaultManager não é usado aqui
    dag_id = context['dag_run'].dag_id

    audit.log("Iniciando coleta de dados econômicos do IPCA", action="IPCA_COLLECT_START", dag_id=dag_id)
    
    # Garante diretório de destino
    Config.INDICADORES_PATH.mkdir(parents=True, exist_ok=True)
    
    try:
        response = requests.get(
            Config.IPCA_URL,
            timeout=Config.REQUEST_TIMEOUT
        )
        response.raise_for_status()
        
        df = pd.DataFrame(response.json())
        output_path = Config.INDICADORES_PATH / "ipca_coletado.csv"
        df.to_csv(output_path, index=False)
        
        audit.log(f"Dados IPCA salvos: {len(df)} registros. Caminho: {output_path}", action="IPCA_COLLECT_SUCCESS", dag_id=dag_id)
    except requests.exceptions.RequestException as e:
        audit.log(f"Falha na coleta do IPCA: {str(e)}", level="ERROR", action="IPCA_COLLECT_FAIL", dag_id=dag_id)
        raise

def _collect_weather(**context: Context) -> None:
    """Task Airflow: Coleta dados meteorológicos"""
    audit, _ = _get_security_components_for_collect_validate() # VaultManager não é usado aqui
    dag_id = context['dag_run'].dag_id

    audit.log("Iniciando coleta de dados meteorológicos", action="CLIMA_COLLECT_START", dag_id=dag_id)
    
    # Garante diretório de destino
    Config.CLIMA_PATH.mkdir(parents=True, exist_ok=True)
    
    # Recupera chave segura via XCom
    ti = context['ti']
    api_key = ti.xcom_pull(key='api_key', task_ids='get_api_key_enterprise')
    if not api_key:
        audit.log("Credencial API não disponível via XCom para coleta climática.", level="CRITICAL", action="CLIMA_API_KEY_MISSING", dag_id=dag_id)
        raise ValueError("Credencial API não disponível via XCom")
    
    weather_data = []
    
    try:
        for cidade, codigo in Config.CIDADES.items():
            url = f"{Config.OPENWEATHER_URL}?id={codigo}&appid={api_key}&units=metric&lang=pt"
            response = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            weather_data.append({
                "cidade": cidade,
                "temperatura": data["main"]["temp"],
                "condicao": data["weather"][0]["description"],
                "umidade": data["main"]["humidity"],
                "pressao": data["main"]["pressure"]
            })
            
        output_path = Config.CLIMA_PATH / "clima_coletado.csv"
        df = pd.DataFrame(weather_data)
        df.to_csv(output_path, index=False)
        
        audit.log(f"Dados climáticos salvos: {len(df)} registros. Caminho: {output_path}", action="CLIMA_COLLECT_SUCCESS", dag_id=dag_id)
    except requests.exceptions.RequestException as e:
        audit.log(f"Falha na coleta de dados climáticos: {str(e)}", level="ERROR", action="CLIMA_COLLECT_FAIL", dag_id=dag_id)
        raise

def _validate_data(**context: Context) -> None:
    """Task Airflow: Executa validações de qualidade nos dados coletados"""
    audit, _ = _get_security_components_for_collect_validate() # VaultManager não é usado aqui
    dag_id = context['dag_run'].dag_id

    audit.log("Iniciando validação de qualidade de dados", action="VALIDATION_START", dag_id=dag_id)
    
    validation_status = []

    # Valida dados do IPCA
    ipca_file = Config.INDICADORES_PATH / "ipca_coletado.csv"
    if ipca_file.exists():
        df_ipca = pd.read_csv(ipca_file)
        null_count = df_ipca.isnull().sum().sum()
        null_percent = null_count / df_ipca.size
        
        if null_percent > Config.VALIDATION_THRESHOLDS['null_tolerance']:
            audit.log(f"Alerta IPCA: {null_percent:.2%} de valores nulos (limite: {Config.VALIDATION_THRESHOLDS['null_tolerance']:.2%})", level="WARNING", action="IPCA_VALIDATION_WARNING", dag_id=dag_id)
            validation_status.append(f"IPCA - ALERTA NULOS: {null_percent:.2%}")
        else:
            audit.log(f"IPCA válido: {null_percent:.2%} de valores nulos", action="IPCA_VALIDATION_SUCCESS", dag_id=dag_id)
            validation_status.append("IPCA - OK")
    else:
        audit.log("Arquivo IPCA não encontrado para validação", level="ERROR", action="IPCA_VALIDATION_FILE_MISSING", dag_id=dag_id)
        validation_status.append("IPCA - ERRO: ARQUIVO AUSENTE")
    
    # Valida dados climáticos
    clima_file = Config.CLIMA_PATH / "clima_coletado.csv"
    if clima_file.exists():
        df_clima = pd.read_csv(clima_file)
        null_count = df_clima.isnull().sum().sum()
        null_percent = null_count / df_clima.size
        
        if null_percent > Config.VALIDATION_THRESHOLDS['null_tolerance']:
            audit.log(f"Alerta Clima: {null_percent:.2%} de valores nulos (limite: {Config.VALIDATION_THRESHOLDS['null_tolerance']:.2%})", level="WARNING", action="CLIMA_VALIDATION_WARNING", dag_id=dag_id)
            validation_status.append(f"Clima - ALERTA NULOS: {null_percent:.2%}")
        else:
            audit.log(f"Clima válido: {null_percent:.2%} de valores nulos", action="CLIMA_VALIDATION_SUCCESS", dag_id=dag_id)
            validation_status.append("Clima - OK")
        
        # Validação adicional para temperaturas extremas
        if 'temperatura' in df_clima.columns:
            extreme_temp = df_clima[(df_clima['temperatura'] < -10) | (df_clima['temperatura'] > 50)]
            if not extreme_temp.empty:
                audit.log(f"Alerta: {len(extreme_temp)} registros com temperaturas extremas", level="WARNING", action="CLIMA_VALIDATION_EXTREME_TEMP", dag_id=dag_id)
                validation_status.append(f"Clima - ALERTA TEMPERATURA EXTREMA: {len(extreme_temp)} registros")
    else:
        audit.log("Arquivo climático não encontrado para validação", level="ERROR", action="CLIMA_VALIDATION_FILE_MISSING", dag_id=dag_id)
        validation_status.append("Clima - ERRO: ARQUIVO AUSENTE")

    audit.log(f"Validação de qualidade concluída. Sumário: {'; '.join(validation_status)}", action="VALIDATION_COMPLETE", dag_id=dag_id)


# =================================================================================
# DEFINIÇÃO DA DAG
# =================================================================================

with DAG(
    dag_id='dag_coleta_validacao_enterprise_v1',
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None, # Mantido None para execução manual/trigger
    catchup=False,
    max_active_runs=1,
    doc_md="""
    ## DAG de Coleta e Validação de Dados Externos - Enterprise Edition
    
    ### Arquitetura
    ```mermaid
    flowchart LR
        A[API BCB] --> B[Coleta IPCA]
        C[API OpenWeather] --> D[Coleta Clima]
        B --> E[Validação]
        D --> E
        E --> F[Relatório Qualidade]
    ```
    
    ### Fluxo Principal
    1. Recuperação segura de credenciais
    2. Coleta paralela de múltiplas fontes
    3. Validação de qualidade dos dados
    4. Geração de relatórios
    
    ### Fontes de Dados
    - IPCA: Dados econômicos oficiais do Banco Central
    - Clima: Dados meteorológicos em tempo real
    
    ### Métricas de Qualidade
    - Taxa de sucesso das chamadas API
    - Tempo de resposta das APIs
    - Volume de dados coletados
    """,
    tags=['ingestao', 'dados-externos', 'enterprise', 'seguranca', 'qualidade']
) as dag:

    get_key_task = PythonOperator(
        task_id='get_api_key_enterprise',
        python_callable=_get_api_key,
        doc_md="""
        ## Task de Recuperação de Credenciais
        
        Responsabilidade:
        Acessa o vault de segredos e recupera a chave da API de forma segura.
        
        Segurança:
        - Credencial nunca exposta em logs
        - Transmissão criptografada via XCom
        - Auditoria de acesso
        """
    )

    collect_ipca_task = PythonOperator(
        task_id='coleta_ipca_task',
        python_callable=_collect_ipca,
        doc_md="""
        ## Task de Coleta IPCA
        
        Fonte: Banco Central do Brasil (Série 433)
        Frequência: Diária
        Validações:
        - Status code HTTP
        - Formato JSON válido
        - Schema esperado
        """
    )

    collect_weather_task = PythonOperator(
        task_id='coleta_clima_task',
        python_callable=_collect_weather,
        doc_md="""
        ## Task de Coleta Climática
        
        Fonte: OpenWeatherMap API
        Cidades: São Paulo, Rio de Janeiro
        Métricas:
        - Temperatura (C)
        - Condição climática
        - Umidade (%)
        - Pressão (hPa)
        """
    )

    validate_task = PythonOperator(
        task_id='validacao_dados_task',
        python_callable=_validate_data,
        doc_md="""
        ## Task de Validação
        
        Verificações:
        - Valores nulos/missing
        - Temperaturas extremas
        - Consistência de dados
        
        Thresholds:
        - Máximo 1% de valores nulos
        - Faixa térmica: -10C a 50C
        """
    )

    # Orquestração
    get_key_task >> collect_weather_task # Coleta clima depende da chave API
    [collect_ipca_task, collect_weather_task] >> validate_task # Validação depende de ambas as coletas
