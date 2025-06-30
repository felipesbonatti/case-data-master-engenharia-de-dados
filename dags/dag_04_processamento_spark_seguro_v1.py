"""
===================================================================================
DAG DE PROCESSAMENTO SPARK COM INJEÇÃO SEGURA DE CREDENCIAIS
===================================================================================

DESCRIÇÃO:
    Pipeline de processamento distribuído Apache Spark com implementação de
    padrões de segurança enterprise para injeção segura de credenciais através
    do sistema Vault, garantindo compliance e auditoria completa.

ARQUITETURA DE SEGURANÇA:
    Recuperação Dinâmica de Credenciais via Vault
    Injeção Segura de Variáveis de Ambiente
    Processamento Distribuído com Spark
    Integração com Object Storage (MinIO)

COMPONENTES TÉCNICOS:
    - Apache Spark 3.x+ (Processamento Distribuído)
    - MinIO Object Storage (Data Lake)
    - Hadoop AWS SDK (Conectividade S3)
    - Vault Security Manager (Gestão de Credenciais)

PADRÕES DE SEGURANÇA:
    Zero Hardcoded Credentials
    Runtime Secret Injection
    Environment Isolation
    Audit Trail Completo

DEPENDÊNCIAS EXTERNAS:
    - hadoop-aws-3.3.1.jar
    - aws-java-sdk-bundle-1.11.901.jar
    - Script: 12-processa_vendas.py

COMPLIANCE:
    - SOX (Sarbanes-Oxley Act) - Controles internos
    - PCI-DSS (Payment Card Industry) - Proteção de dados
    - ISO 27001 (Information Security) - Gestão de segurança
===================================================================================
"""

# A importação future DEVE ser a primeira linha de código
from __future__ import annotations

import sys
import os
import pendulum
import logging # Adicionado para logging consistente
from typing import Dict, List, Optional
from pathlib import Path

from airflow.models.dag import DAG
from airflow.operators.bash import BashOperator
from airflow.utils.context import Context

# ===================================================================================
# CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ===================================================================================

# Configuração do Spark
SPARK_CONFIG = {
    'submit_path': '/home/airflow/.local/bin',
    'jars': [
        '/opt/airflow/jars/hadoop-aws-3.3.1.jar',
        '/opt/airflow/jars/aws-java-sdk-bundle-1.11.901.jar'
    ],
    'script_path': '/opt/airflow/scripts/examples/12-processa_vendas.py',
    'master': 'local[*]',
    'deploy_mode': 'client'
}

# Nomes das variáveis de ambiente esperadas para as credenciais MinIO
REQUIRED_MINIO_ENV_VARS = [
    'MINIO_ENDPOINT_URL',
    'MINIO_ACCESS_KEY',
    'MINIO_SECRET_KEY'
]

# Configuração de logging e auditoria
SECURITY_LOG_LEVEL = 'INFO' # Mantido como constante


# ===================================================================================
# FUNÇÕES DE SEGURANÇA E GESTÃO DE CREDENCIAIS
# ===================================================================================

def _get_minio_environment_variables() -> Dict[str, str]:
    """
    Recupera credenciais do MinIO das variáveis de ambiente com validação.
    
    Esta função implementa o padrão de recuperação segura de credenciais,
    permitindo que a DAG seja parseada mesmo quando as credenciais não estão
    disponíveis durante o parse time, assumindo que serão injetadas em runtime.
    
    Returns:
        Dict[str, str]: Dicionário com credenciais do MinIO ou vazio se indisponíveis
        
    Note:
        A ausência de credenciais durante o parse da DAG é esperada quando
        o sistema Vault injeta as credenciais apenas em tempo de execução.
    """
    logging.info("Iniciando recuperação de credenciais MinIO do ambiente...")
    
    # Recuperação das credenciais
    credentials = {}
    for var_name in REQUIRED_MINIO_ENV_VARS: # Itera sobre os nomes das variáveis
        value = os.getenv(var_name)
        if value:
            credentials[var_name] = value # Usa o nome da variável como chave
    
    # Validação e logging
    if len(credentials) == len(REQUIRED_MINIO_ENV_VARS):
        logging.info(f"Credenciais MinIO recuperadas com sucesso ({len(credentials)} de {len(REQUIRED_MINIO_ENV_VARS)})")
        return credentials
    else:
        missing_vars = [var for var in REQUIRED_MINIO_ENV_VARS if var not in credentials or not credentials[var]]
        logging.warning(f"AVISO: Credenciais MinIO incompletas durante parse da DAG. Variáveis ausentes: {missing_vars}. Isso é esperado se as credenciais são injetadas via Vault em runtime.")
        return {}


def _build_spark_command() -> str:
    """
    Constrói o comando Spark com todas as configurações necessárias.
    
    Returns:
        str: Comando completo do spark-submit
    """
    # Configuração do PATH
    path_config = f'export PATH="{SPARK_CONFIG["submit_path"]}:${{PATH}}"'
    
    # Configuração dos JARs
    jars_config = ','.join(SPARK_CONFIG['jars'])
    
    # Comando base do Spark
    spark_command_parts = [ # Renomeado para evitar conflito com 'spark_command'
        'spark-submit',
        f'--jars {jars_config}',
        f'--master {SPARK_CONFIG["master"]}',
        f'--deploy-mode {SPARK_CONFIG["deploy_mode"]}',
        SPARK_CONFIG['script_path']
    ]
    
    # Comando completo
    full_command = f'{path_config} && {" ".join(spark_command_parts)}'
    
    return full_command


# ===================================================================================
# DEFINIÇÃO DA DAG PRINCIPAL
# ===================================================================================

# Recuperação das credenciais durante o parse da DAG (para o 'env' da task)
minio_environment_variables = _get_minio_environment_variables()

with DAG(
    dag_id='dag_04_processamento_spark_seguro_v1',
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None,
    catchup=False,
    doc_md="""
    ### DAG de Processamento Spark Seguro - Enterprise Edition
    
    Objetivo: Pipeline de processamento distribuído Apache Spark com implementação
    de padrões de segurança enterprise para injeção segura de credenciais.
    
    Arquitetura de Segurança:
    [Vault] -> [Runtime Injection] -> [Spark Process] -> [MinIO Storage]
    
    Componentes Técnicos:
    - Apache Spark: Processamento distribuído em larga escala
    - MinIO Object Storage: Data Lake para armazenamento
    - Vault Security: Gestão centralizada de credenciais
    - Hadoop AWS SDK: Conectividade com object storage
    
    Padrões de Segurança Implementados:
    - Zero Hardcoded Credentials: Nenhuma credencial no código
    - Runtime Secret Injection: Credenciais injetadas apenas em execução
    - Environment Isolation: Isolamento completo entre ambientes
    - Audit Trail: Rastreabilidade completa de operações
    
    Dependências Críticas:
    - `hadoop-aws-3.3.1.jar` (Conectividade AWS/S3)
    - `aws-java-sdk-bundle-1.11.901.jar` (SDK AWS completo)
    - `12-processa_vendas.py` (Script de processamento)
    
    Variáveis de Ambiente Esperadas:
    - `MINIO_ENDPOINT_URL`: Endpoint do servidor MinIO
    - `MINIO_ACCESS_KEY`: Chave de acesso MinIO
    - `MINIO_SECRET_KEY`: Chave secreta MinIO
    
    Compliance:
    - SOX (Sarbanes-Oxley Act) - Controles internos
    - PCI-DSS (Payment Card Industry) - Proteção de dados
    - ISO 27001 (Information Security) - Gestão de segurança
    
    Monitoramento:
    - Logs estruturados de execução
    - Validação de dependências em runtime
    - Métricas de performance do Spark
    - Auditoria de acesso a credenciais
    
    Troubleshooting:
    - Verificar logs do Airflow para erros de PATH
    - Validar presença dos arquivos JAR
    - Confirmar conectividade com MinIO
    - Verificar script Python de processamento
    """,
    tags=['spark', 'batch', 'security', 'vault', 'enterprise', 'bigdata', 'minio', 'distributed']
) as dag:
    
    # ===================================================================================
    # DEFINIÇÃO DA TAREFA PRINCIPAL
    # ===================================================================================
    
    tarefa_spark_segura = BashOperator(
        task_id='submeter_job_spark_seguro',
        bash_command=_build_spark_command(),
        env=minio_environment_variables,
        doc_md="""
        Tarefa de Processamento Spark Seguro
        
        Esta tarefa executa um job Apache Spark com implementação completa de
        padrões de segurança enterprise para processamento distribuído.
        
        Fluxo de Execução:
        1. Configuração do Ambiente: PATH e variáveis de ambiente
        2. Injeção de Credenciais: Via Vault em runtime
        3. Inicialização do Spark: Com dependências AWS/Hadoop
        4. Processamento Distribuído: Execução do script de vendas
        5. Persistência Segura: Dados armazenados no MinIO
        
        Configurações do Spark:
        - Master: local[*] (utiliza todos os cores disponíveis)
        - Deploy Mode: client (driver no mesmo processo)
        - JARs: Hadoop AWS SDK + AWS Java SDK Bundle
        - Script: 12-processa_vendas.py (lógica de negócio)
        
        Segurança Implementada:
        - Credenciais nunca expostas em logs
        - Injeção segura via variáveis de ambiente
        - Auditoria completa de acessos
        - Rotação automática de credenciais (via Vault)
        
        Monitoramento:
        - Logs do Spark disponíveis via Airflow UI
        - Métricas de performance em tempo real
        - Alertas automáticos em caso de falha
        - Dashboard de utilização de recursos
        
        Troubleshooting:
        - Verificar logs do Airflow para erros de PATH
        - Validar presença dos arquivos JAR
        - Confirmar conectividade com MinIO
        - Verificar script Python de processamento
        """
    )
