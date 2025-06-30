"""
====================================================================================
DAG DE GERENCIAMENTO DE LIFECYCLE DE DADOS - ARQUITETURA ENTERPRISE
====================================================================================

DESCRIÇÃO:
    Pipeline automatizado para gerenciamento do ciclo de vida de dados em armazenamento
    de objetos (MinIO/S3), movendo dados inativos da camada "Hot Storage" (Bronze Layer)
    para a "Cold Storage" (Cold Storage Layer). Essencial para otimização de custos,
    performance de consulta e compliance de retenção de dados.

ARQUITETURA DE ARMAZENAMENTO:
    Hot Storage (MinIO - Bronze) --> Mecanismo de Lifecycle (Verificação, Movimentação)
    --> Cold Storage (MinIO - Cold)

COMPONENTES TÉCNICOS:
    - MinIO / S3 Compatível Object Storage
    - Biblioteca Boto3 para interação com S3
    - Vault de Segurança para credenciais de acesso
    - Auditoria de operações de movimentação de dados
    - Logging estruturado para rastreabilidade

POLÍTICA DE LIFECYCLE:
    - Dados com mais de 30 dias de última modificação são considerados 'frios'.
    - Movimentação de objetos (copy + delete) entre buckets.

SEGURANÇA E COMPLIANCE:
    - Acesso seguro às credenciais de armazenamento via Vault.
    - Operações de movimentação de dados auditáveis.
    - Garante a conformidade com políticas de retenção de dados.

OTIMIZAÇÃO E PERFORMANCE:
    - Redução de custos de armazenamento em camadas de acesso frequente.
    - Melhoria da performance de leitura na camada "Hot" ao reduzir o volume.
    - Processamento paginado para lidar com grandes volumes de objetos.
====================================================================================
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
import logging
import json # Necessário para parsear credenciais do Vault, que são JSON string
from typing import Dict, Any, Optional
from pathlib import Path

import pendulum
import boto3
from botocore.exceptions import ClientError

from airflow.models.dag import DAG
from airflow.decorators import task

# Configuração do logger para a DAG (assumindo configuração externa ou básica)
logger = logging.getLogger(__name__)

# ---
# Configurações Globais
# ---

class LifecycleConfig:
    """Centraliza todas as configurações para a DAG de gerenciamento de lifecycle."""
    
    # Nomes dos buckets no MinIO/S3
    HOT_STORAGE_BUCKET: str = "bronze-layer"
    COLD_STORAGE_BUCKET: str = "cold-storage-layer"

    # Período de inatividade para considerar um arquivo 'cold' (em dias)
    INACTIVITY_THRESHOLD_DAYS: int = 30

    # Caminhos relacionados ao Airflow HOME para componentes de segurança
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json'
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'audit_lifecycle.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'system_lifecycle.log'

    # Chave do Vault para credenciais MinIO
    MINIO_VAULT_KEY: str = "minio_local_credentials"

# ---
# Funções Auxiliares de Segurança e Conexão
# ---

def _get_minio_client_secure() -> boto3.client:
    """
    Cria e retorna um cliente boto3 para interagir com o MinIO de forma segura.
    As credenciais são obtidas do Vault via `VaultManager`.

    Returns:
        boto3.client: Uma instância configurada do cliente S3 (boto3).

    Raises:
        ValueError: Se a variável de ambiente `SECURITY_VAULT_SECRET_KEY` não estiver definida
                    ou se as credenciais do MinIO não forem encontradas no Vault.
        ImportError: Se os módulos de segurança não puderem ser importados.
        ClientError: Se houver problemas de conexão com o MinIO usando as credenciais.
    """
    logger.info("Iniciando a obtenção segura do cliente MinIO/S3.")
    
    try:
        from plugins.security_system.vault_manager_helper import VaultManager # Importação CORRETA
        from plugins.security_system.audit import AuditLogger # Importado para uso no VaultManager e logs
    except ImportError as e:
        logger.critical(f"ERRO CRÍTICO: Módulos de segurança não encontrados. "
                        f"Verifique se 'plugins.security_system' está acessível no PYTHONPATH. Detalhes: {e}")
        raise ImportError(f"Dependência de segurança ausente: {e}")

    secret_key = os.getenv('SECURITY_VAULT_SECRET_KEY')
    if not secret_key:
        logger.critical("ERRO CRÍTICO: Variável de ambiente 'SECURITY_VAULT_SECRET_KEY' não definida.")
        raise ValueError("SECURITY_VAULT_SECRET_KEY não está definida. Acesso ao Vault negado.")

    # Inicializa AuditLogger para uso pelo VaultManager e para logging
    try:
        LifecycleConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LifecycleConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit_logger_instance = AuditLogger(
            audit_file_path=str(LifecycleConfig.AUDIT_LOG_PATH),
            system_log_file_path=str(LifecycleConfig.SYSTEM_LOG_PATH)
        )
    except Exception as e:
        logger.warning(f"Não foi possível inicializar AuditLogger: {e}. O logging de auditoria será limitado.")
        class SimpleAuditLogger: # Fallback simples
            def log(self, *args, **kwargs): pass
        audit_logger_instance = SimpleAuditLogger()

    # Inicializa VaultManager (o responsável por ler os segredos do vault.json)
    vault_manager = VaultManager(
        vault_path=str(LifecycleConfig.VAULT_JSON_PATH),
        secret_key=secret_key,
        logger=audit_logger_instance # Passa a instância do logger de auditoria
    )
    
    # Recupera credenciais do MinIO do Vault
    minio_creds_encrypted = vault_manager.get_secret(LifecycleConfig.MINIO_VAULT_KEY)
    
    if not minio_creds_encrypted:
        logger.critical(f"Credenciais '{LifecycleConfig.MINIO_VAULT_KEY}' não encontradas ou inválidas no Vault.")
        raise ValueError(f"Credenciais do MinIO não encontradas no Vault com a chave '{LifecycleConfig.MINIO_VAULT_KEY}'.")
    
    try:
        minio_creds = json.loads(minio_creds_encrypted) # Deserializa o JSON
    except json.JSONDecodeError as e:
        logger.critical(f"Erro ao decodificar credenciais do MinIO do Vault (JSON inválido): {e}")
        raise ValueError("Formato de credenciais MinIO no Vault inválido.")

    try:
        minio_client = boto3.client(
            "s3",
            endpoint_url=minio_creds.get('endpoint_url'),
            aws_access_key_id=minio_creds.get('access_key'),
            aws_secret_access_key=minio_creds.get('secret_key'),
            verify=False # ATENÇÃO: Em produção, defina para True e configure o certificado SSL apropriadamente.
        )
        # Teste de conexão básico
        minio_client.list_buckets() 
        logger.info("Cliente MinIO/S3 configurado e conexão testada com sucesso.")
        return minio_client
    except ClientError as e:
        logger.error(f"ERRO de conexão com MinIO/S3. Verifique as credenciais ou a URL do endpoint: {e}")
        raise
    except Exception as e:
        logger.error(f"ERRO inesperado ao criar cliente MinIO/S3: {e}")
        raise

# ---
# Tarefas da DAG
# ---

@task
def criar_bucket_cold_storage():
    """
    Tarefa Airflow: Garante a existência do bucket de 'cold storage' (destino)
    antes de qualquer operação de movimentação de dados. Cria o bucket se ele
    ainda não existir.
    """
    logger.info(f"Verificando existência do bucket de cold storage: '{LifecycleConfig.COLD_STORAGE_BUCKET}'")
    s3_client = _get_minio_client_secure()
    
    try:
        s3_client.head_bucket(Bucket=LifecycleConfig.COLD_STORAGE_BUCKET)
        logger.info(f"Bucket de cold storage '{LifecycleConfig.COLD_STORAGE_BUCKET}' já existe. Nenhuma ação necessária.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            logger.info(f"Bucket '{LifecycleConfig.COLD_STORAGE_BUCKET}' não encontrado. Iniciando criação...")
            try:
                s3_client.create_bucket(Bucket=LifecycleConfig.COLD_STORAGE_BUCKET)
                logger.info(f"Bucket de cold storage '{LifecycleConfig.COLD_STORAGE_BUCKET}' criado com sucesso.")
            except ClientError as create_error:
                logger.error(f"Falha ao criar o bucket '{LifecycleConfig.COLD_STORAGE_BUCKET}': {create_error}")
                raise
        else:
            logger.error(f"Erro inesperado ao checar o bucket '{LifecycleConfig.COLD_STORAGE_BUCKET}': {e}")
            raise
    except Exception as e:
        logger.error(f"Erro geral na tarefa de criação do bucket: {e}")
        raise

@task
def mover_arquivos_antigos():
    """
    Tarefa Airflow: Identifica e move arquivos antigos da camada de 'hot storage'
    (Bronze Layer) para a camada de 'cold storage'. Um arquivo é considerado antigo
    se sua última modificação exceder o limite de dias configurado.
    """
    logger.info(f"Iniciando movimentação de arquivos antigos do bucket '{LifecycleConfig.HOT_STORAGE_BUCKET}' para '{LifecycleConfig.COLD_STORAGE_BUCKET}'.")
    s3_client = _get_minio_client_secure()
    
    hoje = datetime.now() # Usar datetime.now() para a data atual
    arquivos_movidos_count = 0

    logger.info(f"Procurando arquivos com mais de {LifecycleConfig.INACTIVITY_THRESHOLD_DAYS} dias de inatividade.")
    
    try:
        # Usa um paginator para lidar com um grande número de objetos eficientemente
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=LifecycleConfig.HOT_STORAGE_BUCKET)
        
        found_files_in_bucket = False # Flag para verificar se o bucket tem arquivos
        for page in pages:
            if 'Contents' not in page:
                continue
            
            found_files_in_bucket = True
            for obj in page['Contents']:
                object_key = obj['Key']
                # Remover tzinfo para comparação com datetime.now()
                last_modified = obj['LastModified'].replace(tzinfo=None) 
                
                if (hoje - last_modified) > timedelta(days=LifecycleConfig.INACTIVITY_THRESHOLD_DAYS):
                    logger.info(f"-> Arquivo '{object_key}' é antigo (última modificação: {last_modified}). Movendo para cold storage...")
                    try:
                        copy_source = {'Bucket': LifecycleConfig.HOT_STORAGE_BUCKET, 'Key': object_key}
                        s3_client.copy_object(Bucket=LifecycleConfig.COLD_STORAGE_BUCKET, CopySource=copy_source, Key=object_key)
                        s3_client.delete_object(Bucket=LifecycleConfig.HOT_STORAGE_BUCKET, Key=object_key)
                        logger.info(f"-> Arquivo '{object_key}' movido e removido da origem com sucesso.")
                        arquivos_movidos_count += 1
                    except ClientError as ce:
                        logger.error(f"-> Erro ao mover/deletar '{object_key}': {ce}")
                    except Exception as e:
                        logger.error(f"-> Erro inesperado ao processar '{object_key}': {e}")
                else:
                    logger.info(f"-> Arquivo '{object_key}' é recente (última modificação: {last_modified}). Nenhuma ação necessária.")
        
        if not found_files_in_bucket:
            logger.info(f"O bucket '{LifecycleConfig.HOT_STORAGE_BUCKET}' está vazio. Nenhuma ação de movimentação necessária.")
        elif arquivos_movidos_count == 0:
            logger.info("Nenhum arquivo antigo encontrado para mover neste ciclo.")
        else:
            logger.info(f"Total de arquivos movidos para cold storage: {arquivos_movidos_count}.")

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            logger.warning(f"O bucket de origem '{LifecycleConfig.HOT_STORAGE_BUCKET}' não existe. Nada a fazer.")
        else:
            logger.error(f"Erro inesperado ao listar objetos no bucket de origem: {e}")
            raise
    except Exception as e:
        logger.error(f"Erro geral na tarefa de movimentação de arquivos: {e}")
        raise

# ---
# Definição da DAG
# ---

with DAG(
    dag_id='dag_gerenciamento_lifecycle_enterprise_v1',
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule_interval='@daily', # Execução diária para gerenciar o ciclo de vida
    catchup=False, # Não executa tarefas retroativamente para agendamentos perdidos
    max_active_runs=1, # Permite apenas uma execução ativa por vez
    doc_md="""
    ## DAG de Gerenciamento de Lifecycle de Dados - Enterprise Edition

    ### Objetivo
    Esta DAG implementa uma política de gerenciamento do ciclo de vida de dados,
    movendo automaticamente arquivos antigos da camada de "Hot Storage" (bronze-layer)
    para a camada de "Cold Storage" (cold-storage-layer) dentro do MinIO/S3.
    Este processo é fundamental para:
    - Otimização de Custos: Reduzir os custos de armazenamento de dados raramente acessados.
    - Performance: Melhorar a performance de leitura na camada "Hot" ao reduzir o volume de dados ativos.
    - Compliance: Atender a políticas de retenção e arquivamento de dados.

    ### Arquitetura de Fluxo
    ```mermaid
    graph TD
        A[MinIO: bronze-layer (Hot Storage)] -->|Listar Objetos| B{Identificar Arquivos Antigos}
        B -->|Mover (Copy Object)| C[MinIO: cold-storage-layer (Cold Storage)]
        C -->|Remover (Delete Object)| A
        PreCheck[Criar Bucket Destino] --> A
    ```
    - Pre-Check: Garante que o bucket de destino (cold-storage-layer) existe.
    - Listagem: Lista todos os objetos no bucket de origem (bronze-layer).
    - Identificação: Verifica a data da última modificação de cada objeto.
        Arquivos com mais de 30 dias de inatividade são marcados para movimentação.
    - Movimentação: O arquivo é copiado para o bucket de destino.
    - Remoção: Após a cópia bem-sucedida, o arquivo original é removido do bucket de origem.

    ### Componentes Chave
    - MinIO/S3: Plataforma de armazenamento de objetos.
    - Boto3: SDK Python para interação programática com S3.
    - Vault de Segurança: Armazena e recupera credenciais de acesso ao MinIO de forma segura.
    - Airflow Decorator Tasks: Utilização de @task para tarefas Python mais concisas.

    ### Segurança e Auditoria
    - As credenciais de acesso ao MinIO são recuperadas de um Vault centralizado,
        garantindo que não sejam expostas no código ou logs.
    - Todas as operações de verificação e movimentação de arquivos são logadas
        detalhadamente para fins de auditoria e rastreabilidade.

    ### Métricas e Monitoramento
    - Acompanhamento da quantidade de arquivos movidos por execução.
    - Logs informativos para cada arquivo processado (recente ou movido).

    """,
    tags=['lifecycle', 'minio', 's3', 'storage', 'data-governance', 'cost-optimization', 'enterprise']
) as dag:

    # ---
    # Definição das Tarefas
    # ---

    # Tarefa 1: Garante que o bucket de destino de cold storage exista
    criar_bucket_destino_task = criar_bucket_cold_storage()

    # Tarefa 2: Move arquivos da camada hot para cold storage
    mover_arquivos_para_cold_task = mover_arquivos_antigos()

    # ---
    # Definição do Fluxo de Tarefas
    # ---

    # O bucket de destino deve ser criado (ou verificado) antes que qualquer arquivo possa ser movido para ele.
    criar_bucket_destino_task >> mover_arquivos_para_cold_task
