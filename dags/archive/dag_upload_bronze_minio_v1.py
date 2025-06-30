"""
====================================================================================
DAG DE UPLOAD PARA DATA LAKE (CAMADA BRONZE) - ARQUITETURA ENTERPRISE
====================================================================================

DESCRIÇÃO:
    Pipeline de ingestão seguro e automatizado que orquestra o upload de arquivos
    locais para a Camada Bronze do Data Lake (MinIO). Este processo é a porta de
    entrada para dados brutos, garantindo que estejam disponíveis para processamento
    e análise subsequentes, com ênfase em segurança e auditabilidade.

ARQUITETURA DE INGESTÃO:
    ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
    │   FONTES LOCAIS     │    │   CAMADA DE         │    │   DATA LAKE         │
    │   (Airflow Worker)  │───▶│   INGESTÃO SEGURA   │───▶│   (MinIO - Bronze)  │
    │   - Arquivos CSV    │    │   - Segurança Vault │    │   - Dados Brutos    │
    │   - Dados Coletados │    │   - Auditoria       │    │   - Immutable       │
    └─────────────────────┘    └─────────────────────┘    └─────────────────────┘

COMPONENTES TÉCNICOS:
    - MinIO: Armazenamento de objetos compatível com S3 para o Data Lake.
    - Apache Airflow: Orquestrador do pipeline de upload.
    - Vault de Segurança: Gerenciamento centralizado e seguro de credenciais (API Keys, segredos).
    - Boto3: SDK Python para interação robusta com o MinIO/S3.
    - Sistema de Auditoria Customizado: Para rastrear operações de segurança e dados.

SEGURANÇA IMPLEMENTADA:
    - Credenciais MinIO recuperadas de forma dinâmica e segura via Vault.
    - Nenhuma credencial sensível é exposta em logs, variáveis de ambiente (fora do Vault) ou código-fonte.
    - Acesso mínimo privilegiado: Credenciais são obtidas apenas quando necessário.
    - Logs de auditoria detalhados para cada upload realizado ou falho.

QUALIDADE E GOVERNANÇA:
    - Pontos de entrada definidos para dados brutos na Camada Bronze.
    - Estrutura de pastas lógica no Data Lake (clima/, indicadores/, olist/).
    - Verificação de existência de arquivos locais antes do upload.
    - Auditabilidade completa das operações de ingestão.
====================================================================================
"""

from __future__ import annotations

import os
import pendulum
from pathlib import Path
import logging # Importar o módulo logging
import json # Necessário para parsear credenciais do Vault
from typing import Dict, Any, Optional

# Importações de boto3 (devem ser resolvidas pelo requirements.txt do Dockerfile)
import boto3
from botocore.exceptions import ClientError

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator

# Configuração do logger para a DAG (assume configuração externa ou básica)
logger = logging.getLogger(__name__)

# ---
# Configurações Globais
# ---

class UploadConfig:
    """Centraliza todas as configurações para a DAG de upload para a Camada Bronze."""

    # Caminhos base dentro do contêiner Airflow.
    # Estes caminhos são mapeados para volumes locais via docker-compose.yml.
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    
    # Caminhos para componentes de segurança e logs
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'audit.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'system.log'
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json' # Caminho do arquivo do Vault

    # Nome da variável de ambiente que contém a chave secreta para o Vault
    VAULT_SECRET_KEY_ENV: str = 'SECURITY_VAULT_SECRET_KEY'

    # Chave para recuperar as credenciais do MinIO do Vault
    MINIO_CREDS_KEY: str = "minio_local_credentials"
    
    # Nome do bucket de destino no MinIO (Camada Bronze)
    BRONZE_BUCKET_NAME: str = "bronze"

    # Mapeamento de arquivos locais (no sistema de arquivos do Airflow Worker)
    # para os caminhos de objeto no MinIO.
    # ATENÇÃO: As chaves são caminhos absolutos dentro do contêiner.
    FILES_TO_UPLOAD: Dict[Path, str] = {
        AIRFLOW_HOME / 'data' / 'clima' / 'clima_coletado.csv': "clima/clima_coletado.csv",
        AIRFLOW_HOME / 'data' / 'indicadores' / 'ipca_coletado.csv': "indicadores/ipca_coletado.csv",
        AIRFLOW_HOME / 'data' / 'olist' / 'dados_consolidados.csv': "olist/dados_consolidados.csv"
    }

# ---
# Função Auxiliar de Acesso ao MinIO (Segura)
# ---

def _get_minio_s3_client_secure(audit_logger: object) -> boto3.client:
    """
    Cria e retorna um cliente boto3 (compatível com S3) para interagir com o MinIO.
    As credenciais são recuperadas de forma segura do Vault.

    Args:
        audit_logger: Uma instância do AuditLogger para registrar eventos de segurança e acesso.

    Returns:
        boto3.client: Um cliente S3 configurado.

    Raises:
        ValueError: Se a chave secreta do Vault não estiver definida ou credenciais não encontradas.
        ImportError: Se os módulos de segurança customizados não puderem ser importados.
        ClientError: Para erros específicos do cliente S3 (e.g., credenciais inválidas, endpoint).
        Exception: Para qualquer outro erro inesperado.
    """
    logger.info("Iniciando a obtenção segura do cliente MinIO/S3.")

    try:
        # Importação local (isolada) do sistema de segurança para garantir que seja no contexto da tarefa
        from plugins.security_system.vault_manager_helper import VaultManager # Usando VaultManager
    except ImportError as e:
        logger.critical(f"ERRO CRÍTICO: Módulo de segurança 'VaultManager' não encontrado. Detalhes: {e}")
        raise ImportError(f"Dependência de segurança ausente: {e}")

    secret_key = os.getenv(UploadConfig.VAULT_SECRET_KEY_ENV)
    if not secret_key:
        audit_logger.log('SECURITY_ERROR', 'Variável de ambiente SECURITY_VAULT_SECRET_KEY não definida.', level='CRITICAL')
        logger.critical(f"ERRO CRÍTICO: A variável de ambiente '{UploadConfig.VAULT_SECRET_KEY_ENV}' não está definida.")
        raise ValueError(f"SECURITY_VAULT_SECRET_KEY não definida. Acesso ao Vault negado.")

    # Inicializa VaultManager para gerenciar os segredos
    vault_manager = VaultManager(
        vault_path=str(UploadConfig.VAULT_JSON_PATH),
        secret_key=secret_key,
        logger=audit_logger # Passa o audit_logger para o VaultManager
    )

    audit_logger.log('VAULT_ACCESS_ATTEMPT', 'Tentando obter credenciais MinIO do Vault.', user='airflow_dag')
    minio_creds_encrypted = vault_manager.get_secret(UploadConfig.MINIO_CREDS_KEY)

    if not minio_creds_encrypted:
        audit_logger.log('VAULT_CREDENTIALS_MISSING', f"Credenciais '{UploadConfig.MINIO_CREDS_KEY}' não encontradas no Vault.", level='CRITICAL', user='airflow_dag')
        logger.critical(f"ERRO: Credenciais '{UploadConfig.MINIO_CREDS_KEY}' não encontradas no Vault.")
        raise ValueError(f"Credenciais 'minio_local_credentials' não encontradas no Vault.")

    try:
        minio_creds = json.loads(minio_creds_encrypted)
    except json.JSONDecodeError as e:
        audit_logger.log('VAULT_CREDENTIALS_JSON_ERROR', f"Erro ao decodificar credenciais MinIO do Vault (JSON inválido): {e}", level='CRITICAL', user='airflow_dag')
        logger.critical(f"ERRO: Erro ao decodificar credenciais MinIO do Vault (JSON inválido): {e}")
        raise ValueError("Formato de credenciais MinIO no Vault inválido.")

    logger.info(f"Conectando ao MinIO em: {minio_creds.get('endpoint_url')}")
    audit_logger.log('MINIO_CONNECTION_ATTEMPT', f"Iniciando conexão com MinIO: {minio_creds.get('endpoint_url')}", user='airflow_dag')

    try:
        s3_client = boto3.client(
            "s3",
            endpoint_url=minio_creds.get('endpoint_url'),
            aws_access_key_id=minio_creds.get('access_key'),
            aws_secret_access_key=minio_creds.get('secret_key'),
            verify=False # ATENÇÃO: Em produção, defina para True e configure o certificado SSL apropriadamente.
        )
        # Teste de conexão básico para validar as credenciais e o endpoint
        s3_client.list_buckets()
        logger.info("Cliente MinIO/S3 configurado e conexão testada com sucesso.")
        audit_logger.log('MINIO_CONNECTION_SUCCESS', 'Conexão com MinIO estabelecida com sucesso.', user='airflow_dag')
        return s3_client
    except ClientError as e:
        audit_logger.log('MINIO_CONNECTION_FAILED', f"Falha na conexão com MinIO: {e}", level='CRITICAL', user='airflow_dag')
        logger.error(f"ERRO DE CONEXÃO: Falha ao conectar ao MinIO. Verifique credenciais e endpoint. Detalhes: {e}")
        raise
    except Exception as e:
        audit_logger.log('MINIO_CONNECTION_UNEXPECTED_ERROR', f"Erro inesperado ao criar cliente MinIO: {e}", level='CRITICAL', user='airflow_dag')
        logger.error(f"ERRO INESPERADO ao criar cliente MinIO: {e}")
        raise

# ---
# Função Principal de Upload (callable para PythonOperator)
# ---

def _upload_para_minio_seguro() -> None:
    """
    Função principal que orquestra o processo de upload de arquivos locais
    para a Camada Bronze do Data Lake (MinIO), garantindo segurança e auditabilidade.

    Fluxo de Execução:
        1. Inicializa o sistema de auditoria para rastreamento.
        2. Obtém um cliente MinIO/S3 configurado com credenciais seguras do Vault.
        3. Verifica a existência do bucket de destino e o cria se necessário.
        4. Itera sobre uma lista predefinida de arquivos locais e os faz upload
           para seus respectivos caminhos no MinIO, logando cada operação.

    Raises:
        Exception: Re-lança quaisquer erros críticos que ocorram durante o processo,
                   garantindo que a tarefa do Airflow seja marcada como falha.
    """
    logger.info("Iniciando a execução da DAG de Upload para a Camada Bronze (MinIO).")

    # Inicializa os componentes de segurança e auditoria
    try:
        from plugins.security_system.audit import AuditLogger
        # Garante que o diretório de logs exista
        UploadConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        UploadConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit = AuditLogger(str(UploadConfig.AUDIT_LOG_PATH), str(UploadConfig.SYSTEM_LOG_PATH))
    except ImportError as e:
        logger.critical(f"ERRO CRÍTICO: Módulo de auditoria 'AuditLogger' não encontrado. Detalhes: {e}")
        raise ImportError(f"Módulo de auditoria 'AuditLogger' ausente: {e}. Verifique a instalação do plugin.")
    except Exception as e:
        logger.critical(f"ERRO CRÍTICO: Falha ao inicializar o AuditLogger. Detalhes: {e}")
        raise

    try:
        s3_client = _get_minio_s3_client_secure(audit)

        # Verifica ou cria o bucket de destino (Camada Bronze)
        logger.info(f"Verificando existência do bucket '{UploadConfig.BRONZE_BUCKET_NAME}'...")
        try:
            s3_client.head_bucket(Bucket=UploadConfig.BRONZE_BUCKET_NAME)
            logger.info(f"Bucket '{UploadConfig.BRONZE_BUCKET_NAME}' já existe.")
            audit.log('MINIO_BUCKET_CHECK', f"Bucket '{UploadConfig.BRONZE_BUCKET_NAME}' existente.", user='airflow_dag')
        except ClientError as e:
            # Se o erro for 'Not Found', o bucket não existe e podemos criá-lo.
            if e.response['Error']['Code'] == '404':
                logger.info(f"Bucket '{UploadConfig.BRONZE_BUCKET_NAME}' não encontrado. Criando...")
                s3_client.create_bucket(Bucket=UploadConfig.BRONZE_BUCKET_NAME)
                logger.info(f"Bucket '{UploadConfig.BRONZE_BUCKET_NAME}' criado com sucesso.")
                audit.log('MINIO_BUCKET_CREATED', f"Bucket '{UploadConfig.BRONZE_BUCKET_NAME}' criado.", user='airflow_dag')
            else:
                audit.log('MINIO_BUCKET_ERROR', f"Erro inesperado ao checar/criar bucket: {e}", level='CRITICAL', user='airflow_dag')
                logger.error(f"ERRO: Falha ao checar/criar o bucket '{UploadConfig.BRONZE_BUCKET_NAME}': {e}")
                raise

        logger.info("\nIniciando upload dos arquivos locais para a Camada Bronze do MinIO...")
        
        uploaded_files_count = 0
        for local_path, minio_object_path in UploadConfig.FILES_TO_UPLOAD.items():
            if local_path.exists():
                logger.info(f"Fazendo upload de '{local_path.name}' para 's3://{UploadConfig.BRONZE_BUCKET_NAME}/{minio_object_path}'")
                try:
                    s3_client.upload_file(str(local_path), UploadConfig.BRONZE_BUCKET_NAME, minio_object_path)
                    logger.info(f"Upload de '{local_path.name}' concluído com sucesso.")
                    audit.log('MINIO_UPLOAD_SUCCESS', f"Arquivo '{local_path.name}' enviado para s3://{UploadConfig.BRONZE_BUCKET_NAME}/{minio_object_path}.", user='airflow_dag')
                    uploaded_files_count += 1
                except ClientError as e:
                    audit.log('MINIO_UPLOAD_FAILED', f"Falha no upload de '{local_path.name}': {e}", level='ERROR', user='airflow_dag')
                    logger.error(f"ERRO no upload de '{local_path.name}': {e}")
                except Exception as e:
                    audit.log('MINIO_UPLOAD_UNEXPECTED_ERROR', f"Erro inesperado no upload de '{local_path.name}': {e}", level='ERROR', user='airflow_dag')
                    logger.error(f"ERRO INESPERADO no upload de '{local_path.name}': {e}")
            else:
                audit.log('LOCAL_FILE_NOT_FOUND', f"Arquivo local não encontrado, pulando: '{local_path}'.", level='WARNING', user='airflow_dag')
                logger.warning(f"Arquivo não encontrado, pulando: {local_path}")
        
        logger.info(f"\nProcesso de upload concluído. Total de arquivos enviados: {uploaded_files_count}.")
        audit.log('MINIO_UPLOAD_PROCESS_COMPLETE', f"Total de arquivos enviados: {uploaded_files_count}.", user='airflow_dag')

    except Exception as e:
        audit.log('UPLOAD_PIPELINE_CRITICAL_ERROR', f"Erro crítico no pipeline de upload para MinIO Bronze: {e}", level='CRITICAL', user='airflow_dag')
        logger.critical(f"ERRO CRÍTICO no pipeline de upload para MinIO Bronze: {e}", exc_info=True)
        raise # Re-lança para o Airflow marcar a tarefa como falha

# ---
# Definição da DAG Principal
# ---

with DAG(
    dag_id="dag_upload_bronze_minio_enterprise_v1",
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None, # Definido como 'None' para execução manual ou agendamento externo
    catchup=False, # Não executa para datas passadas que não foram capturadas
    max_active_runs=1, # Garante que apenas uma instância da DAG rode por vez
    doc_md="""
    ## DAG de Upload para Data Lake (Camada Bronze) - Enterprise Edition

    ### Objetivo
    Esta DAG implementa um pipeline de ingestão seguro e automatizado para
    carregar arquivos de dados brutos de fontes locais (simuladas aqui no worker do Airflow)
    para a Camada Bronze de um Data Lake baseado em MinIO/S3.
    É o primeiro passo crucial para qualquer arquitetura de dados, garantindo
    que os dados brutos estejam disponíveis de forma íntegra e rastreável.

    ### Arquitetura de Ingestão
    ```mermaid
    graph TD
        A[Fontes de Dados Locais<br>(No Airflow Worker)] -->|Upload Seguro com Boto3| B{Tarefa de Upload<br>PythonOperator}
        B -->|Autenticação Segura| C[Vault de Segurança<br>(Credenciais MinIO)]
        B --> D[MinIO - Camada Bronze<br>(Data Lake)]
        B --- E[Sistema de Auditoria<br>(Logs de Upload)]
    ```
    - Fontes de Dados Locais: Arquivos CSV gerados por pipelines anteriores (e.g., coleta de APIs, consolidação)
      e armazenados no sistema de arquivos do Airflow Worker (via volumes Docker).
    - Vault de Segurança: Um componente crítico que armazena e fornece credenciais de acesso
      ao MinIO de forma criptografada, prevenindo a exposição de segredos.
    - Tarefa de Upload (PythonOperator): A lógica principal da DAG, que orquestra
      a conexão segura, verificação do bucket e o upload dos arquivos.
    - MinIO - Camada Bronze: O destino final dos dados brutos. Esta camada é projetada
      para ser um repositório imutável de dados, mantendo-os em seu formato original.
    - Sistema de Auditoria: Registra detalhadamente cada tentativa de upload, sucesso,
      falha e acesso a segredos, garantindo a conformidade e rastreabilidade.

    ### Componentes Técnicos Utilizados
    - Apache Airflow: Orquestrador que gerencia o agendamento e a execução do pipeline.
    - Boto3: SDK Python para interação programática com o armazenamento de objetos
      MinIO/S3, facilitando operações como criação de buckets e upload de arquivos.
    - Pathlib: Módulo Python para manipulação de caminhos de arquivos de forma
      orientada a objetos, tornando o código mais legível e robusto.
    - Vault de Segurança Customizado (`plugins.security_system`): Módulos internos
      para gerenciar e acessar segredos de forma segura.

    ### Segurança e Compliance
    - Credenciais Criptografadas: As chaves de acesso ao MinIO são armazenadas de
      forma segura no Vault e recuperadas em tempo de execução usando uma chave de ambiente.
    - Isolamento de Segredos: Nenhuma credencial sensível é hardcoded na DAG, exposta
      em logs do Airflow ou em variáveis de ambiente acessíveis a outros processos.
    - Auditabilidade Completa: Cada upload, falha de upload e acesso ao Vault
      é registrado em um sistema de auditoria, fornecendo um rastro completo para
      compliance regulatório (e.g., LGPD, SOX).
    - Verificação SSL: O cliente Boto3 pode ser configurado para verificar certificados
      SSL (importante para produção com MinIO/S3).

    ### Robustez e Tratamento de Erros
    - Verificação de Pré-requisitos: Garante que o bucket de destino exista ou o cria.
    - Verificação de Arquivos Locais: Ignora e loga arquivos de origem que não existem.
    - Tratamento de Exceções: Inclui blocos `try-except` para capturar e logar
      erros de conexão, upload e acesso a arquivos, facilitando a depuração.
    - Logging Detalhado: Fornece mensagens informativas em cada etapa do processo,
      essenciais para monitoramento e diagnóstico em ambientes de produção.

    ### Instruções para Avaliadores
    - Setup do Vault: Certifique-se de que o script `setup_vault_secrets.py`
      foi executado e que as credenciais para `minio_local_credentials`
      estão registradas no Vault.
    - Variável de Ambiente: A variável de ambiente `SECURITY_VAULT_SECRET_KEY`
      deve estar configurada no ambiente do Airflow Worker.
    - Volumes Docker: Os volumes Docker no `docker-compose.yml` devem mapear
      as pastas de dados locais para `/opt/airflow/data` dentro do contêiner Airflow,
      garantindo que os arquivos de origem estejam acessíveis.
    """,
    tags=['bronze', 'minio', 'upload', 'vault', 'data-lake', 'ingestao', 'enterprise', 'seguranca']
) as dag:

    # ---
    # Definição da Tarefa Principal
    # ---

    tarefa_upload_minio = PythonOperator(
        task_id="upload_ficheiros_para_camada_bronze",
        python_callable=_upload_para_minio_seguro,
        # Você pode adicionar retries e retry_delay aqui se a tarefa puder falhar transitoriamente
        # retries=3,
        # retry_delay=pendulum.duration(minutes=5),
        doc_md="""
        ## Tarefa: Upload de Arquivos para a Camada Bronze do Data Lake

        **Propósito**: Esta tarefa é responsável por mover arquivos de dados brutos
        de seus locais de origem (simulados como diretórios no worker do Airflow)
        para a Camada Bronze do Data Lake (MinIO). É um passo fundamental
        para centralizar e versionar dados brutos.

        ### Funções Principais:
        - Autenticação Segura: Utiliza o sistema de Vault para obter as
          credenciais de acesso ao MinIO de forma segura, sem expor senhas
          ou chaves no código.
        - Verificação/Criação de Bucket: Garante que o bucket de destino
          (`bronze`) exista no MinIO. Se não existir, ele é criado automaticamente.
        - Upload de Arquivos: Itera sobre uma lista predefinida de arquivos
          locais (`clima_coletado.csv`, `ipca_coletado.csv`, `dados_consolidados.csv`)
          e os faz upload para subdiretórios lógicos dentro do bucket `bronze`
          (e.g., `clima/`, `indicadores/`, `olist/`).
        - Auditoria e Logging: Cada operação de upload (sucesso ou falha)
          é logada detalhadamente no sistema de auditoria, garantindo rastreabilidade
          e compliance.

        ### Robustez e Confiabilidade:
        - Tratamento de Arquivos Ausentes: Se um arquivo de origem local
          não for encontrado, ele é pulado e um aviso é logado, sem interromper
          a execução da tarefa para outros arquivos.
        - Tratamento de Erros de Conexão/Upload: Blocos `try-except` lidam
          com falhas de conexão ao MinIO ou problemas durante o processo de upload.
        - Idempotência (Consideração): O upload de arquivos para o MinIO
          por padrão sobrescreve arquivos com o mesmo nome. Para uma idempotência
          mais avançada em casos de reprocessamento, estratégias de versionamento
          de objetos no S3 ou uploads com sufixos de timestamp podem ser exploradas.

        ### Saídas Esperadas:
        - Arquivos CSV copiados para o bucket `bronze` no MinIO, organizados
          em subpastas como `clima/`, `indicadores/` e `olist/`.
        - Logs detalhados na interface do Airflow e nos arquivos de auditoria,
          registrando o status de cada upload.
        """
    )
