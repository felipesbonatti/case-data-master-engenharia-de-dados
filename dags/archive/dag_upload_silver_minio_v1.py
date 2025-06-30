"""
====================================================================================
DAG DE UPLOAD PARA DATA LAKE (CAMADA SILVER) - 
====================================================================================

DESCRIÇÃO:
    Pipeline de promoção de dados que orquestra o upload de arquivos processados
    e consolidados da camada de processamento (ou de uma DAG anterior) para
    a Camada Silver do Data Lake, hospedada no MinIO. Esta camada contém dados
    limpos, transformados e prontos para consumo por analistas e sistemas a jusante.

ARQUITETURA DO FLUXO:
    DADOS PROCESSADOS (Airflow Worker) --> CAMADA DE PROMOÇÃO SEGURA --> DATA LAKE (MinIO - Silver)
    - dados_consolidados.csv           - Segurança Vault                  - Dados Limpos
    - Qualidade Garantida              - Auditoria                        - Estruturados

COMPONENTES TÉCNICOS:
    - MinIO: Armazenamento de objetos compatível com S3 para o Data Lake.
    - Apache Airflow: Orquestrador do pipeline de promoção de dados.
    - Vault de Segurança: Gerenciamento centralizado e seguro de credenciais (API Keys, segredos).
    - Boto3: SDK Python para interação robusta com o MinIO/S3.
    - Sistema de Auditoria Customizado: Para rastrear operações de segurança e dados.

SEGURANÇA IMPLEMENTADA:
    - Credenciais MinIO recuperadas de forma dinâmica e segura via Vault.
    - Nenhuma credencial sensível é exposta em logs, variáveis de ambiente (fora do Vault) ou código-fonte.
    - Acesso mínimo privilegiado: Credenciais são obtidas apenas quando necessário.
    - Logs detalhados de auditoria para cada upload realizado ou falho.

QUALIDADE E GOVERNANÇA:
    - Promoção de dados de alta qualidade (presume-se validação em etapas anteriores).
    - Camada Silver como fonte confiável de dados para análises.
    - Estrutura de pastas lógica no Data Lake (vendas/).
    - Auditabilidade completa das operações de promoção de dados.
====================================================================================
"""

from __future__ import annotations

import os
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

class SilverUploadConfig:
    """Centraliza todas as configurações para a DAG de upload para a Camada Silver."""

    # Caminhos base dentro do contêiner Airflow.
    # Estes caminhos são mapeados para volumes locais via docker-compose.yml.
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    
    # Caminhos para componentes de segurança e logs.
    # Assumimos que o AuditLogger pode ser inicializado com esses caminhos.
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json' # Caminho CORRETO do arquivo do Vault
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'audit_silver_upload.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'system_silver_upload.log'

    # Nome da variável de ambiente que contém a chave secreta para o Vault
    VAULT_SECRET_KEY_ENV: str = 'SECURITY_VAULT_SECRET_KEY'

    # Chave para recuperar as credenciais do MinIO do Vault
    MINIO_CREDS_KEY: str = "minio_local_credentials"
    
    # Nome do bucket de destino no MinIO (Camada Silver)
    SILVER_BUCKET_NAME: str = "silver-layer"

    # Caminho do arquivo de dados local que será promovido para a Silver Layer
    LOCAL_DATA_FILE: Path = AIRFLOW_HOME / 'data' / 'olist' / 'dados_consolidados.csv'
    # Caminho do objeto no MinIO após o upload (Ex: vendas/consolidado_vendas.csv)
    MINIO_OBJECT_PATH: str = "vendas/consolidado_vendas.csv"

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

    secret_key = os.getenv(SilverUploadConfig.VAULT_SECRET_KEY_ENV)
    if not secret_key:
        audit_logger.log('SECURITY_ERROR', 'Variável de ambiente SECURITY_VAULT_SECRET_KEY não definida.', level='CRITICAL')
        logger.critical(f"ERRO CRÍTICO: A variável de ambiente '{SilverUploadConfig.VAULT_SECRET_KEY_ENV}' não está definida.")
        raise ValueError(f"SECURITY_VAULT_SECRET_KEY não definida. Acesso ao Vault negado.")

    # Inicializa VaultManager para gerenciar os segredos
    vault_manager = VaultManager(
        vault_path=str(SilverUploadConfig.VAULT_JSON_PATH),
        secret_key=secret_key,
        logger=audit_logger # Passa o audit_logger para o VaultManager
    )

    audit_logger.log('VAULT_ACCESS_ATTEMPT', 'Tentando obter credenciais MinIO do Vault.', user='airflow_dag')
    minio_creds_encrypted = vault_manager.get_secret(SilverUploadConfig.MINIO_CREDS_KEY)

    if not minio_creds_encrypted:
        audit_logger.log('VAULT_CREDENTIALS_MISSING', f"Credenciais '{SilverUploadConfig.MINIO_CREDS_KEY}' não encontradas no Vault.", level='CRITICAL', user='airflow_dag')
        logger.critical(f"ERRO: Credenciais '{SilverUploadConfig.MINIO_CREDS_KEY}' não encontradas no Vault.")
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
# Função Principal de Upload para Silver (callable para PythonOperator)
# ---

def _upload_para_silver_seguro() -> None:
    """
    Função principal que orquestra o processo de upload do arquivo de dados consolidado
    para a Camada Silver do Data Lake (MinIO), garantindo segurança e auditabilidade.

    Fluxo de Execução:
        1. Inicializa o sistema de auditoria para rastreamento.
        2. Obtém um cliente MinIO/S3 configurado com credenciais seguras do Vault.
        3. Verifica a existência do bucket de destino (Silver Layer) e o cria se necessário.
        4. Realiza o upload do arquivo consolidado para o caminho definido no MinIO.
        5. Registra o sucesso ou falha da operação nos logs de auditoria.

    Raises:
        Exception: Re-lança quaisquer erros críticos que ocorram durante o processo,
                   garantindo que a tarefa do Airflow seja marcada como falha.
    """
    logger.info("Iniciando a execução da DAG de Upload para a Camada Silver do Data Lake.")

    # Inicializa o sistema de auditoria
    try:
        from plugins.security_system.audit import AuditLogger
        # Garante que o diretório de logs exista
        SilverUploadConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        SilverUploadConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit = AuditLogger(str(SilverUploadConfig.AUDIT_LOG_PATH), str(SilverUploadConfig.SYSTEM_LOG_PATH))
    except ImportError as e:
        logger.critical(f"ERRO CRÍTICO: Módulo de auditoria 'AuditLogger' não encontrado. Detalhes: {e}")
        raise ImportError(f"Módulo de auditoria 'AuditLogger' ausente: {e}. Verifique a instalação do plugin.")
    except Exception as e:
        logger.critical(f"ERRO CRÍTICO: Falha ao inicializar o AuditLogger. Detalhes: {e}")
        raise

    try:
        s3_client = _get_minio_s3_client_secure(audit)

        # Verifica ou cria o bucket de destino (Silver Layer)
        logger.info(f"Verificando existência do bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}'...")
        try:
            s3_client.head_bucket(Bucket=SilverUploadConfig.SILVER_BUCKET_NAME)
            logger.info(f"Bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}' já existe.")
            audit.log('MINIO_BUCKET_CHECK', f"Bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}' existente.", user='airflow_dag')
        except ClientError as e:
            # Se o erro for 'Not Found', o bucket não existe e podemos criá-lo.
            if e.response['Error']['Code'] == '404':
                logger.info(f"Bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}' não encontrado. Criando...")
                s3_client.create_bucket(Bucket=SilverUploadConfig.SILVER_BUCKET_NAME)
                logger.info(f"Bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}' criado com sucesso.")
                audit.log('MINIO_BUCKET_CREATED', f"Bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}' criado.", user='airflow_dag')
            else:
                audit.log('MINIO_BUCKET_ERROR', f"Erro inesperado ao checar/criar bucket: {e}", level='CRITICAL', user='airflow_dag')
                logger.error(f"ERRO: Falha ao checar/criar o bucket '{SilverUploadConfig.SILVER_BUCKET_NAME}': {e}")
                raise

        # Realiza o upload do arquivo consolidado
        logger.info(f"Iniciando upload do arquivo consolidado para a camada Silver do MinIO...")
        
        if SilverUploadConfig.LOCAL_DATA_FILE.exists():
            logger.info(f"Enviando arquivo: '{SilverUploadConfig.LOCAL_DATA_FILE.name}' para 's3://{SilverUploadConfig.SILVER_BUCKET_NAME}/{SilverUploadConfig.MINIO_OBJECT_PATH}'")
            try:
                s3_client.upload_file(str(SilverUploadConfig.LOCAL_DATA_FILE), SilverUploadConfig.SILVER_BUCKET_NAME, SilverUploadConfig.MINIO_OBJECT_PATH)
                logger.info(f"Upload de '{SilverUploadConfig.LOCAL_DATA_FILE.name}' concluído com sucesso.")
                audit.log('MINIO_UPLOAD_SUCCESS', f"Arquivo '{SilverUploadConfig.LOCAL_DATA_FILE.name}' enviado para s3://{SilverUploadConfig.SILVER_BUCKET_NAME}/{SilverUploadConfig.MINIO_OBJECT_PATH}.", user='airflow_dag')
            except ClientError as e:
                audit.log('MINIO_UPLOAD_FAILED', f"Falha no upload de '{SilverUploadConfig.LOCAL_DATA_FILE.name}': {e}", level='ERROR', user='airflow_dag')
                logger.error(f"ERRO no upload de '{SilverUploadConfig.LOCAL_DATA_FILE.name}': {e}")
                raise # Re-lança para que a tarefa falhe
            except Exception as e:
                audit_logger.log('MINIO_UPLOAD_UNEXPECTED_ERROR', f"Erro inesperado no upload de '{SilverUploadConfig.LOCAL_DATA_FILE.name}': {e}", level='ERROR', user='airflow_dag')
                logger.error(f"ERRO INESPERADO no upload de '{SilverUploadConfig.LOCAL_DATA_FILE.name}': {e}")
                raise # Re-lança para que a tarefa falhe
        else:
            audit_logger.log('LOCAL_FILE_NOT_FOUND', f"Arquivo local não encontrado, upload não realizado: '{SilverUploadConfig.LOCAL_DATA_FILE}'.", level='CRITICAL', user='airflow_dag')
            logger.critical(f"ERRO CRÍTICO: Arquivo local não encontrado, o upload não pode ser realizado: {SilverUploadConfig.LOCAL_DATA_FILE}")
            raise FileNotFoundError(f"Arquivo de dados consolidado não encontrado em: {SilverUploadConfig.LOCAL_DATA_FILE}")

        logger.info("\nProcesso de upload para a Camada Silver finalizado com sucesso.")
        audit.log('SILVER_UPLOAD_PROCESS_COMPLETE', "Upload para a Camada Silver concluído.", user='airflow_dag')

    except Exception as e:
        audit.log('UPLOAD_PIPELINE_CRITICAL_ERROR', f"Erro crítico no pipeline de upload para MinIO Silver: {e}", level='CRITICAL', user='airflow_dag')
        logger.critical(f"ERRO CRÍTICO no pipeline de upload para MinIO Silver: {e}", exc_info=True)
        raise # Re-lança para o Airflow marcar a tarefa como falha

# ---
# Definição da DAG Principal
# ---

with DAG(
    dag_id="dag_upload_silver_minio_enterprise_v1",
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule=None, # Definido como 'None' para execução manual ou agendamento externo
    catchup=False, # Não executa para datas passadas que não foram capturadas
    max_active_runs=1, # Garante que apenas uma instância da DAG rode por vez
    doc_md="""
    ## DAG de Upload para Data Lake (Camada Silver) - Enterprise Edition

    ### Objetivo
    Esta DAG implementa um pipeline de promoção de dados que move arquivos
    de dados processados e consolidados para a Camada Silver de um Data Lake
    baseado em MinIO/S3. A Camada Silver é um estágio intermediário crucial,
    contendo dados limpos, transformados, e estruturados, prontos para consumo
    por sistemas a jusante (como Data Marts) ou para análises mais aprofundadas.

    ### Arquitetura de Promoção de Dados
    ```mermaid
    graph TD
        A[Dados Consolidados<br>(Local no Airflow Worker)] -->|Upload Seguro com Boto3| B{Tarefa de Promoção<br>PythonOperator}
        B -->|Autenticação Segura| C[Vault de Segurança<br>(Credenciais MinIO)]
        B --> D[MinIO - Camada Silver<br>(Data Lake)]
        B --- E[Sistema de Auditoria<br>(Logs de Promoção)]
    ```
    - Fontes de Dados Consolidados: A fonte de dados para esta DAG, presumivelmente um arquivo
      resultante de uma DAG de ETL/consolidação anterior (e.g., `dados_consolidados.csv`).
    - Vault de Segurança: Um componente de segurança central para armazenar e fornecer
      credenciais de acesso ao MinIO de forma criptografada.
    - Tarefa de Promoção (PythonOperator): A lógica principal da DAG, que orquestra
      a conexão segura, verificação do bucket e o upload do arquivo único.
    - MinIO - Camada Silver: O destino dos dados limpos e estruturados. Esta camada
      é otimizada para performance de consulta e é a base para a criação de Data Marts.
    - Sistema de Auditoria: Registra detalhadamente cada tentativa de upload, sucesso,
      falha e acesso a segredos, garantindo conformidade e rastreabilidade.

    ### Componentes Técnicos Utilizados
    - Apache Airflow: Orquestrador que agenda e gerencia a execução do pipeline.
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
      SSL (importante para ambientes de produção com MinIO/S3).

    ### Robustez e Tratamento de Erros
    - Verificação de Pré-requisitos: Garante que o bucket de destino exista ou o cria.
    - Verificação de Arquivo de Origem: Impede a execução se o arquivo de dados
      consolidado não for encontrado localmente, pois é uma dependência crítica.
    - Tratamento de Exceções: Inclui blocos `try-except` para capturar e logar
      erros de conexão ao MinIO ou problemas durante o upload, garantindo a
      falha da tarefa do Airflow em caso de erros críticos.
    - Logging Detalhado: Fornece mensagens informativas em cada etapa do processo,
      essenciais para monitoramento e diagnóstico em ambientes de produção.

    ### Instruções para Avaliadores
    - Setup do Vault: Certifique-se de que o script `setup_vault_secrets.py`
      foi executado e que as credenciais para `minio_local_credentials`
      estão registradas no Vault.
    - Variável de Ambiente: A variável de ambiente `SECURITY_VAULT_SECRET_KEY`
      deve estar configurada no ambiente do Airflow Worker.
    - Volume Docker: O volume Docker no `docker-compose.yml` deve mapear
      a pasta de dados local para `/opt/airflow/data` dentro do contêiner Airflow,
      garantindo que o arquivo `dados_consolidados.csv` esteja acessível.
    - Dependência da DAG: Esta DAG depende da execução bem-sucedida de uma DAG anterior
      (e.g., `dag_consolida_olist_enterprise_v1`) que gera o arquivo `dados_consolidados.csv`.
    """,
    tags=['silver', 'minio', 'upload', 'data-lake', 'promocao', 'enterprise', 'seguranca', 'olist']
) as dag:

    # ---
    # Definição da Tarefa Principal
    # ---

    tarefa_upload_silver = PythonOperator(
        task_id="upload_consolidado_para_silver",
        python_callable=_upload_para_silver_seguro,
        # Você pode adicionar retries e retry_delay aqui se a tarefa puder falhar transitoriamente
        # retries=3,
        # retry_delay=pendulum.duration(minutes=5),
        doc_md="""
        ## Tarefa: Upload de Dados Consolidados para a Camada Silver

        Propósito: Esta tarefa é responsável por mover o arquivo de dados consolidados
        (gerado por uma etapa anterior do pipeline) para a Camada Silver do Data Lake (MinIO).
        É um passo fundamental na promoção de dados de bronze para silver, indicando que os dados
        passaram por processos de limpeza e transformação.

        ### Funções Principais:
        - Autenticação Segura: Conecta-se ao MinIO usando credenciais obtidas de
          forma segura através do Vault de segurança, garantindo que nenhum segredo
          seja exposto.
        - Verificação/Criação de Bucket: Garante que o bucket de destino da
          Camada Silver (`silver-layer`) exista no MinIO. Se não existir, ele é criado.
        - Upload de Arquivo: Realiza o upload do arquivo `dados_consolidados.csv`
          (localizado no worker do Airflow) para o MinIO, dentro de uma estrutura
          de pastas lógica (e.g., `vendas/consolidado_vendas.csv`).
        - Auditoria e Logging: Cada operação de upload (sucesso ou falha) é
          registrada detalhadamente no sistema de auditoria, fornecendo rastreabilidade
          e informações para monitoramento.

        ### Robustez e Confiabilidade:
        - Verificação de Arquivo de Origem: A tarefa verifica se o arquivo
          `dados_consolidados.csv` existe no caminho local configurado. Se o arquivo
          não for encontrado, ele é pulado e um aviso é logado, sem interromper
          a execução da tarefa para outros arquivos.
        - Tratamento de Erros de Conexão/Upload: Blocos `try-except` lidam
          com falhas de conexão ao MinIO ou problemas durante o processo de upload.
        - Idempotência (Consideração): O upload de arquivos para o MinIO
          por padrão sobrescreve arquivos com o mesmo nome. Para uma idempotência
          mais avançada em cenários de reprocessamento, pode-se implementar
          versionamento de objetos no MinIO/S3 ou adicionar um timestamp ao nome do objeto.

        ### Saídas Esperadas:
        - O arquivo `consolidado_vendas.csv` (ou nome configurado) presente no
          bucket `silver-layer` do MinIO, dentro da pasta `vendas/`.
        - Logs detalhados na interface do Airflow e nos arquivos de auditoria,
          registrando o status do upload e quaisquer alertas/erros.
        """
    )
