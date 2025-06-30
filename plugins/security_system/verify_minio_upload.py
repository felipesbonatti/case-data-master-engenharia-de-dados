import os
import urllib3
import logging
import json # Para lidar com credenciais JSON do Vault
from pathlib import Path # Para manipulação de caminhos robusta
from typing import Dict, Any, Optional

# Importações de boto3 (devem ser resolvidas pelo requirements.txt do Dockerfile)
import boto3
from botocore.exceptions import ClientError
import minio # Cliente Minio
from minio.error import S3Error # Para capturar erros específicos do MinIO

# Importações absolutas para módulos do sistema de segurança
from plugins.security_system.vault_manager_helper import VaultManager # O gerenciador de segredos real
from plugins.security_system.audit import AuditLogger
from plugins.security_system.exceptions import SecureConnectionError, ConfigurationError, SecuritySystemBaseError

# Configuração de logging para este script utilitário (assume configuração externa ou básica)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Desabilitar avisos de SSL para MinIO em ambientes de desenvolvimento/teste.
# ATENÇÃO: Em produção, configure certificados SSL e remova esta linha.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
====================================================================================
SCRIPT DE UTILIDADE: VERIFICACAO DE UPLOAD MINIO/S3 
====================================================================================

DESCRICAO:
    Este script utilitario fornece uma ferramenta para verificar a presenca e o status de
    um arquivo especifico (`dados_consolidados.csv`) em um bucket do MinIO/S3.
    Ele demonstra a integracao segura com o Vault para obter um cliente MinIO autenticado,
    garantindo que as credenciais sejam gerenciadas e nao expostas.

OBJETIVO PRINCIPAL:
    - Confirmar se um arquivo critico (`dados_consolidados.csv`) foi carregado
      com sucesso para o MinIO.
    - Verificar a existencia do bucket alvo.
    - Exibir o tamanho do arquivo para validacao rapida.
    - Demonstrar a integracao segura com o Vault para credenciais.

COMPONENTES UTILIZADOS:
    - Minio Client: Para interacao com o servico de armazenamento de objetos.
    - Vault de Seguranca: Fonte das credenciais de acesso ao MinIO.
    - AuditLogger: Para registrar eventos e erros para rastreabilidade.

SEGURANCA E ROBUSTEZ:
    - Conectividade Segura: Credenciais obtidas do Vault, sem hardcoding.
    - Tratamento de Erros: Captura excecoes especificas de conexao e configuracao.
    - Mensagens Informativas: Fornece feedback claro sobre o status da operacao.

INSTRUCOES DE USO:
    1.  Configuracao do Vault: Certifique-se de que as credenciais `minio_local_credentials`
        estejam devidamente configuradas no Vault (`vault.json`).
    2.  Ambiente: Certifique-se de que a variavel de ambiente `SECURITY_VAULT_SECRET_KEY` esta definida.
        Execute este script no ambiente onde os modulos customizados estao acessiveis.
        Ex: `python -m plugins.security_system.verify_minio_upload`
    3.  Execucao: A saida no console indicara o status do arquivo.
====================================================================================
"""

# ---
# Configuracoes Globais para este script
# ---

class VerifyUploadConfig:
    """Centraliza as configuracoes especificas para o script de verificacao de upload do MinIO."""
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json'
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'script_verify_upload_audit.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'script_verify_upload_system.log'

    VAULT_SECRET_KEY_ENV: str = 'SECURITY_VAULT_SECRET_KEY'
    MINIO_CREDS_KEY: str = "minio_local_credentials"

def _get_minio_s3_client_secure(audit_logger: AuditLogger) -> boto3.client:
    """
    Cria e retorna um cliente boto3 (compativel com S3) para interagir com o MinIO.
    As credenciais sao recuperadas de forma segura do Vault.

    Args:
        audit_logger: Uma instancia do AuditLogger para registrar eventos de seguranca e acesso.

    Returns:
        boto3.client: Um cliente S3 configurado.

    Raises:
        ValueError: Se a chave secreta do Vault nao estiver definida ou credenciais nao encontradas.
        ImportError: Se os modulos de seguranca customizados nao puderem ser importados.
        ClientError: Para erros especificos do cliente S3 (e.g., credenciais invalidas, endpoint).
        Exception: Para qualquer outro erro inesperado.
    """
    logger.info("Iniciando a obtencao segura do cliente MinIO/S3.")

    try:
        # Importacao local (isolada) do sistema de seguranca para garantir que seja no contexto da tarefa
        from plugins.security_system.vault_manager_helper import VaultManager # Usando VaultManager
    except ImportError as e:
        logger.critical(f"ERRO CRITICO: Modulo de seguranca 'VaultManager' nao encontrado. Detalhes: {e}")
        raise ImportError(f"Dependencia de seguranca ausente: {e}")

    secret_key = os.getenv(VerifyUploadConfig.VAULT_SECRET_KEY_ENV)
    if not secret_key:
        audit_logger.log('SECURITY_ERROR', 'Variavel de ambiente SECURITY_VAULT_SECRET_KEY nao definida.', level='CRITICAL')
        logger.critical(f"ERRO CRITICO: A variavel de ambiente '{VerifyUploadConfig.VAULT_SECRET_KEY_ENV}' nao esta definida.")
        raise ValueError(f"SECURITY_VAULT_SECRET_KEY nao definida. Acesso ao Vault negado.")

    # Inicializa VaultManager para gerenciar os segredos
    vault_manager = VaultManager(
        vault_path=str(VerifyUploadConfig.VAULT_JSON_PATH),
        secret_key=secret_key,
        logger=audit_logger # Passa o audit_logger para o VaultManager
    )

    audit_logger.log('VAULT_ACCESS_ATTEMPT', 'Tentando obter credenciais MinIO do Vault.', user='script_verify_minio_upload')
    minio_creds_encrypted = vault_manager.get_secret(VerifyUploadConfig.MINIO_CREDS_KEY)

    if not minio_creds_encrypted:
        audit_logger.log('VAULT_CREDENTIALS_MISSING', f"Credenciais '{VerifyUploadConfig.MINIO_CREDS_KEY}' nao encontradas no Vault.", level='CRITICAL')
        logger.critical(f"ERRO: Credenciais '{VerifyUploadConfig.MINIO_CREDS_KEY}' nao encontradas no Vault.")
        raise ValueError(f"Credenciais 'minio_local_credentials' nao encontradas no Vault.")

    try:
        minio_creds = json.loads(minio_creds_encrypted)
    except json.JSONDecodeError as e:
        audit_logger.log('VAULT_CREDENTIALS_JSON_ERROR', f"Erro ao decodificar credenciais MinIO do Vault (JSON invalido): {e}", level='CRITICAL')
        logger.critical(f"ERRO: Erro ao decodificar credenciais MinIO do Vault (JSON invalido): {e}")
        raise ValueError("Formato de credenciais MinIO no Vault invalido.")

    logger.info(f"Conectando ao MinIO em: {minio_creds.get('endpoint_url')}")
    audit_logger.log('MINIO_CONNECTION_ATTEMPT', f"Iniciando conexao com MinIO: {minio_creds.get('endpoint_url')}", user='script_verify_minio_upload')

    try:
        s3_client = boto3.client(
            "s3",
            endpoint_url=minio_creds.get('endpoint_url'),
            aws_access_key_id=minio_creds.get('access_key'),
            aws_secret_access_key=minio_creds.get('secret_key'),
            verify=False 
        )
        # Teste de conexao basico para validar as credenciais e o endpoint
        s3_client.list_buckets()
        logger.info("Cliente MinIO/S3 configurado e conexao testada com sucesso.")
        audit_logger.log('MINIO_CONNECTION_SUCCESS', 'Conexao com MinIO estabelecida com sucesso.', user='script_verify_minio_upload')
        return s3_client
    except ClientError as e:
        audit_logger.log('MINIO_CONNECTION_FAILED', f"Falha na conexao com MinIO: {e}", level='CRITICAL', user='script_verify_minio_upload')
        logger.error(f"ERRO DE CONEXAO: Falha ao conectar ao MinIO. Verifique credenciais e endpoint. Detalhes: {e}")
        raise
    except Exception as e:
        audit_logger.log('MINIO_CONNECTION_UNEXPECTED_ERROR', f"Erro inesperado ao criar cliente MinIO: {e}", level='CRITICAL', user='script_verify_minio_upload')
        logger.error(f"ERRO INESPERADO ao criar cliente MinIO: {e}")
        raise

def verify_upload(bucket_name: str = "s-prd.sand-ux-indc-brasil", object_name: str = "dados_consolidados.csv") -> None:
    """
    Verifica a existencia e o status de um arquivo especifico em um bucket do MinIO/S3.

    Args:
        bucket_name (str): O nome do bucket no MinIO/S3 a ser verificado.
        object_name (str): O nome do objeto (arquivo) a ser procurado dentro do bucket.
    """
    logger.info(f"Iniciando verificacao do arquivo '{object_name}' no bucket MinIO: '{bucket_name}'")
    logger.info(f"--- Verificando arquivo '{object_name}' no bucket '{bucket_name}' do MinIO ---")

    # Inicializa o AuditLogger aqui para ter logs de auditoria para o script utilitario.
    try:
        VerifyUploadConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        VerifyUploadConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = AuditLogger(str(VerifyUploadConfig.AUDIT_LOG_PATH), str(VerifyUploadConfig.SYSTEM_LOG_PATH))
        logger.info("AuditLogger inicializado para o script verify_upload.")
    except Exception as e:
        logger.error(f"Nao foi possivel inicializar AuditLogger para verify_upload: {e}. A auditoria pode estar limitada.")
        class NoOpAuditLogger:
            def log(self, *args, **kwargs): pass
            def info(self, *args, **kwargs): pass
            def error(self, *args, **kwargs): pass
            def critical(self, *args, **kwargs): pass
        audit_logger = NoOpAuditLogger()

    try:
        minio_client = _get_minio_s3_client_secure(audit_logger)

        logger.info(f"Cliente MinIO obtido com sucesso. Verificando bucket '{bucket_name}'.")
        # Verifica se o bucket existe
        if minio_client.bucket_exists(Bucket=target_bucket): # Usar Bucket= para boto3
            logger.info(f"Bucket '{bucket_name}' existe. Verificando objeto '{object_name}'.")
            audit_logger.log(f"Bucket '{bucket_name}' verificado. Existe.", action="MINIO_BUCKET_CHECK_SUCCESS", resource=bucket_name)
            
            try:
                # Tenta obter os metadados do objeto para confirmar sua existencia e tamanho
                obj_stat = minio_client.stat_object(bucket_name, object_name)
                logger.info(f"Arquivo '{object_name}' ENCONTRADO. Tamanho: {obj_stat.size} bytes.")
                logger.info(f"Arquivo '{object_name}' ENCONTRADO no bucket '{bucket_name}'.")
                logger.info(f"Tamanho: {obj_stat.size / (1024*1024):.2f} MB")
                logger.info("Status: OK")
                audit_logger.log(f"Arquivo '{object_name}' encontrado. Tamanho: {obj_stat.size} bytes.", 
                                 action="MINIO_OBJECT_FOUND", resource=f"{bucket_name}/{object_name}", 
                                 details={"size_bytes": obj_stat.size})

            except S3Error as e:
                # Captura erros especificos do MinIO/S3, como 'NoSuchKey'
                if e.code == 'NoSuchKey':
                    logger.warning(f"Arquivo '{object_name}' NAO ENCONTRADO no bucket '{bucket_name}'.")
                    audit_logger.log(f"Arquivo '{object_name}' NAO ENCONTRADO.", level="WARNING", action="MINIO_OBJECT_NOT_FOUND", resource=f"{bucket_name}/{object_name}")
                else:
                    logger.error(f"ERRO S3 MinIO ao verificar objeto '{object_name}': {e}", exc_info=True)
                    audit_logger.log(f"Erro S3 ao verificar objeto '{object_name}'. Detalhes: {e}", level="ERROR", action="MINIO_OBJECT_STAT_FAIL", resource=f"{bucket_name}/{object_name}", error_message=str(e))
            except Exception as e:
                logger.critical(f"ERRO INESPERADO ao verificar objeto '{object_name}': {e}", exc_info=True)
                audit_logger.log(f"Erro inesperado ao verificar objeto '{object_name}'. Detalhes: {e}", level="CRITICAL", action="MINIO_OBJECT_STAT_UNEXPECTED_FAIL", resource=f"{bucket_name}/{object_name}", error_message=str(e), stack_trace_needed=True)

        else:
            logger.error(f"ERRO: O bucket '{bucket_name}' NAO EXISTE no MinIO.")
            audit_logger.log(f"Bucket '{bucket_name}' nao existe.", level="CRITICAL", action="MINIO_BUCKET_NOT_FOUND", resource=bucket_name)

    except (SecureConnectionError, ConfigurationError, SecuritySystemBaseError) as e:
        # Captura erros relacionados a conexao segura ou configuracao
        logger.critical(f"ERRO ao conectar/verificar MinIO (Erro de Seguranca/Configuracao): {e}", exc_info=True)
        audit_logger.log(f"Falha na conexao/verificacao MinIO devido a erro de seguranca/configuracao. Detalhes: {e}", 
                         level="CRITICAL", action="MINIO_VERIFY_CONN_FAIL", error_message=str(e), stack_trace_needed=True)
    except Exception as e:
        # Captura qualquer outra excecao inesperada
        logger.critical(f"ERRO INESPERADO no script de verificacao de upload MinIO: {e}", exc_info=True)
        audit_logger.log(f"Erro FATAL inesperado no script de verificacao de upload MinIO. Detalhes: {e}", 
                         level="CRITICAL", action="MINIO_VERIFY_UNEXPECTED_FAIL", error_message=str(e), stack_trace_needed=True)

# Ponto de entrada do script
if __name__ == "__main__":
    verify_upload(bucket_name="s-prd.sand-ux-indc-brasil", object_name="dados_consolidados.csv")
