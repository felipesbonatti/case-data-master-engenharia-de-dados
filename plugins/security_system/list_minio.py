import os
import urllib3
import logging
import json # Adicionado para lidar com credenciais JSON do Vault
from pathlib import Path # Adicionado para manipulação de caminhos robusta

# Importações absolutas para módulos do sistema de segurança
from plugins.security_system.vault_manager_helper import VaultManager # O gerenciador de segredos real
from plugins.security_system.audit import AuditLogger
from plugins.security_system.exceptions import SecureConnectionError, ConfigurationError, SecuritySystemBaseError

# Boto3 é uma dependência direta para interagir com S3/MinIO
import boto3
from botocore.exceptions import ClientError

# Configuração de logging para este script utilitário
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Desabilitar warnings de SSL para MinIO em ambientes de desenvolvimento/teste.
# ATENÇÃO: Em produção, configure certificados SSL e remova esta linha.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
====================================================================================
SCRIPT DE UTILIDADE: LISTAGEM DE OBJETOS MINIO/S3 
====================================================================================

DESCRIÇÃO:
    Este script utilitário fornece uma ferramenta para listar objetos em um bucket
    específico do MinIO/S3. Ele demonstra o uso seguro do `SecureConnectionPool`
    para obter uma conexão autenticada ao MinIO, garantindo que as credenciais
    sejam gerenciadas via Vault e não expostas diretamente no código.

OBJETIVO:
    - Verificar a conectividade com o MinIO.
    - Listar o conteúdo de um bucket da camada Bronze (ou outro configurável).
    - Validar a acessibilidade dos dados armazenados.
    - Demonstrar a integração segura com o Vault para credenciais.

COMPONENTES PRINCIPAIS:
    - SecureConnectionPool: Gerencia a obtenção segura de clientes MinIO.
    - Minio Client: Para interação com o serviço de armazenamento de objetos.
    - Vault de Segurança: Fonte das credenciais de acesso ao MinIO.
    - Logging: Registro de eventos e erros para rastreabilidade.

SEGURANÇA E ROBUSTEZ:
    - Conectividade Segura: As credenciais são obtidas do Vault, sem hardcoding.
    - Tratamento de Erros: Captura e loga exceções específicas de conexão e configuração.
    - Mensagens Informativas: Fornece feedback claro sobre o status da operação.

INSTRUÇÕES DE USO:
    1.  Certifique-se de que o Vault está configurado com as credenciais `minio_local_credentials`.
    2.  Certifique-se de que a variável de ambiente `SECURITY_VAULT_SECRET_KEY` está definida.
    3.  Execute este script diretamente no ambiente onde o `VaultManager` e `AuditLogger` estão acessíveis.
        Ex: `python -m plugins.security_system.list_minio` (se estiver no PYTHONPATH)
            ou execute dentro de um container Docker configurado.
    4.  A saída mostrará os objetos encontrados ou mensagens de erro/aviso.
====================================================================================
"""

# ---
# Configurações Globais para este script
# ---

class ListMinioConfig:
    """Centraliza as configurações específicas para o script de listagem de MinIO."""
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json'
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'script_list_minio_audit.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'script_list_minio_system.log'

    VAULT_SECRET_KEY_ENV: str = 'SECURITY_VAULT_SECRET_KEY'
    MINIO_CREDS_KEY: str = "minio_local_credentials"

def list_minio_objects(target_bucket: str = "bronze-layer") -> None:
    """
    Tenta listar todos os objetos em um bucket específico do MinIO/S3.

    Utiliza o VaultManager para obter credenciais MinIO e audita as operações de acesso.

    Args:
        target_bucket (str): O nome do bucket no Minio a ser listado.
                               Padrão é "bronze-layer" para fins de demonstração.

    Raises:
        SecureConnectionError: Se houver falha na conexão segura ao MinIO.
        ConfigurationError: Se as credenciais do Minio não forem encontradas ou forem inválidas.
        Exception: Para qualquer outro erro inesperado durante a listagem.
    """
    logger.info(f"Iniciando tentativa de listar objetos no bucket MinIO: '{target_bucket}'")

    # Inicializa AuditLogger para este script
    try:
        ListMinioConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ListMinioConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = AuditLogger(
            audit_file_path=str(ListMinioConfig.AUDIT_LOG_PATH),
            system_log_file_path=str(ListMinioConfig.SYSTEM_LOG_PATH)
        )
    except Exception as e:
        logger.critical(f"ERRO CRÍTICO: Falha ao inicializar AuditLogger para script de listagem MinIO: {e}", exc_info=True)
        # Fallback para um logger que apenas imprime (para não parar o script utilitário)
        class NoOpAuditLogger:
            def log(self, *args, **kwargs): pass
            def info(self, *args, **kwargs): pass
            def error(self, *args, **kwargs): pass
        audit_logger = NoOpAuditLogger()

    secret_key = os.getenv(ListMinioConfig.VAULT_SECRET_KEY_ENV)
    if not secret_key:
        audit_logger.log('SECURITY_ERROR', 'Variável de ambiente SECURITY_VAULT_SECRET_KEY não definida.', level='CRITICAL')
        logger.critical(f"ERRO CRÍTICO: A variável de ambiente '{ListMinioConfig.VAULT_SECRET_KEY_ENV}' não está definida.")
        print(f"ERRO: A variável de ambiente '{ListMinioConfig.VAULT_SECRET_KEY_ENV}' não está definida. Acesso ao Vault negado.")
        return # Sai da função

    try:
        # Inicializa VaultManager
        # Garante que o diretório do vault.json exista
        ListMinioConfig.VAULT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        vault_manager = VaultManager(
            vault_path=str(ListMinioConfig.VAULT_JSON_PATH),
            secret_key=secret_key,
            logger=audit_logger
        )
        logger.debug("AuditLogger e VaultManager inicializados para o script.")

        # Obtém credenciais MinIO do Vault
        minio_creds_encrypted = vault_manager.get_secret(ListMinioConfig.MINIO_CREDS_KEY)
        if not minio_creds_encrypted:
            audit_logger.log('VAULT_CREDENTIALS_MISSING', f"Credenciais '{ListMinioConfig.MINIO_CREDS_KEY}' não encontradas no Vault.", level='CRITICAL')
            logger.critical(f"ERRO: Credenciais '{ListMinioConfig.MINIO_CREDS_KEY}' não encontradas no Vault.")
            print(f"ERRO: Credenciais '{ListMinioConfig.MINIO_CREDS_KEY}' não encontradas no Vault.")
            return

        minio_creds = json.loads(minio_creds_encrypted) # Deserializa o JSON

        # Inicializa o cliente MinIO (boto3)
        logger.info(f"Conectando ao MinIO em: {minio_creds.get('endpoint_url')}")
        minio_client = boto3.client(
            "s3",
            endpoint_url=minio_creds.get('endpoint_url'),
            aws_access_key_id=minio_creds.get('access_key'),
            aws_secret_access_key=minio_creds.get('secret_key'),
            verify=False # ATENÇÃO: Em produção, defina para True
        )
        # Teste de conexão básico
        minio_client.list_buckets()
        logger.info("Cliente MinIO/S3 configurado e conexão testada com sucesso.")
        audit_logger.log('MINIO_CONNECTION_SUCCESS', 'Conexão com MinIO estabelecida com sucesso.', user='script_list_minio')

    except (SecureConnectionError, ConfigurationError, SecuritySystemBaseError) as e:
        logger.error(f"ERRO CRÍTICO ao inicializar o cliente MinIO (Exceção de Segurança): {e}", exc_info=True)
        print(f"ERRO: Não foi possível estabelecer conexão segura com o MinIO. Detalhes: {e}")
        return # Sai da função em caso de erro crítico de conexão/configuração
    except Exception as e:
        logger.critical(f"ERRO INESPERADO na inicialização do script: {e}", exc_info=True)
        print(f"ERRO FATAL: Falha inesperada. Detalhes: {e}")
        return

    logger.info(f"Verificando existência do bucket: '{target_bucket}'")
    try:
        if not minio_client.bucket_exists(Bucket=target_bucket): # Usar Bucket= para boto3
            logger.warning(f"AVISO: O bucket '{target_bucket}' não existe no MinIO.")
            print(f"AVISO: O bucket '{target_bucket}' não existe no MinIO.")
            return

        objects = minio_client.list_objects_v2(Bucket=target_bucket, Recursive=True) # Usar list_objects_v2 e Recursive

        found_objects = False
        print(f"\nObjetos encontrados no bucket '{target_bucket}':")
        if 'Contents' in objects:
            for obj in objects['Contents']:
                print(f"- {obj['Key']} (Tamanho: {obj['Size']} bytes, Última Modificação: {obj['LastModified']})")
                found_objects = True

        if not found_objects:
            print("Nenhum objeto encontrado neste bucket.")
        
        logger.info(f"Listagem de objetos no bucket '{target_bucket}' concluída com sucesso. Objetos encontrados: {found_objects}.")

    except ClientError as e:
        logger.error(f"ERRO ao listar objetos do MinIO (ClientError): {e}", exc_info=True)
        print(f"ERRO: Falha específica do cliente MinIO ao listar objetos. Detalhes: {e}")
    except Exception as e:
        logger.critical(f"ERRO INESPERADO ao listar objetos do MinIO: {e}", exc_info=True)
        print(f"ERRO: Falha inesperada durante a listagem de objetos do MinIO. Detalhes: {e}")


