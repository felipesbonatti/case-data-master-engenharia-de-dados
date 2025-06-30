import os
import sys
import logging
import urllib3
from pathlib import Path
import json
from typing import Dict, Any, Optional

# Importações dos módulos de segurança customizados.
try:
    from security_system.vault_manager_helper import VaultManager # Usar VaultManager
    from security_system.audit import AuditLogger
    from security_system.exceptions import ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError
except ImportError as e:
    logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.critical(f"ERRO CRITICO: Modulos de seguranca customizados nao encontrados. Detalhes: {e}")
    logging.critical("Certifique-se de que 'plugins/security_system' esta no PYTHONPATH ou no diretorio de plugins do Airflow.")
    sys.exit(1)

import minio
from minio.error import S3Error

# Configuração de logging para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s - %(filename)s:%(lineno)d')
logger = logging.getLogger(__name__)

# Desabilita avisos de SSL para conexoes HTTP/S.
# ATENCAO: Em ambientes de producao, e CRITICO configurar a verificacao de certificados SSL (secure=True)
# e nao desabilitar avisos de InsecureRequestWarning. Esta configuracao e apenas para desenvolvimento/teste
# com MinIO local sem certificado.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


"""
====================================================================================
UPLOAD COM CRIPTOGRAFIA SERVER-SIDE (SSE) NO DATA LAKE (MINIO/S3)
====================================================================================

DESCRICAO:
    Este script Python demonstra como realizar o upload de arquivos para o MinIO/S3
    aplicando criptografia no lado do servidor (Server-Side Encryption - SSE)
    usando a chave gerenciada pelo servico (SSE-S3 com AES256). Este e um requisito
    fundamental em ambientes com alta demanda de seguranca e conformidade, garantindo
    que os dados estejam protegidos em repouso no Data Lake.

OBJETIVO PRINCIPAL:
    - Realizar upload seguro de arquivos locais para um bucket no MinIO/S3.
    - Aplicar criptografia SSE-S3 (AES256) durante o processo de upload.
    - Utilizar o Vault de Seguranca para obtencao de credenciais MinIO.
    - Auditar as operacoes de upload e criptografia.

COMPONENTES TECNICOS:
    - `minio`: Cliente Python para interacao com o MinIO/S3.
    - `urllib3`: Para gerenciamento de pools de conexao HTTP e avisos SSL.
    - `plugins.security_system.vault_manager_helper.VaultManager`: Para acesso seguro as credenciais.
    - `plugins.security_system.audit.AuditLogger`: Para registro de eventos de seguranca.

TECNICA DE CRIPTOGRAFIA:
    - Server-Side Encryption with S3-managed Keys (SSE-S3): O MinIO/S3 gerencia a chave
      de criptografia e a criptografia/decriptografia dos objetos. O cabecalho
      `x-amz-server-side-encryption: AES256` e adicionado a requisicao.

SEGURANCA E CONFORMIDADE:
    - Credenciais Zero-Exposure: As credenciais do MinIO sao obtidas do Vault
      em tempo de execucao, nunca hardcoded.
    - Dados em Repouso: Garante que os dados estejam criptografados no momento
      em que sao armazenados no MinIO/S3.
    - Auditoria Completa: Todas as operacoes de conexao, criacao de bucket e upload
      sao registradas no sistema de auditoria para rastreabilidade e compliance.

INSTRUCOES DE USO:
    1.  Configurar Vault: Execute `scripts/setup_vault_secrets.py` para popular o Vault
        com as credenciais MinIO (chave esperada: `minio_local_credentials`).
        Certifique-se de que `SECURITY_VAULT_SECRET_KEY` esteja definida no ambiente.
    2.  Arquivos Locais: Tenha os arquivos CSV de exemplo (`olist_customers_dataset.csv`,
        `olist_orders_dataset.csv`) disponiveis no `BASE_DATA_PATH` configurado.
    3.  Execucao: Execute este script.
        Ex: `python3 [caminho_para_este_script]/upload_sse.py`
====================================================================================
"""

# ---
# CONFIGURACOES GLOBAIS
# ---
class SseUploadConfig:
    """Centraliza as configuracoes para o script de upload com SSE."""

    # Variavel de ambiente para a chave mestra do Vault (CRITICA!)
    SECRET_KEY: Optional[str] = os.getenv('SECURITY_VAULT_SECRET_KEY')

    # Caminhos para componentes do sistema de seguranca customizado
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json' # Caminho correto para vault.json
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'sse_upload_audit.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'sse_upload_system.log'

    # Chave do Vault para credenciais MinIO
    MINIO_CREDS_KEY: str = "minio_local_credentials"

    # Nome do bucket de destino no MinIO (para dados criptografados)
    TARGET_BUCKET_NAME: str = "bronze-criptografado"

    # Caminho base para os arquivos locais a serem enviados (simulando a fonte de dados)
    BASE_DATA_PATH: Path = Path(os.getenv('SSE_UPLOAD_DATA_PATH', 'data/olist'))

    # Mapeamento de arquivos locais para nomes de objetos no MinIO
    FILES_TO_UPLOAD: Dict[Path, str] = {
        BASE_DATA_PATH / "olist_customers_dataset.csv": "olist/customers_encrypted.csv",
        BASE_DATA_PATH / "olist_orders_dataset.csv": "olist/orders_encrypted.csv"
    }

    # Configuracao da criptografia Server-Side
    SSE_HEADER: Dict[str, str] = {"x-amz-server-side-encryption": "AES256"}


# ---
# FUNCOES AUXILIARES
# ---

def _get_minio_client(audit_logger: AuditLogger) -> minio.Minio:
    """
    Obtem uma instancia segura do cliente Minio usando credenciais do Vault.
    Configura um http_client customizado para lidar com avisos SSL em ambientes de teste.

    Retorna:
        minio.Minio: Uma instancia autenticada do cliente Minio.

    Levanta:
        ValueError: Se a SECRET_KEY do Vault nao estiver definida.
        ConfigurationError: Se as credenciais MinIO nao forem encontradas ou forem invalidas.
        SecureConnectionError: Para falhas ao estabelecer a conexao com o MinIO.
    """
    logger.info("Iniciando obtencao de cliente MinIO seguro para upload com SSE.")

    secret_key = os.getenv(SseUploadConfig.SECRET_KEY_ENV_VAR_NAME) 
    if not secret_key:
        audit_logger.critical("ERRO CRITICO: A variavel de ambiente 'SECURITY_VAULT_SECRET_KEY' nao esta definida.", action="VAULT_KEY_MISSING")
        logger.critical("ERRO CRITICO: A variavel de ambiente 'SECURITY_VAULT_SECRET_KEY' nao esta definida.")
        raise ValueError("SECURITY_VAULT_SECRET_KEY nao definida. Acesso ao Vault negado.")

    try:
        # Inicializa VaultManager (o gerenciador de segredos real)
        vault_manager = VaultManager(
            vault_path=str(SseUploadConfig.VAULT_JSON_PATH), # Caminho correto para vault.json
            secret_key=secret_key,
            logger=audit_logger # Passa o AuditLogger
        )
        audit_logger.info("VaultManager inicializado para _get_minio_client.", action="VAULT_MANAGER_INIT")

        # Recupera as credenciais MinIO do Vault
        audit_logger.log("Recuperando credenciais MinIO do Vault para SSE upload.", action="GET_MINIO_CREDS_FOR_SSE")
        minio_creds_encrypted = vault_manager.get_secret(SseUploadConfig.MINIO_CREDS_KEY)

        if not minio_creds_encrypted:
            error_msg = f"Credenciais '{SseUploadConfig.MINIO_CREDS_KEY}' nao encontradas ou invalidas no Vault."
            audit_logger.critical(error_msg, action="MINIO_CREDS_MISSING", error_message=error_msg)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)
        
        try:
            minio_creds = json.loads(minio_creds_encrypted) # Desserializa o JSON
        except json.JSONDecodeError as e:
            error_msg = f"Erro ao decodificar credenciais MinIO do Vault (JSON invalido): {e}"
            audit_logger.critical(error_msg, action="MINIO_CREDS_JSON_ERROR", error_message=str(e), stack_trace_needed=True)
            logger.critical(error_msg, exc_info=True)
            raise ConfigurationError(error_msg)

        endpoint_clean = minio_creds.get('endpoint_url', '') 
        access_key = minio_creds.get('access_key')
        secret_key_val = minio_creds.get('secret_key') #
        secure_conn = minio_creds.get('secure', False) # Assume False para ambiente local/teste se nao especificado

        if not all([endpoint_clean, access_key, secret_key_val]):
            error_msg = "Credenciais MinIO incompletas (faltando endpoint, access_key ou secret_key)."
            audit_logger.critical(error_msg, action="MINIO_CREDS_INCOMPLETE", error_message=error_msg)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)

        # Configura http_client para ignorar verificacao SSL (apenas para teste/dev com MinIO sem HTTPS valido)
        http_client = urllib3.PoolManager(cert_reqs='CERT_NONE')
        
        client = minio.Minio( 
            endpoint=endpoint_clean,
            access_key=access_key,
            secret_key=secret_key_val,
            secure=secure_conn, 
            http_client=http_client
        )
        
        # Teste de conexao: listar buckets para verificar autenticacao e conectividade
        client.list_buckets() 
        
        audit_logger.log("Cliente Minio obtido com sucesso para SSE upload.", action="MINIO_CLIENT_SUCCESS_SSE", service="MinIO")
        logger.info("Cliente MinIO conectado e autenticado com sucesso para upload SSE.")
        return client

    except (ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError) as e:
        logger.error(f"Erro de seguranca/configuracao ao obter cliente MinIO para SSE: {e}", exc_info=True)
        raise # Re-lanca a excecao customizada
    except Exception as e:
        logger.critical(f"Erro inesperado ao obter cliente MinIO para SSE: {e}", exc_info=True)
        raise SecureConnectionError(f"Erro inesperado na conexao MinIO para SSE: {e}")

# ---
# FUNCAO PRINCIPAL DE UPLOAD COM SSE
# ---
def perform_sse_upload() -> None:
    """
    Realiza o processo de upload de arquivos locais para o MinIO/S3
    com criptografia Server-Side (SSE-S3 / AES256).
    """
    logger.info("Iniciando o script de upload com criptografia Server-Side Encryption (SSE).")

    # Inicializa o sistema de auditoria
    audit_logger: AuditLogger
    try:
        SseUploadConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        SseUploadConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = AuditLogger(str(SseUploadConfig.AUDIT_LOG_PATH), str(SseUploadConfig.SYSTEM_LOG_PATH))
    except Exception as e:
        logger.critical(f"ERRO CRITICO: Falha ao inicializar AuditLogger para upload SSE: {e}", exc_info=True)
        class NoOpAuditLogger: # Fallback
            def log(self, *args, **kwargs): pass
            def info(self, *args, **kwargs): pass
            def error(self, *args, **kwargs): pass
            def critical(self, *args, **kwargs): pass
        audit_logger = NoOpAuditLogger()

    # 1) Configurando cliente MinIO seguro
    logger.info("1) Configurando cliente MinIO seguro para upload SSE...")
    client: minio.Minio # Tipo de cliente ajustado para minio.Minio
    try:
        client = _get_minio_client(audit_logger)
        logger.info("Cliente MinIO configurado.")
    except Exception as e:
        logger.critical(f"ERRO CRITICO: Falha ao configurar cliente MinIO: {e}", exc_info=True)
        sys.exit(1) # Sai com erro

    bucket_name = SseUploadConfig.TARGET_BUCKET_NAME
    
    # 2) Verificando/Criando bucket de destino
    logger.info(f"2) Verificando/Criando bucket '{bucket_name}'...")
    logger.info(f"Verificando existencia do bucket '{bucket_name}'.")
    try:
        if not client.bucket_exists(bucket_name):
            client.make_bucket(bucket_name)
            logger.info(f"Bucket '{bucket_name}' criado com sucesso.")
            audit_logger.log(f"Bucket '{bucket_name}' criado para SSE upload.", action="MINIO_BUCKET_CREATED_SSE")
        else:
            logger.info(f"Bucket '{bucket_name}' ja existe.")
            audit_logger.log(f"Bucket '{bucket_name}' verificado. Ja existe.", action="MINIO_BUCKET_EXISTS_SSE")
    except S3Error as e:
        logger.critical(f"ERRO MinIO S3 ao verificar/criar bucket '{bucket_name}': {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.critical(f"ERRO INESPERADO ao verificar/criar bucket '{bucket_name}': {e}", exc_info=True)
        sys.exit(1)

    # 3) Iniciando upload com criptografia SSE AES256
    logger.info("3) Iniciando upload com criptografia SSE AES256...")
    logger.info("Iniciando uploads de arquivos com SSE AES256.")
    
    uploaded_files_count = 0
    for local_path_obj, object_name in SseUploadConfig.FILES_TO_UPLOAD.items():
        if local_path_obj.exists():
            logger.info(f"Enviando '{local_path_obj.name}' para '{bucket_name}/{object_name}' com SSE...")
            try:
                client.fput_object(
                    bucket_name,
                    object_name,
                    str(local_path_obj), # Converte Path para string para fput_object
                    metadata=SseUploadConfig.SSE_HEADER # Aplica o cabecalho de criptografia SSE-S3
                )
                logger.info(f"Upload de '{local_path_obj.name}' concluido com SUCESSO (SSE-S3).")
                uploaded_files_count += 1
                # Auditoria de upload bem-sucedido
                audit_logger.log(f"Upload SSE-S3 de '{local_path_obj.name}' para '{bucket_name}/{object_name}'", 
                                 action="MINIO_UPLOAD_SSE_SUCCESS", 
                                 resource=f"{bucket_name}/{object_name}", 
                                 details={"local_path": str(local_path_obj), "encryption": "AES256"})
            except S3Error as e:
                logger.error(f"ERRO MinIO S3 ao fazer upload de '{local_path_obj.name}': {e}", exc_info=True)
                audit_logger.error(f"Falha no upload SSE-S3 de '{local_path_obj.name}'. Detalhes: {e}", 
                                   action="MINIO_UPLOAD_SSE_FAIL", 
                                   resource=f"{bucket_name}/{object_name}", 
                                   error_message=str(e), stack_trace_needed=True)
            except Exception as e:
                logger.critical(f"ERRO INESPERADO ao fazer upload de '{local_path_obj.name}': {e}", exc_info=True)
                audit_logger.critical(f"Erro inesperado no upload SSE-S3 de '{local_path_obj.name}'. Detalhes: {e}", 
                                      action="MINIO_UPLOAD_SSE_UNEXPECTED_FAIL", 
                                      resource=f"{bucket_name}/{object_name}", 
                                      error_message=str(e), stack_trace_needed=True)
        else:
            logger.warning(f"AVISO: Ficheiro nao encontrado, pulando upload: {local_path_obj}")
            audit_logger.warning(f"Ficheiro local nao encontrado para upload SSE: '{local_path_obj}'", 
                                 action="LOCAL_FILE_NOT_FOUND_SSE", 
                                 resource=str(local_path_obj))

    if uploaded_files_count > 0:
        logger.info("\nUpload com criptografia finalizado com sucesso.")
        audit_logger.info("Upload com criptografia SSE concluido.", action="SSE_UPLOAD_COMPLETE")
    else:
        logger.warning("\nAVISO: Nenhum arquivo foi enviado com sucesso. Verifique os logs.")
        audit_logger.warning("Nenhum arquivo enviado no upload SSE.", action="SSE_UPLOAD_NO_FILES")


# ---
# PONTO DE ENTRADA PRINCIPAL
# ---
if __name__ == "__main__":
    # Garante que os diretorios de dados e logs existam antes de qualquer operacao
    SseUploadConfig.BASE_DATA_PATH.mkdir(parents=True, exist_ok=True)
    SseUploadConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SseUploadConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    try:
        perform_sse_upload()
    except Exception:
        # Captura qualquer excecao nao tratada na funcao principal para sair com codigo de erro
        logger.critical("O script de upload com SSE terminou com um erro critico.")
        sys.exit(1) # Garante que o script saia com erro se algo inesperado acontecer
