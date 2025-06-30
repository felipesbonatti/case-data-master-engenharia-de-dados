import os
import sys
import json
import logging
from pathlib import Path
from dotenv import load_dotenv # Para carregar variaveis de ambiente de .env
from datetime import datetime, timedelta # Para a chave de criptografia inicial
from typing import Dict, Any # Para type hinting

# Configuração de Logging 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s - %(filename)s:%(lineno)d')
logger = logging.getLogger(__name__)

# Adiciona o diretório raiz do projeto (geralmente /opt/airflow) ao path de busca do Python.
# Isso e crucial para que os modulos em `plugins/security_system` possam ser importados corretamente
# quando o script e executado diretamente.
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent # Dependendo da estrutura, ajuste para a raiz do projeto
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Importações dos módulos de segurança customizados.
# Em caso de falha, o script deve encerrar.
try:
    from plugins.security_system.vault_manager_helper import VaultManager
    from plugins.security_system.audit import AuditLogger
    from plugins.security_system.exceptions import SecuritySystemBaseError, ConfigurationError
    from cryptography.fernet import Fernet # Importar Fernet aqui para gerar a chave de exemplo
except ImportError as e:
    # Configura um logger basico para erros criticos de importacao.
    logging.critical(f"ERRO CRITICO: Nao foi possivel importar modulos de seguranca. Detalhes: {e}")
    logging.critical("Certifique-se de que 'plugins/security_system' esta no PYTHONPATH ou no diretorio de plugins do Airflow.")
    sys.exit(1) # Sai do script se os modulos essenciais nao puderem ser carregados


"""
====================================================================================
SCRIPT: SETUP E INICIALIZACAO DE SEGREDOS DO VAULT 
====================================================================================

DESCRICAO:
    Este script e o ponto de entrada para a configuracao inicial do Vault de Seguranca.
    Ele permite a insercao e atualizacao programatica de credenciais e segredos
    essenciais que serao utilizados pelos pipelines de dados. Ao centralizar
    o gerenciamento de segredos no Vault, garantimos que credenciais nunca
    sejam hardcoded nas DAGs ou expostas em logs.

OBJETIVO PRINCIPAL:
    - Inicializar (se necessario) o arquivo de banco de dados do Vault.
    - Adicionar ou atualizar credenciais para servicos criticos como:
        - MinIO/S3 (armazenamento de Data Lake)
        - APIs Externas (ex: OpenWeatherMap)
        - PostgreSQL (bancos de dados transacionais ou Data Marts)
    - Integrar com o sistema de Auditoria para registrar as operacoes de escrita no Vault.

ARQUITETURA DE SEGURANCA:
    - Vault Centralizado: `vault.json` armazena segredos criptografados.
    - Chave de Criptografia Externa: `SECURITY_VAULT_SECRET_KEY` (variavel de ambiente)
      garante que o Vault nao pode ser decriptado sem a chave correta.
    - Auditabilidade: Todas as operacoes de `set_secret` sao registradas para conformidade.

CREDENCIAIS GERENCIADAS (EXEMPLO):
    - `minio_local_credentials`: Endpoint, access_key, secret_key para o MinIO.
    - `openweathermap_api_key`: Chave de API para servicos meteorologicos.
    - `postgres_indicativos_credentials`: Host, porta, banco de dados, usuario, senha para PostgreSQL.
    - `data_masking_key`: Chave para mascaramento de dados.
    - `current_encryption_key`: Chave ativa para criptografia de dados em geral (usada pelo KeyRotator).

INSTRUCOES DE USO:
    1.  Chave Secreta: Antes de executar, defina a variavel de ambiente `SECURITY_VAULT_SECRET_KEY`.
        Esta chave e CRITICA e deve ser a mesma usada para decriptar o Vault em outros modulos.
        Ex: `export SECURITY_VAULT_SECRET_KEY="SUA_CHAVE_FORTE_E_SEGURA"` (substitua pela sua chave real e segura)
    2.  Caminhos: Os caminhos para o Vault (`VAULT_PATH`) e logs de auditoria
        (`AUDIT_LOG_PATH`, `SYSTEM_LOG_PATH`) sao configurados com base em `AIRFLOW_HOME`.
    3.  Atualizar Segredos: Modifique o dicionario `secrets_to_add` com suas
        credenciais reais e seguras.
    4.  Execucao: Execute este script a partir do terminal.
        Ex: `python scripts/setup_vault_secrets.py`
        (Assegure-se de que o ambiente Python tenha as dependencias instaladas: `cryptography`, `python-dotenv`).
====================================================================================
"""

# ---
# Configuracoes Globais
# ---

class SetupConfig:
    """Centraliza as configuracoes para o script de setup do Vault."""
    
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))

    # Caminhos para o Vault e logs de auditoria
    VAULT_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json'
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'audit_setup.csv' 
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'system_setup.log' 

    # Nome da variavel de ambiente para a chave secreta do Vault
    SECRET_KEY_ENV_VAR: str = 'SECURITY_VAULT_SECRET_KEY'

    # Gerar uma chave Fernet inicial para `current_encryption_key` (se necessario)
    INITIAL_FERNET_KEY = Fernet.generate_key().decode('utf-8')

    # Segredos a serem adicionados/atualizados no Vault.
    # ATENCAO: SUBSTITUA OS VALORES PADRAO POR SUAS CREDENCIAIS 
    SECRETS_TO_ADD: Dict[str, Any] = {
        "minio_local_credentials": {
            "endpoint_url": os.getenv('MINIO_ENDPOINT_URL', 'http://minio:9000'), # Usa env var para defaults
            "access_key": os.getenv('MINIO_ACCESS_KEY', 'minioadmin'), # Usa env var para defaults
            "secret_key": os.getenv('MINIO_SECRET_KEY', 'minioadmin'), # Usa env var para defaults
            "secure": False # Defina como True para HTTPS em producao
        },
        "openweathermap_api_key": os.getenv('OPENWEATHER_API_KEY', 'SUA_CHAVE_DE_API_DO_OPENWEATHER_AQUI'), # Usa env var para defaults
        "postgres_indicativos_credentials": { # Nome consistente para o Data Mart
            "host": os.getenv('POSTGRES_HOST', 'postgres'), # Usa env var para defaults
            "port": int(os.getenv('POSTGRES_PORT', 5432)), # Usa env var para defaults, converte para int
            "database": os.getenv('POSTGRES_DB', 'airflow'), # Usa env var para defaults
            "user": os.getenv('POSTGRES_USER', 'airflow'), # Usa env var para defaults
            "password": os.getenv('POSTGRES_PASSWORD', 'airflow'), # Usa env var para defaults
        },
        "data_masking_key": os.getenv('MASKING_KEY', 'uma_chave_de_mascaramento_forte_para_teste_e_dev'), # Usa env var para defaults
        "current_encryption_key": { # Chave usada pelo KeyRotator, precisa de um valor inicial
            "version": f"v{datetime.now().strftime('%Y%m%d%H%M%S')}_initial",
            "value": INITIAL_FERNET_KEY, # Valor gerado automaticamente para o setup inicial
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=90)).isoformat()
        }
    }

# ---
# Carregamento de Variaveis de Ambiente (Opcional, para testes locais)
# ---

# Carrega variaveis de ambiente de um arquivo .env.
dotenv_path = Path(os.getcwd()) / '.env' 
if dotenv_path.exists():
    load_dotenv(dotenv_path, override=True)
    logger.info(f"Arquivo .env carregado de '{dotenv_path}'.")
else:
    logger.warning(f"AVISO: Arquivo .env nao encontrado em '{dotenv_path}'. "
                   "Se as variaveis de ambiente nao estiverem configuradas globalmente, o Vault pode falhar.")

# ---
# Logica Principal do Script
# ---

def run_vault_setup_and_validation():
    """
    Executa o processo de setup e validacao do Vault de seguranca.
    Isso inclui a inicializacao do logger de auditoria, do gerenciador de seguranca,
    e a tentativa de leitura de segredos essenciais para verificar a operacionalidade.
    """
    logger.info("--- Iniciando Setup e Validacao do Vault ---")
    
    # Garante que os diretorios para os logs e para o vault.json existam
    SetupConfig.VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SetupConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SetupConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Diretorios de log de teste e do Vault criados/verificados: {SetupConfig.AUDIT_LOG_PATH.parent}, {SetupConfig.VAULT_PATH.parent}")
    
    # Inicializa o AuditLogger para que ele possa ser passado para o VaultManager
    audit_logger: AuditLogger
    try:
        audit_logger = AuditLogger(
            audit_file_path=str(SetupConfig.AUDIT_LOG_PATH),
            system_log_file_path=str(SetupConfig.SYSTEM_LOG_PATH)
        )
        logger.info("AuditLogger inicializado para o script de setup.")
    except SecuritySystemBaseError as e:
        logger.critical(f"ERRO ao inicializar AuditLogger para setup: {e}", exc_info=True)
        logger.critical(f"ERRO CRITICO: Falha ao inicializar o AuditLogger. Detalhes: {e}")
        sys.exit(1)

    # Obter a chave secreta do ambiente (CRITICO para producao)
    secret_key = os.getenv(SetupConfig.SECRET_KEY_ENV_VAR)
    if not secret_key:
        audit_logger.error( # Usar audit_logger aqui
            f"ERRO CRITICO: Variavel de ambiente '{SetupConfig.SECRET_KEY_ENV_VAR}' nao definida.",
            action="VAULT_SETUP_KEY_MISSING",
            service="VaultSetup"
        )
        logger.critical(f"ERRO CRITICO: Variavel de ambiente '{SetupConfig.SECRET_KEY_ENV_VAR}' nao definida. O Vault nao pode ser inicializado.")
        sys.exit(1) # Sai com erro fatal

    vault_manager: VaultManager
    try:
        # Inicializa o VaultManager (a classe correta para gerenciar segredos)
        vault_manager = VaultManager(
            vault_path=str(SetupConfig.VAULT_PATH),
            secret_key=secret_key,
            logger_instance=audit_logger # Integracao com o sistema de auditoria
        )
        logger.info("VaultManager inicializado.")
    except SecuritySystemBaseError as e:
        logger.critical(f"ERRO ao inicializar VaultManager: {e}", exc_info=True)
        logger.critical(f"ERRO CRITICO: Falha ao inicializar o VaultManager. Detalhes: {e}")
        sys.exit(1)

    logger.info("\n--- Iniciando adicao/atualizacao de segredos no Vault ---")
    secrets_added_count = 0
    for key, value in SetupConfig.SECRETS_TO_ADD.items():
        try:
            # Se o valor for um dicionario, serializa para JSON antes de armazenar
            if isinstance(value, dict):
                vault_manager.set_secret(key, json.dumps(value))
            else:
                vault_manager.set_secret(key, value) # Armazena strings diretamente

            logger.info(f"Segredo '{key}' adicionado/atualizado no Vault.")
            secrets_added_count += 1
        except SecuritySystemBaseError as e:
            logger.error(f"Falha ao adicionar/atualizar segredo '{key}': {e}", exc_info=True)
            audit_logger.error(f"Falha ao adicionar/atualizar segredo '{key}'.", action="VAULT_SET_SECRET_FAILED", resource=key, error_message=str(e))
        except Exception as e:
            logger.critical(f"ERRO INESPERADO ao adicionar/atualizar segredo '{key}': {e}", exc_info=True)
            audit_logger.critical(f"Erro inesperado ao adicionar/atualizar segredo '{key}'.", action="VAULT_SET_SECRET_UNEXPECTED_FAILURE", resource=key, error_message=str(e), stack_trace_needed=True)

    if secrets_added_count == len(SetupConfig.SECRETS_TO_ADD):
        logger.info("\nConfiguracao de segredos do Vault concluida com sucesso!")
        audit_logger.info("Todos os segredos configurados com sucesso.", action="VAULT_SETUP_COMPLETE")
    else:
        logger.warning(f"\nConfiguracao de segredos do Vault concluida com AVISOS. {secrets_added_count} de {len(SetupConfig.SECRETS_TO_ADD)} segredos adicionados/atualizados. Verifique os avisos/erros anteriores.")
        audit_logger.warning("Configuracao de segredos do Vault concluida com avisos.", action="VAULT_SETUP_WITH_WARNINGS", details={"added_count": secrets_added_count, "total_expected": len(SetupConfig.SECRETS_TO_ADD)})

    logger.info("\n--- Verificando Acessibilidade de Segredos Essenciais ---")
    
    # MinIO Credentials
    minio_local_credentials_json = vault_manager.get_secret("minio_local_credentials")
    minio_local_credentials = json.loads(minio_local_credentials_json) if minio_local_credentials_json else None
    logger.info(f"MinIO Local Credentials (Dict): {'ENCONTRADO' if minio_local_credentials and isinstance(minio_local_credentials, dict) else 'NAO ENCONTRADO ou Invalido'}")
    
    # PostgreSQL Credentials
    postgres_credentials_json = vault_manager.get_secret("postgres_indicativos_credentials")
    postgres_credentials = json.loads(postgres_credentials_json) if postgres_credentials_json else None
    logger.info(f"PostgreSQL Credentials (Dict): {'ENCONTRADO' if postgres_credentials and isinstance(postgres_credentials, dict) else 'NAO ENCONTRADO ou Invalido'}")

    # OpenWeatherMap API Key
    openweathermap_api_key = vault_manager.get_secret("openweathermap_api_key")
    logger.info(f"OpenWeatherMap API Key: {'ENCONTRADO' if openweathermap_api_key else 'NAO ENCONTRADO'}")

    # Data Masking Key
    data_masking_key = vault_manager.get_secret("data_masking_key")
    logger.info(f"Data Masking Key: {'ENCONTRADO' if data_masking_key else 'NAO ENCONTRADO'}")

    # Current Encryption Key (for KeyRotator)
    current_encryption_key_json = vault_manager.get_secret("current_encryption_key")
    current_encryption_key = json.loads(current_encryption_key_json) if current_encryption_key_json else None
    logger.info(f"Current Encryption Key (for KeyRotator): {'ENCONTRADO' if current_encryption_key and isinstance(current_encryption_key, dict) else 'NAO ENCONTRADO ou Invalido'}")


    logger.info("\n--- Validacao de Acessibilidade de Segredos Concluida. ---")
    logger.info(f"Verifique o log de auditoria de teste em: {SetupConfig.AUDIT_LOG_PATH}")

# ---
## Ponto de Entrada do Script
---

if __name__ == "__main__":
    try:
        setup_secrets()
    except Exception as e:
        logger.critical(f"O script de setup do Vault terminou com um erro critico: {e}", exc_info=True)
        sys.exit(1)
