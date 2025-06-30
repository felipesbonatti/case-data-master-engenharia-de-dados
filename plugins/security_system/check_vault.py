"""
====================================================================================
SCRIPT DE SETUP E VALIDAÇÃO DO VAULT DE SEGURANÇA 
====================================================================================

DESCRIÇÃO:
    Este script é responsável pela configuração inicial e validação do Vault de Segurança.
    Ele permite inserir, atualizar e verificar a acessibilidade de credenciais sensíveis
    (como as do MinIO e PostgreSQL), garantindo que o sistema de gerenciamento de segredos
    esteja operacional e seguro antes da execução das DAGs.

ARQUITETURA DE SEGURANÇA:
    - Vault Criptografado: Armazena segredos de forma segura em um arquivo de banco de dados.
    - Chave Secreta Externa: A chave para criptografar/decriptar o Vault é carregada via
      variável de ambiente, evitando o hardcoding de segredos.
    - Integração com Auditoria: Todas as operações de acesso ao Vault são logadas
      em um sistema de auditoria dedicado para rastreabilidade e compliance.

COMPONENTES TÉCNICOS:
    - `plugins.security_system.vault_manager_helper.VaultManager`: Classe para gerenciar
      as operações de Vault (leitura/escrita de segredos).
    - `plugins.security_system.audit.AuditLogger`: Classe para registrar eventos de auditoria.
    - `python-dotenv`: Para carregar variáveis de ambiente de um arquivo .env (opcional).

OBJETIVO PRINCIPAL:
    - Criar ou atualizar segredos no Vault.
    - Validar se os segredos essenciais (MinIO, PostgreSQL) podem ser lidos corretamente.
    - Testar a integração do Vault com o sistema de Auditoria.

SEGURANÇA E CONFORMIDADE:
    - Previne hardcoding de credenciais no código-fonte das DAGs.
    - Garante que a chave de criptografia do Vault é gerenciada externamente.
    - Oferece um mecanismo para auditar todos os acessos aos segredos.

INSTRUÇÕES DE USO:
    1.  Variável de Ambiente: Certifique-se de que `SECURITY_VAULT_SECRET_KEY`
        esteja definida no ambiente onde este script será executado (preferencialmente
        no arquivo .env do Docker Compose ou diretamente no ambiente do Airflow Worker).
    2.  Caminhos: Os caminhos para o Vault (`VAULT_JSON_PATH`) e logs de auditoria
        (`AUDIT_LOG_PATH_FOR_TEST`, `SYSTEM_LOG_PATH_FOR_TEST`) devem corresponder
        à estrutura de diretórios do ambiente Airflow (`/opt/airflow/`).
    3.  Execução:
        - Para adicionar/atualizar segredos, modifique a seção "Adicionar/Atualizar Segredos no Vault"
          e execute o script.
        - Para apenas verificar os segredos existentes, execute o script como está.
====================================================================================
"""

import os
import sys
import json
import logging
from pathlib import Path
from dotenv import load_dotenv

# Configuração de Logging para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Adiciona o diretório de plugins ao sys.path para importar os módulos de segurança
# Isso é crucial se este script for executado de fora do ambiente Airflow padrão
script_dir = Path(__file__).resolve().parent
plugins_dir = script_dir.parent.parent / 'plugins'
if str(plugins_dir) not in sys.path:
    sys.path.insert(0, str(plugins_dir))

# Importações dos módulos de segurança customizados
try:
    from security_system.vault_manager_helper import VaultManager # Usando VaultManager
    from security_system.audit import AuditLogger
except ImportError as e:
    logger.critical(f"ERRO CRÍTICO: Nao foi possivel importar modulos de seguranca. "
                    f"Certifique-se de que 'plugins/security_system' esta acessivel no PYTHONPATH. Detalhes: {e}")
    sys.exit(1) # Sai do script se os módulos essenciais nao puderem ser carregados

# ---
# Configuracoes Globais
# ---

class VaultSetupConfig:
    """Centraliza as configuracoes para o script de setup do Vault."""
    
    # Airflow Home: Determinado via variavel de ambiente ou padrao
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))

    # Caminho para o arquivo .env de configuracoes de seguranca
    # Notar que o docker-compose lera o .env da raiz do projeto.
    # Este .env_config_path e para uso opcional se o script for rodado localmente.
    DOTENV_CONFIG_PATH: Path = AIRFLOW_HOME / 'config' / 'security.env'

    # Caminho para o arquivo JSON do Vault (consistente com o que as DAGs esperam)
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json'

    # Chave secreta para criptografar/decriptar o Vault.
    # E CRITICO que esta chave seja a mesma usada para criptografar os segredos.
    # EM PRODUCAO, ESTE VALOR DEVE VIR DE UMA VARIAVEL DE AMBIENTE SEGURA!
    # Para testes, obtemos de os.getenv, que devera ser setado via .env e docker-compose.
    SECRET_KEY_ENV_VAR_NAME: str = 'SECURITY_VAULT_SECRET_KEY'

    # Caminhos para os arquivos de log de auditoria usados NESTE script de teste.
    # Eles podem ser separados dos logs de producao para nao misturar.
    AUDIT_LOG_PATH_FOR_TEST: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'audit_setup_test.csv'
    SYSTEM_LOG_PATH_FOR_TEST: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'system_setup_test.log'

# ---
# Carregamento de Variaveis de Ambiente (Opcional, para testes locais)
# ---

# Carrega variaveis de ambiente de um arquivo .env se ele existir.
# Isso e util se a `SECRET_KEY` ou outras variaveis estiverem no .env.
if VaultSetupConfig.DOTENV_CONFIG_PATH.exists():
    load_dotenv(VaultSetupConfig.DOTENV_CONFIG_PATH, override=True)
    logger.info(f"Arquivo .env carregado de '{VaultSetupConfig.DOTENV_CONFIG_PATH}'.")
else:
    logger.warning(f"AVISO: Arquivo .env nao encontrado em '{VaultSetupConfig.DOTENV_CONFIG_PATH}'. "
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
    VaultSetupConfig.AUDIT_LOG_PATH_FOR_TEST.parent.mkdir(parents=True, exist_ok=True)
    VaultSetupConfig.SYSTEM_LOG_PATH_FOR_TEST.parent.mkdir(parents=True, exist_ok=True)
    VaultSetupConfig.VAULT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Diretorios de log de teste e do Vault criados/verificados: {VaultSetupConfig.AUDIT_LOG_PATH_FOR_TEST.parent}, {VaultSetupConfig.VAULT_JSON_PATH.parent}")
    
    # Inicializa o AuditLogger para que ele possa ser passado para o VaultManager
    test_audit_logger = AuditLogger(
        audit_file_path=str(VaultSetupConfig.AUDIT_LOG_PATH_FOR_TEST),
        system_log_file_path=str(VaultSetupConfig.SYSTEM_LOG_PATH_FOR_TEST)
    )
    logger.info("AuditLogger de teste inicializado.")

    # Obter a chave secreta do ambiente (CRITICO para producao)
    secret_key = os.getenv(VaultSetupConfig.SECRET_KEY_ENV_VAR_NAME)
    if not secret_key:
        test_audit_logger.error(
            f"ERRO CRITICO: Variavel de ambiente '{VaultSetupConfig.SECRET_KEY_ENV_VAR_NAME}' nao definida.",
            action="VAULT_SETUP_KEY_MISSING",
            service="VaultSetup"
        )
        logger.critical(f"ERRO CRITICO: Variavel de ambiente '{VaultSetupConfig.SECRET_KEY_ENV_VAR_NAME}' nao definida. O Vault nao pode ser inicializado.")
        sys.exit(1) # Sai com erro fatal

    try:
        # Inicializa o VaultManager (a classe correta para gerenciar segredos)
        vault_manager = VaultManager(
            vault_path=str(VaultSetupConfig.VAULT_JSON_PATH),
            secret_key=secret_key,
            logger=test_audit_logger # Integração com o sistema de auditoria
        )
        logger.info("VaultManager inicializado.")

        ### Adicionar/Atualizar Segredos no Vault 

        logger.info("\n--- Adicionando/Atualizando Segredos no Vault (Exemplo) ---")
        try:
            # Exemplo de credenciais MinIO 
            # Use json.dumps para armazenar dicionarios como strings no Vault
            minio_credentials = {
                "endpoint_url": os.getenv('MINIO_ENDPOINT_URL', 'http://minio:9000'),
                "access_key": os.getenv('MINIO_ACCESS_KEY', 'minioadmin'),
                "secret_key": os.getenv('MINIO_SECRET_KEY', 'minioadmin')
            }
            vault_manager.set_secret("minio_local_credentials", json.dumps(minio_credentials))
            logger.info("Credenciais MinIO (exemplo) adicionadas/atualizadas.")

            # Exemplo de credenciais PostgreSQL 
            postgres_credentials = {
                "host": os.getenv('POSTGRES_HOST', 'postgres'),
                "port": int(os.getenv('POSTGRES_PORT', 5432)), # Converter para int
                "database": os.getenv('POSTGRES_DB', 'airflow'),
                "user": os.getenv('POSTGRES_USER', 'airflow'),
                "password": os.getenv('POSTGRES_PASSWORD', 'airflow')
            }
            vault_manager.set_secret("postgresql_credentials", json.dumps(postgres_credentials))
            logger.info("Credenciais PostgreSQL (exemplo) adicionadas/atualizadas.")

            # Exemplo de chave OpenWeatherMap API (substitua pela sua chave REAL)
            openweathermap_api_key = os.getenv('OPENWEATHER_API_KEY', 'your_open_weather_api_key_here')
            if openweathermap_api_key == 'your_open_weather_api_key_here':
                logger.warning("ATENCAO: OPENWEATHER_API_KEY nao definida. Usando placeholder.")
            vault_manager.set_secret("openweathermap_api_key", openweathermap_api_key)
            logger.info("Chave OpenWeatherMap API (exemplo) adicionada/atualizada.")

        except Exception as e:
            logger.warning(f"AVISO: Erro ao tentar adicionar/atualizar segredos: {e}")
            test_audit_logger.error(f"Erro ao adicionar segredos: {e}", action="VAULT_SET_SECRET_FAILED", service="VaultSetup")
        logger.info("--- Fim da secao de Adicionar/Atualizar Segredos ---")


        logger.info("\n--- Verificando Acessibilidade de Segredos Essenciais ---")
        
        # MinIO Credentials
        minio_local_credentials_json = vault_manager.get_secret("minio_local_credentials")
        minio_local_credentials = json.loads(minio_local_credentials_json) if minio_local_credentials_json else None

        logger.info(f"MinIO Local Credentials (Dict): {'ENCONTRADO' if minio_local_credentials and isinstance(minio_local_credentials, dict) else 'NAO ENCONTRADO ou Invalido'}")
        
        # PostgreSQL Credentials
        postgres_credentials_json = vault_manager.get_secret("postgresql_credentials")
        postgres_credentials = json.loads(postgres_credentials_json) if postgres_credentials_json else None
        
        logger.info(f"PostgreSQL Credentials (Dict): {'ENCONTRADO' if postgres_credentials and isinstance(postgres_credentials, dict) else 'NAO ENCONTRADO ou Invalido'}")

        # OpenWeatherMap API Key
        openweathermap_api_key = vault_manager.get_secret("openweathermap_api_key")
        logger.info(f"OpenWeatherMap API Key: {'ENCONTRADO' if openweathermap_api_key else 'NAO ENCONTRADO'}")

        logger.info("\n--- Validacao de Acessibilidade de Segredos Concluida. ---")
        logger.info(f"Verifique o log de auditoria de teste em: {VaultSetupConfig.AUDIT_LOG_PATH_FOR_TEST}")

    except Exception as e:
        logger.critical(f"\nERRO CRITICO ao executar o script de Setup/Validacao do Vault: {e}", exc_info=True)
        logger.critical("\nPor favor, verifique os seguintes pontos criticos:")
        logger.critical(f"- Se o arquivo do Vault existe no caminho esperado: '{VaultSetupConfig.VAULT_JSON_PATH}'")
        logger.critical(f"- Se a SECRET_KEY de ambiente ('{VaultSetupConfig.SECRET_KEY_ENV_VAR_NAME}') esta **EXATAMENTE** a mesma usada para criptografar os segredos no Vault.")
        logger.critical("- Se os modulos de seguranca estao no PYTHONPATH do ambiente de execucao.")
        if 'test_audit_logger' in locals() and test_audit_logger:
            test_audit_logger.critical(f"ERRO CRITICO no script de Setup/Validacao do Vault: {e}", action="VAULT_SETUP_CRITICAL_FAILURE", service="VaultSetup", error_message=str(e), stack_trace_needed=True)
        sys.exit(1) # Sai com codigo de erro

if __name__ == "__main__":
    run_vault_setup_and_validation()

