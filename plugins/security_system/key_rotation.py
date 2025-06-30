import os
import sqlite3
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import logging
from pathlib import Path
from typing import Optional, Any

# Importações dos módulos de segurança customizados (ajustado para VaultManager)
from security_system.vault_manager_helper import VaultManager # O gerenciador de segredos real
from security_system.audit import AuditLogger
from security_system.exceptions import KeyManagementError, ConfigurationError, SecuritySystemBaseError, AuditLogError

# Configuração do logger para este módulo (assume configuração externa ou básica)
logger = logging.getLogger(__name__)

class KeyRotator:
    """
    Gerencia a rotação e o ciclo de vida das chaves criptográficas.
    As chaves são armazenadas em um banco de dados SQLite local e a chave ativa
    é gerenciada no Vault de Segurança.
    """

    def __init__(self, security_manager: VaultManager, audit_logger: Optional[AuditLogger] = None, db_path: Optional[str] = None):
        """
        Inicializa o KeyRotator.

        Args:
            security_manager (VaultManager): Instância OBRIGATÓRIA do VaultManager.
            audit_logger (Optional[AuditLogger]): Instância do AuditLogger.
            db_path (Optional[str]): Caminho para o banco de dados SQLite de rotação de chaves.
                                     Padrao e `/tmp/airflow_key_rotation.db` ou `KEY_ROTATION_DB_PATH` env var.
        Raises:
            ConfigurationError: Se security_manager não for uma instância válida de VaultManager.
        """
        if not isinstance(security_manager, VaultManager):
            raise ConfigurationError("security_manager deve ser uma instância valida de VaultManager.")
        
        self.security_manager: VaultManager = security_manager
        
        # Inicialização do AuditLogger
        self.audit: AuditLogger
        if audit_logger:
            self.audit = audit_logger
        else:
            try:
                # Tenta criar uma instância padrao do AuditLogger se nenhuma for fornecida
                airflow_home_path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
                default_audit_path = airflow_home_path / 'logs' / 'security_audit' / 'key_rotator_audit.csv'
                default_system_log_path = airflow_home_path / 'logs' / 'security_audit' / 'key_rotator_system.log'
                
                # Garante que os diretorios existam
                default_audit_path.parent.mkdir(parents=True, exist_ok=True)
                default_system_log_path.parent.mkdir(parents=True, exist_ok=True)
                self.audit = AuditLogger(str(default_audit_path), str(default_system_log_path))
                logger.warning("AuditLogger nao fornecido para KeyRotator. Usando instancia padrao.")
            except Exception as e:
                logger.error(f"Falha ao instanciar AuditLogger padrao no KeyRotator.init: {e}. O logging de auditoria pode estar desabilitado para este modulo.", exc_info=True)
                class NoOpAuditLogger:
                    def log(self, *args, **kwargs): pass
                    def info(self, *args, **kwargs): pass
                    def error(self, *args, **kwargs): pass
                self.audit = NoOpAuditLogger()

        self.db_path: Path = Path(db_path or os.getenv('KEY_ROTATION_DB_PATH', '/tmp/airflow_key_rotation.db'))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        # Adicionar um handler de StreamHandler basico para self.logger se nao houver nenhum,
        # para garantir que os logs sejam visiveis no console/logs do Airflow.
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            self.logger.debug("StreamHandler adicionado ao logger do KeyRotator.")
            
        self._initialize_db()
        self.audit.log("KeyRotator inicializado.", action="KEY_ROTATOR_INIT", service="KeyRotation")
        self.logger.info("KeyRotator inicializado com sucesso.")


    def _initialize_db(self) -> None:
        """
        Inicializa o banco de dados SQLite para armazenar as chaves.
        Cria a tabela 'keys' se ela nao existir.
        """
        try:
            db_dir = self.db_path.parent
            if not db_dir.exists():
                db_dir.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Diretorio de DB para rotacao de chaves criado: {db_dir}")

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    version TEXT PRIMARY KEY,
                    key_value BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                )
            """)
            conn.commit()
            conn.close()
            self.audit.log("Banco de dados de rotacao de chaves inicializado/verificado.", action="KEY_DB_INIT", service="KeyRotation")
            self.logger.info("Banco de dados de rotacao de chaves inicializado com sucesso.")
        except Exception as e:
            error_msg = f"Erro ao inicializar o banco de dados de rotacao de chaves em '{self.db_path}': {e}"
            self.audit.log(error_msg, level="CRITICAL", action="KEY_DB_INIT_FAIL", service="KeyRotation", error_message=str(e), stack_trace_needed=True)
            self.logger.error(error_msg, exc_info=True)
            raise KeyManagementError(f"Falha ao inicializar o DB de rotacao de chaves: {e}", operation="db_init")

    def _generate_new_key(self) -> bytes:
        """
        Gera uma nova chave criptografica usando Fernet.

        Returns:
            bytes: A nova chave criptografica.
        """
        new_key = Fernet.generate_key()
        self.audit.log("Nova chave criptografica gerada.", action="KEY_GENERATED", service="KeyRotation")
        self.logger.info("Nova chave criptografica gerada.")
        return new_key

    def _store_key(self, version: str, key_value: bytes, expires_at: Optional[datetime] = None) -> None:
        """
        Armazena uma chave criptografica no banco de dados de rotacao.

        Args:
            version (str): A versao da chave (identificador unico).
            key_value (bytes): O valor da chave criptografica.
            expires_at (Optional[datetime]): Data e hora de expiracao da chave, se aplicavel.
                                             Padrao e None.
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            created_at = datetime.now().isoformat()
            
            cursor.execute(
                "INSERT INTO keys (version, key_value, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (version, key_value, created_at, expires_at.isoformat() if expires_at else None)
            )
            conn.commit()
            conn.close()
            self.audit.log(f"Chave versao '{version}' armazenada no DB.", action="KEY_STORED", resource=version, service="KeyRotation")
            self.logger.info(f"Chave versao '{version}' armazenada no DB.")
        except sqlite3.IntegrityError:
            warning_msg = f"Tentativa de armazenar chave com versao duplicada: '{version}'. Pulando armazenamento."
            self.audit.log(warning_msg, level="WARNING", action="KEY_STORE_DUPLICATE", resource=version, service="KeyRotation", risk_level="LOW")
            self.logger.warning(warning_msg)
        except Exception as e:
            error_msg = f"Erro ao armazenar chave versao '{version}': {e}"
            self.audit.log(error_msg, level="CRITICAL", action="KEY_STORE_FAIL", resource=version, service="KeyRotation", error_message=str(e), stack_trace_needed=True)
            self.logger.error(error_msg, exc_info=True)
            raise KeyManagementError(f"Falha ao armazenar chave: {e}", operation="store_key")

    def _get_key_from_db(self, version: str) -> Optional[bytes]:
        """
        Recupera uma chave criptografica especifica do banco de dados de rotacao.

        Args:
            version (str): A versao da chave a ser recuperada.

        Returns:
            Optional[bytes]: O valor da chave se encontrada, caso contrario None.
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT key_value FROM keys WHERE version = ?", (version,))
            result = cursor.fetchone()
            conn.close()
            if result:
                self.audit.log(f"Chave versao '{version}' recuperada do DB.", action="KEY_RETRIEVED_FROM_DB", resource=version, service="KeyRotation")
                return result[0]
            self.logger.info(f"Chave versao '{version}' nao encontrada no DB.")
            return None
        except Exception as e:
            error_msg = f"Erro ao recuperar chave versao '{version}' do banco de dados: {e}"
            self.audit.log(error_msg, level="CRITICAL", action="KEY_RETRIEVE_DB_FAIL", resource=version, service="KeyRotation", error_message=str(e), stack_trace_needed=True)
            self.logger.error(error_msg, exc_info=True)
            raise KeyManagementError(f"Falha ao recuperar chave do DB: {e}", operation="get_key_from_db")

    def get_active_key(self) -> Dict[str, Any]:
        """
        Obtem a informacao da chave criptografica atualmente ativa do Vault de Seguranca.

        Returns:
            Dict[str, Any]: Um dicionario contendo a versao e o valor codificado (Base64) da chave ativa.

        Raises:
            ConfigurationError: Se a chave ativa nao estiver definida ou estiver incompleta no Vault.
            KeyManagementError: Para outros erros inesperados ao acessar o Vault para a chave ativa.
        """
        try:
            # security_manager e um VaultManager, que retorna a string do segredo (que e um JSON string)
            current_key_info_json = self.security_manager.get_secret("current_encryption_key")
            
            if not current_key_info_json or not isinstance(current_key_info_json, str):
                error_msg = "Chave de criptografia 'current_encryption_key' nao definida ou invalida (nao e string JSON) no Vault."
                self.audit.error(error_msg, action="ACTIVE_KEY_NOT_FOUND_VAULT", service="KeyRotation", risk_level="CRITICAL")
                self.logger.error(error_msg)
                raise ConfigurationError(error_msg, config_item="current_encryption_key")
            
            try:
                current_key_info = json.loads(current_key_info_json)
            except json.JSONDecodeError as e:
                error_msg = f"Erro ao decodificar JSON da chave 'current_encryption_key' do Vault: {e}"
                self.audit.error(error_msg, action="ACTIVE_KEY_JSON_DECODE_FAIL", service="KeyRotation", risk_level="CRITICAL")
                self.logger.error(error_msg, exc_info=True)
                raise ConfigurationError(error_msg, config_item="current_encryption_key_json")

            if "value" not in current_key_info or "version" not in current_key_info:
                error_msg = "Informacoes da chave de criptografia atual incompletas no Vault (faltando 'value' ou 'version')."
                self.audit.error(error_msg, action="ACTIVE_KEY_INCOMPLETE_VAULT", service="KeyRotation", risk_level="CRITICAL")
                self.logger.error(error_msg)
                raise ConfigurationError(error_msg, config_item="current_encryption_key_structure")
                
            self.audit.log(f"Chave ativa versao '{current_key_info.get('version')}' recuperada do Vault.", action="ACTIVE_KEY_RETRIEVED_VAULT", service="KeyRotation")
            self.logger.info(f"Chave ativa versao '{current_key_info.get('version')}' recuperada do Vault.")
            return current_key_info
        except SecuritySystemBaseError: # Re-lança excecoes customizadas sem modificar
            raise
        except Exception as e:
            error_msg = f"Erro inesperado ao obter a chave criptografica ativa do Vault: {e}"
            self.audit.error(error_msg, action="ACTIVE_KEY_GET_UNEXPECTED_FAIL", service="KeyRotation", risk_level="CRITICAL", error_message=str(e), stack_trace_needed=True)
            self.logger.error(error_msg, exc_info=True)
            raise KeyManagementError(f"Falha ao obter chave ativa do Vault: {e}", operation="get_active_key")

    def rotate_key(self, key_lifetime_days: int = 90) -> str:
        """
        Executa o processo completo de rotacao da chave criptografica ativa.
        Gera uma nova chave, armazena a chave antiga no historico (se existir),
        e atualiza o Vault com a nova chave ativa.

        Args:
            key_lifetime_days (int): Tempo de vida da nova chave em dias.
                                     Padrao e 90 dias.

        Returns:
            str: A versao da nova chave rotacionada.

        Raises:
            KeyManagementError: Se ocorrer qualquer falha durante o processo de rotacao.
        """
        self.audit.log("Iniciando rotacao de chave criptografica.", action="KEY_ROTATION_START", service="KeyRotation")
        self.logger.info("Iniciando rotacao de chave criptografica...")
        
        try:
            # 1. Recupera a chave ativa atual do Vault (se houver)
            old_key_info = None
            try:
                # O get_secret agora retorna a string JSON
                old_key_info_json = self.security_manager.get_secret("current_encryption_key")
                if old_key_info_json:
                    old_key_info = json.loads(old_key_info_json)
            except (ConfigurationError, KeyManagementError, json.JSONDecodeError) as e:
                self.logger.warning(f"Nenhuma chave ativa anterior encontrada no Vault ou erro ao recupera-la: {e}. Prosseguindo com a geracao da primeira chave.")
                self.audit.warning(f"Tentativa de rotacao sem chave ativa anterior no Vault. Detalhes: {e}", action="KEY_ROTATION_NO_OLD_KEY", service="KeyRotation", risk_level="LOW")
            
            old_key_version = old_key_info.get("version") if old_key_info else None
            old_key_value_b64 = old_key_info.get("value") if old_key_info else None

            # 2. Gera uma nova chave
            new_key_value_raw = self._generate_new_key()
            new_key_value_b64 = base64.urlsafe_b64encode(new_key_value_raw).decode('utf-8')
            
            # 3. Define a nova versao e data de expiracao
            new_key_version = f"v{datetime.now().strftime('%Y%m%d%H%M%S')}"
            new_key_expires_at = datetime.now() + timedelta(days=key_lifetime_days)

            # 4. Armazena a nova chave no DB de historico de chaves
            # O DB armazena o valor RAW da chave (bytes)
            self._store_key(new_key_version, new_key_value_raw, new_key_expires_at)

            # 5. Atualiza a "current_encryption_key" no Vault com a nova chave
            new_current_key_info = {
                "version": new_key_version,
                "value": new_key_value_b64, # Valor em Base64 para armazenamento no Vault (se for JSON/texto)
                "created_at": datetime.now().isoformat(),
                "expires_at": new_key_expires_at.isoformat()
            }
            # O set_secret do VaultManager espera uma string como valor
            self.security_manager.set_secret("current_encryption_key", json.dumps(new_current_key_info))
            self.logger.info(f"Nova chave versao '{new_key_version}' configurada como chave ativa no Vault.")

            # 6. Armazena a chave antiga no DB de historico, se existir e nao foi armazenada ainda
            # (A chave ativa ja deve ser a que esta no Vault, entao o DB so guarda historico)
            if old_key_value_b64 and old_key_version:
                # Se a chave antiga estava no formato base64 no Vault, precisamos decodificar antes de armazenar no DB (que guarda RAW bytes)
                try:
                    old_key_value_raw_for_db = base64.urlsafe_b64decode(old_key_value_b64)
                    # Verifica se ja existe no DB, para evitar IntegrityError se ja foi rotacionada antes
                    if not self._get_key_from_db(old_key_version):
                        self._store_key(old_key_version, old_key_value_raw_for_db)
                        self.logger.info(f"Chave antiga versao '{old_key_version}' armazenada no historico.")
                    else:
                        self.logger.info(f"Chave antiga versao '{old_key_version}' ja existente no historico. Nao armazenada novamente.")
                except Exception as e:
                    self.logger.error(f"Nao foi possivel decodificar/armazenar a chave antiga '{old_key_version}': {e}", exc_info=True)
                    self.audit.error(f"Falha ao armazenar chave antiga no historico: {old_key_version}. Detalhes: {e}", action="KEY_OLD_STORE_FAIL", service="KeyRotation", risk_level="MEDIUM")


            self.audit.log(
                f"Chave rotacionada com sucesso. Anterior: {old_key_version if old_key_version else 'N/A'}, Nova: {new_key_version}.",
                level="INFO",
                action="KEY_ROTATION_SUCCESS",
                resource="encryption_key",
                details={"old_key_version": old_key_version, "new_key_version": new_key_version}
            )
            self.logger.info(f"Chave rotacionada. Nova versao: {new_key_version}.")
            return new_key_version
            
        except SecuritySystemBaseError as e: # Captura e re-lança excecoes customizadas
            self.audit.error(f"Falha na rotacao da chave: {e.message}. Tipo: {type(e).__name__}.", 
                             action="KEY_ROTATION_FAIL", service="KeyRotation", risk_level="CRITICAL", 
                             error_message=e.message, stack_trace_needed=True, details=e.details)
            self.logger.error(f"Falha na rotacao da chave: {e}", exc_info=True)
            raise e # Re-lança a excecao original customizada
        except Exception as e:
            # Captura excecoes genericas
            error_msg = f"Erro inesperado na rotacao da chave: {e}"
            self.audit.critical(error_msg, action="KEY_ROTATION_UNEXPECTED_FAIL", service="KeyRotation", risk_level="CRITICAL", error_message=str(e), stack_trace_needed=True)
            self.logger.critical(error_msg, exc_info=True)
            raise KeyManagementError(f"Erro inesperado na rotacao da chave: {e}", operation="rotate_key")

    def get_key_for_decryption(self, version: str) -> Fernet:
        """
        Recupera uma chave Fernet (Fernet.generate_key() retorna bytes, Fernet() usa bytes)
        para descriptografia com base em sua versao. Prioriza a busca no DB de historico
        e fallback para a chave ativa no Vault, se for a versao solicitada.

        Args:
            version (str): A versao da chave a ser recuperada para descriptografia.

        Returns:
            Fernet: Uma instancia Fernet pronta para descriptografia.

        Raises:
            KeyManagementError: Se a chave da versao especificada nao for encontrada
                                ou se houver um erro durante a recuperacao/decodificacao.
        """
        self.logger.info(f"Tentando obter chave versao '{version}' para descriptografia.")
        self.audit.log(f"Requisicao de chave para descriptografia: '{version}'.", action="KEY_DECRYPT_REQUEST", resource=version, service="KeyRotation")

        key_value_raw: Optional[bytes] = None

        try:
            # 1. Tenta recuperar do DB de historico de chaves
            key_value_raw = self._get_key_from_db(version)

            if key_value_raw:
                self.logger.info(f"Chave versao '{version}' encontrada no DB de historico.")
                return Fernet(key_value_raw)

            # 2. Se nao estiver no DB, tenta ver se e a chave ativa no Vault
            # O get_secret agora retorna a string JSON
            current_key_info_json = self.security_manager.get_secret("current_encryption_key")
            if current_key_info_json:
                current_key_info = json.loads(current_key_info_json)
                if current_key_info and current_key_info.get("version") == version:
                    key_value_b64 = current_key_info.get("value")
                    if key_value_b64 and isinstance(key_value_b64, str):
                        key_value_raw = base64.urlsafe_b64decode(key_value_b64)
                        self.logger.info(f"Chave versao '{version}' encontrada no Vault (chave ativa).")
                        return Fernet(key_value_raw)
                    else:
                        error_msg = f"Valor da chave ativa '{version}' no Vault esta invalido ou ausente."
                        self.audit.error(error_msg, action="KEY_ACTIVE_INVALID_VALUE", resource=version, service="KeyRotation", risk_level="CRITICAL")
                        self.logger.error(error_msg)
                        raise KeyManagementError(error_msg, operation="get_key_for_decryption")
                
            # 3. Se nao foi encontrada em nenhum lugar
            error_msg = f"Chave versao '{version}' nao encontrada no DB de historico ou como chave ativa no Vault."
            self.audit.warning(error_msg, action="KEY_NOT_FOUND_DEC", resource=version, service="KeyRotation", risk_level="HIGH")
            self.logger.warning(error_msg)
            raise KeyManagementError(error_msg, operation="get_key_for_decryption")

        except SecuritySystemBaseError: # Re-lança excecoes customizadas ja auditadas
            raise
        except Exception as e:
            error_msg = f"Erro inesperado ao obter chave versao '{version}' para descriptografia: {e}"
            self.audit.critical(error_msg, action="KEY_DEC_UNEXPECTED_FAIL", resource=version, service="KeyRotation", risk_level="CRITICAL", error_message=str(e), stack_trace_needed=True)
            self.logger.critical(error_msg, exc_info=True)
            raise KeyManagementError(f"Falha ao obter chave para descriptografia: {e}", operation="get_key_for_decryption")

    def cleanup_old_keys(self, retain_days: int) -> int:
        """
        Limpa chaves antigas do banco de dados de rotacao.
        Retem chaves criadas nos ultimos `retain_days`. Esta funcao e uma simulacao
        e precisaria de logica real de exclusao em producao.

        Args:
            retain_days (int): Numero de dias para reter as chaves no historico.
                               Chaves mais antigas que isso serao removidas (simulado).

        Returns:
            int: Numero de chaves "limpas" (simulado).
        """
        self.audit.log(f"Iniciando limpeza de chaves mais antigas que {retain_days} dias (simulacao).", action="KEY_CLEANUP_START", service="KeyRotation")
        self.logger.info(f"Simulacao: Limpeza de chaves antigas (reter por {retain_days} dias) concluida. Nenhuma chave removida na simulacao.")
        # Em uma implementacao real, a logica de exclusao seria aqui
        # Exemplo:
        # try:
        #     conn = sqlite3.connect(str(self.db_path))
        #     cursor = conn.cursor()
        #     cutoff_date = datetime.now() - timedelta(days=retain_days)
        #     # A chave ativa nao deve ser removida
        #     current_active_key_version_info = self.get_active_key()
        #     current_active_key_version = current_active_key_version_info.get("version")
        #     cursor.execute("DELETE FROM keys WHERE created_at < ? AND version != ?", (cutoff_date.isoformat(), current_active_key_version))
        #     deleted_count = cursor.rowcount
        #     conn.commit()
        #     conn.close()
        #     self.audit.log(f"Limpeza de chaves concluida. {deleted_count} chaves removidas.", action="KEY_CLEANUP_COMPLETE", service="KeyRotation")
        #     self.logger.info(f"Limpeza de chaves concluida. {deleted_count} chaves removidas.")
        #     return deleted_count
        # except Exception as e:
        #     self.audit.error(f"Falha na limpeza de chaves: {e}", action="KEY_CLEANUP_FAIL", service="KeyRotation", risk_level="HIGH")
        #     self.logger.error(f"Falha na limpeza de chaves: {e}", exc_info=True)
        #     raise KeyManagementError(f"Falha na limpeza de chaves: {e}")
        return 0 # Retorna 0 na simulacao

    def __del__(self) -> None:
        """
        Metodo chamado quando o objeto KeyRotator esta prestes a ser destruido.
        Usado para registrar o desligamento e fechar handlers de log.
        """
        try:
            if hasattr(self, 'audit') and self.audit is not None:
                self.audit.log("KeyRotator sendo finalizado.", action="KEY_ROTATOR_SHUTDOWN", service="KeyRotation")
        except Exception: # Captura qualquer excecao durante o log de desligamento
            pass # Nao quero que o __del__ falhe
            
        try:
            if hasattr(self, 'logger') and self.logger:
                handlers = self.logger.handlers[:] # Copia a lista de handlers para iterar
                for handler in handlers:
                    handler.close() # Fecha o handler
                    self.logger.removeHandler(handler) # Remove o handler do logger
        except Exception: # Captura qualquer excecao durante o fechamento de handlers
            pass # Nao quero que o __del__ falhe
