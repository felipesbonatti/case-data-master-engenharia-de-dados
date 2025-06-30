import os
import json
import logging
from cryptography.fernet import Fernet, InvalidToken
from typing import Dict, Any, Optional
from pathlib import Path

# Importações dos módulos de segurança customizados e exceções.
# Assegura que esses módulos essenciais são importados.
from security_system.audit import AuditLogger
from security_system.exceptions import VaultAccessError, KeyManagementError, ConfigurationError, SecuritySystemBaseError

# Configuração de logging para este módulo (assume que o logging principal já está configurado)
logger = logging.getLogger(__name__)

"""
====================================================================================
MÓDULO: GERENCIADOR DE VAULT AUXILIAR 
====================================================================================

DESCRIÇÃO:
    Este módulo implementa um gerenciador de Vault baseado em arquivo JSON
    criptografado. Ele é útil para cenários onde um banco de dados SQLite complexo
    não é necessário, ou como um Vault auxiliar/de bootstrap para outros serviços.
    Ele oferece funcionalidades básicas para armazenar e recuperar segredos de forma
    criptografada.

ARQUITETURA:
    - Armazenamento em JSON: Segredos são armazenados em um arquivo JSON.
    - Criptografia Fernet: O conteúdo do arquivo JSON é criptografado usando Fernet
      (AES-128 GCM) com uma chave mestra externa.
    - Chave Mestra Externa: A chave (`SECRET_KEY`) é obtida via variável de ambiente,
      garantindo que o Vault não pode ser acessado sem ela.
    - Integração com Logger: Registra operações de Vault para fins de auditoria/debug.

COMPONENTES E FUNCIONALIDADES:
    - VaultManager Class: Gerencia as operações de leitura e escrita do Vault JSON.
    - _load_vault(): Carrega e decripta o conteúdo do arquivo Vault JSON.
    - _save_vault(): Criptografa e persiste o conteúdo do Vault JSON.
    - get_secret(key): Recupera um segredo específico.
    - set_secret(key, value): Armazena ou atualiza um segredo.

SEGURANÇA E CONFORMIDADE:
    - Zero Exposure: Credenciais nunca hardcoded.
    - Criptografia de Dados: Protege segredos em repouso.
    - Auditabilidade (via Logger): Registra eventos de acesso e modificação.

USO RECOMENDADO:
    - Ambientes de Desenvolvimento/Teste.
    - Vaults auxiliares para dados menos críticos.
    - Bootstrap de credenciais para sistemas maiores (como um Vault baseado em DB).
====================================================================================
"""

class VaultManager:
    """
    Gerencia um Vault de segurança baseado em um arquivo JSON criptografado.
    Permite armazenar e recuperar segredos de forma segura.
    """

    def __init__(self, vault_path: str, secret_key: str, logger_instance: Optional[logging.Logger] = None):
        """
        Inicializa o VaultManager.

        Args:
            vault_path (str): Caminho para o arquivo JSON do Vault.
            secret_key (str): A chave secreta para criptografar/decriptar.
            logger_instance (Optional[logging.Logger]): Uma instância de logger (compatível com AuditLogger ou logging padrão).
                                                      Se None, o logger padrão do módulo será usado.
        
        Raises:
            ValueError: Se a chave secreta for inválida.
            ConfigurationError: Para problemas de caminho do Vault.
        """
        self.logger = logger_instance if logger_instance else logging.getLogger(__name__)
        
        # Configuração do caminho do Vault
        self.vault_path: Path = Path(vault_path)
        
        # Garante que o diretório do vault exista
        try:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Diretorio do Vault verificado/criado: {self.vault_path.parent}")
        except OSError as e:
            error_msg = f"Falha ao criar diretorio do Vault: {self.vault_path.parent}. Detalhes: {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise ConfigurationError(f"Caminho do Vault invalido ou inacessivel: {self.vault_path.parent}")

        # Configuração da chave secreta
        self.secret_key_str: str = secret_key
        try:
            self.fernet = Fernet(self.secret_key_str.encode())
            self.logger.info("Fernet inicializado com a chave secreta fornecida.")
        except Exception as e:
            error_msg = f"Chave secreta invalida para Fernet. Verifique o formato Base64 URL-safe. Detalhes: {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise ValueError(error_msg)

        # Carrega os dados do Vault na inicialização
        self.vault_data: Dict[str, Any] = self._load_vault()
        self.logger.info("VaultManager inicializado com sucesso.")


    def _load_vault(self) -> Dict[str, Any]:
        """
        Carrega o conteudo do arquivo Vault, decripta-o e o retorna como um dicionario.

        Returns:
            Dict[str, Any]: O dicionario contendo os segredos decriptados.

        Raises:
            VaultAccessError: Se houver problemas de acesso ao arquivo do Vault.
            KeyManagementError: Se a decriptografia falhar (chave incorreta ou dado corrompido).
            SecuritySystemBaseError: Para outros erros inesperados.
        """
        try:
            if not self.vault_path.exists() or self.vault_path.stat().st_size == 0:
                self.logger.info(f"Arquivo do Vault nao encontrado ou esta vazio em '{self.vault_path}'. Iniciando um Vault vazio.")
                return {} # Retorna um Vault vazio se o arquivo nao existe ou esta vazio
            
            with open(self.vault_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_bytes = self.fernet.decrypt(encrypted_data)
            decrypted_str = decrypted_bytes.decode('utf-8')
            
            data = json.loads(decrypted_str)
            self.logger.info(f"Vault carregado e decriptado com sucesso de '{self.vault_path}'.")
            return data
        except InvalidToken as e:
            error_msg = f"Erro ao decriptar o Vault: Chave Fernet incorreta ou dado corrompido em '{self.vault_path}'. Detalhes: {e}"
            self.logger.critical(error_msg, exc_info=True)
            # Re-lança como um erro de gerenciamento de chave
            raise KeyManagementError(f"Falha ao carregar Vault: {error_msg}", original_exception=e)
        except (IOError, OSError) as e:
            error_msg = f"Erro de I/O ao carregar o Vault em '{self.vault_path}': {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise VaultAccessError(f"Falha ao carregar Vault (erro de I/O): {e}", vault_path=str(self.vault_path))
        except json.JSONDecodeError as e:
            error_msg = f"Erro ao decodificar JSON do Vault em '{self.vault_path}'. Arquivo corrompido ou formato invalido apos decriptografia. Detalhes: {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise SecuritySystemBaseError(f"Vault corrompido (JSON invalido): {e}", original_exception=e)
        except Exception as e:
            error_msg = f"Erro inesperado ao carregar o Vault de '{self.vault_path}': {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise SecuritySystemBaseError(f"Falha inesperada ao carregar Vault: {e}", original_exception=e)


    def _save_vault(self) -> None:
        """
        Criptografa o conteudo atual do Vault e o persiste no arquivo.

        Raises:
            VaultAccessError: Se houver problemas de escrita no arquivo do Vault.
            SecuritySystemBaseError: Para outros erros inesperados.
        """
        try:
            json_data = json.dumps(self.vault_data, ensure_ascii=False) # Garante que UTF-8 seja mantido
            encrypted_data = self.fernet.encrypt(json_data.encode('utf-8'))
            
            with open(self.vault_path, 'wb') as f:
                f.write(encrypted_data)
            self.logger.info(f"Vault salvo com sucesso em '{self.vault_path}'.")
        except (IOError, OSError) as e:
            error_msg = f"Erro de I/O ao salvar o Vault em '{self.vault_path}': {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise VaultAccessError(f"Falha ao salvar Vault (erro de I/O): {e}", vault_path=str(self.vault_path))
        except Exception as e:
            error_msg = f"Erro inesperado ao salvar o Vault em '{self.vault_path}': {e}"
            self.logger.critical(error_msg, exc_info=True)
            raise SecuritySystemBaseError(f"Falha inesperada ao salvar Vault: {e}", original_exception=e)


    def get_secret(self, key: str) -> Optional[Any]:
        """
        Recupera um segredo especifico do Vault.

        Args:
            key (str): A chave (nome) do segredo a ser recuperado.

        Returns:
            Optional[Any]: O valor do segredo se encontrado, caso contrario None.
        """
        self.logger.info(f"Tentando recuperar segredo: '{key}' do Vault.")
        try:
            value = self.vault_data.get(key)
            if value is not None:
                self.logger.info(f"Segredo '{key}' encontrado no Vault.")
            else:
                self.logger.warning(f"Segredo '{key}' NAO encontrado no Vault.")
            return value
        except Exception as e:
            error_msg = f"Erro ao recuperar segredo '{key}' do Vault: {e}"
            self.logger.error(error_msg, exc_info=True)
            return None # Retorna None e loga, nao re-lanca para permitir fluxo


    def set_secret(self, key: str, value: Any) -> None:
        """
        Armazena ou atualiza um segredo no Vault e o persiste no arquivo.

        Args:
            key (str): A chave (nome) para o segredo.
            value (Any): O valor do segredo (pode ser string, int, dict, etc.).
        """
        self.logger.info(f"Tentando definir segredo: '{key}' no Vault.")
        try:
            self.vault_data[key] = value
            self._save_vault()
            self.logger.info(f"Segredo '{key}' definido e salvo com sucesso no Vault.")
        except Exception as e:
            error_msg = f"Erro ao definir segredo '{key}' no Vault: {e}"
            self.logger.error(error_msg, exc_info=True)
            # Re-lança para que o chamador possa lidar com a falha
            raise SecuritySystemBaseError(f"Falha ao definir segredo '{key}': {e}", original_exception=e)
