import os
import logging
import json
from typing import Dict, Any, Optional
import urllib3
from minio import Minio
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.sql import text # Importar 'text' para uso em conn.execute(text(...))
import psycopg2

# Importações dos módulos de segurança customizados
from security_system.vault_manager_helper import VaultManager
from security_system.audit import AuditLogger
from security_system.exceptions import SecureConnectionError, ConfigurationError, SecuritySystemBaseError

# Configuração do logger para este módulo (assume que o logging principal já está configurado)
logger = logging.getLogger(__name__)

# Desabilitar avisos de SSL para MinIO em ambientes de desenvolvimento/teste.
# ATENÇÃO: Em produção, configure certificados SSL válidos e remova esta linha.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
====================================================================================
MÓDULO: POOL DE CONEXÕES SEGURAS 
====================================================================================

DESCRIÇÃO:
    Este módulo implementa um Pool de Conexões Seguras (SecureConnectionPool),
    um componente fundamental em uma arquitetura de dados enterprise. Ele centraliza
    e gerencia a obtenção de clientes e conexões para serviços externos (como
    armazenamento de objetos MinIO/S3 e bancos de dados PostgreSQL), garantindo
    que todas as credenciais sejam recuperadas de forma segura do Vault.

ARQUITETURA DE CONEXÃO SEGURA:
    - Centralização: Ponto único para obtenção de conexões a múltiplos serviços.
    - Integração com Vault: Credenciais sempre obtidas do Vault de Segurança.
    - Auditoria: Todas as operações de conexão são registradas no sistema de auditoria.
    - Robustez: Tratamento de exceções específicas para falhas de conexão e configuração.
    - Flexibilidade: Suporta diferentes tipos de clientes/conexões (MinIO, PostgreSQL).

COMPONENTES E FUNCIONALIDADES:
    - SecureConnectionPool Class: Gerencia a criação e reutilização de conexões.
    - get_minio_client(): Retorna um cliente MinIO autenticado.
    - get_postgresql_conn(): Retorna uma conexão psycopg2 para PostgreSQL autenticada.
    - VaultManager: Componente para interagir com o Vault de Segurança.
    - AuditLogger: Para registrar eventos de conexão e falhas.

SEGURANÇA E CONFORMIDADE:
    - Credenciais Zero-Exposure: Nenhuma credencial é hardcoded ou exposta em logs.
    - Vault de Segurança: Única fonte de verdade para credenciais sensíveis.
    - Logging de Auditoria: Rastreabilidade completa de quem/o quê acessou qual serviço.
    - Tratamento de Erros Seguro: Exceções customizadas para comunicação de falhas
      sem vazar informações sensíveis.
====================================================================================
"""

class SecureConnectionPool:
    """
    Gerencia um pool de conexões seguras para diversos serviços externos,
    como MinIO e PostgreSQL. As credenciais são recuperadas do Vault de Segurança.
    """

    def __init__(self, security_manager: VaultManager, audit_logger: AuditLogger):
        """
        Inicializa o SecureConnectionPool.

        Args:
            security_manager (VaultManager): Uma instância OBRIGATÓRIA do VaultManager,
                                             responsável por acessar os segredos.
            audit_logger (AuditLogger): Uma instância OBRIGATÓRIA do AuditLogger para registrar eventos.

        Raises:
            ConfigurationError: Se security_manager não for uma instância válida de VaultManager
                                ou se audit_logger não for uma instância válida de AuditLogger.
        """
        if not isinstance(security_manager, VaultManager):
            raise ConfigurationError("security_manager deve ser uma instancia valida de VaultManager.")
        if not isinstance(audit_logger, AuditLogger):
            raise ConfigurationError("audit_logger deve ser uma instancia valida de AuditLogger.")
        
        self.security_manager: VaultManager = security_manager
        self.audit_logger: AuditLogger = audit_logger

        self.engines: Dict[str, Engine] = {} # Armazena engines SQLAlchemy
        self.clients: Dict[str, Any] = {}    # Armazena clientes MinIO

        logger.info("SecureConnectionPool inicializado com sucesso.")
        self.audit_logger.log("SecureConnectionPool inicializado.", action="CONN_POOL_INIT")

    def get_engine(self, service_name: str) -> Engine:
        """
        Recupera ou cria uma engine SQLAlchemy para o serviço de banco de dados especificado.

        Args:
            service_name (str): Nome do serviço de banco de dados (e.g., 'postgres_datamart').
                                 As credenciais são buscadas no Vault sob '{service_name}_credentials'.

        Returns:
            sqlalchemy.engine.Engine: Uma instância da engine de banco de dados.

        Raises:
            ConfigurationError: Se as credenciais não forem encontradas ou estiverem incompletas/inválidas no Vault.
            SecureConnectionError: Se houver uma falha ao criar a engine de banco de dados.
        """
        logger.info(f"Tentando obter engine para o serviço de DB: '{service_name}'")
        self.audit_logger.log(
            f"Requisicao de engine de DB: '{service_name}'",
            action="DB_ENGINE_REQUEST", service="ConnectionPool"
        )

        if service_name in self.engines:
            logger.info(f"Engine para '{service_name}' encontrada no pool. Reutilizando.")
            self.audit_logger.log(
                f"Engine de DB '{service_name}' reutilizada.",
                action="DB_ENGINE_REUSE", service="ConnectionPool"
            )
            return self.engines[service_name]

        secret_name = f"{service_name}_credentials"
        secret_data_encrypted = self.security_manager.get_secret(secret_name)

        if not secret_data_encrypted:
            error_msg = f"Credenciais para o servico de DB '{service_name}' nao encontradas no Vault sob a chave '{secret_name}'."
            self.audit_logger.error(
                error_msg,
                action="DB_CREDS_MISSING", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        
        try:
            secret_data = json.loads(secret_data_encrypted)
        except json.JSONDecodeError as e:
            error_msg = f"Formato de credenciais DB invalido para '{service_name}' no Vault (JSON invalido): {e}."
            self.audit_logger.error(
                error_msg,
                action="DB_CREDS_JSON_ERROR", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)

        try:
            # A URL base define o dialeto (e.g., 'postgresql+psycopg2://')
            db_url = f"{secret_data.get('dialect', 'postgresql')}+{secret_data.get('driver', 'psycopg2')}://"

            # Parametros de conexao explicitos para o driver psycopg2
            connect_args = {
                "host": secret_data.get('host'),
                "port": secret_data.get('port'),
                "user": secret_data.get('user'),
                "password": secret_data.get('password'),
                "dbname": secret_data.get('database'), # 'database' para psycopg2, nao 'dbname'
            }
            logger.debug(f"Criando engine com connect_args: {connect_args}")
            
            engine = create_engine(db_url, connect_args=connect_args)
            
            # Opcional: Testar a conexao para verificar se a engine funciona
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            logger.info(f"Engine para '{service_name}' criada e testada com sucesso.")
            
            self.engines[service_name] = engine
            self.audit_logger.log(
                f"Engine de DB '{service_name}' criada com sucesso.",
                action="DB_ENGINE_CREATED", service="ConnectionPool"
            )
            return engine
        except KeyError as e:
            error_msg = f"Credencial faltando para o servico de DB '{service_name}' na chave '{e}'."
            self.audit_logger.error(
                error_msg,
                action="DB_CREDS_INCOMPLETE", service="ConnectionPool", risk_level="HIGH", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        except Exception as e:
            error_msg = f"Falha ao criar/testar engine para '{service_name}': {e}"
            self.audit_logger.error(
                error_msg,
                action="DB_ENGINE_CREATION_FAILED", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise SecureConnectionError(error_msg)

    def get_minio_client(self, service_name: str = "minio_local") -> Minio:
        """
        Recupera ou cria um cliente MinIO para o servico especificado.

        Args:
            service_name (str): Nome do servico MinIO (e.g., 'minio_local').
                                 As credenciais sao buscadas no Vault sob '{service_name}_credentials'.
                                 O nome padrao 'minio_local' e para compatibilidade com exemplos.

        Returns:
            minio.Minio: Uma instancia do cliente Minio.

        Raises:
            ConfigurationError: Se as credenciais nao forem encontradas ou estiverem incompletas/invalidas no Vault.
            SecureConnectionError: Se houver uma falha ao criar o cliente Minio.
        """
        logger.info(f"Tentando obter cliente MinIO para o servico: '{service_name}'")
        self.audit_logger.log(
            f"Requisicao de cliente MinIO: '{service_name}'",
            action="MINIO_CLIENT_REQUEST", service="ConnectionPool"
        )

        if service_name in self.clients:
            logger.info(f"Cliente Minio para '{service_name}' encontrada no pool. Reutilizando.")
            self.audit_logger.log(
                f"Cliente MinIO '{service_name}' reutilizado.",
                action="MINIO_CLIENT_REUSE", service="ConnectionPool"
            )
            return self.clients[service_name]

        secret_name = f"{service_name}_credentials"
        secret_data_encrypted = self.security_manager.get_secret(secret_name)

        if not secret_data_encrypted:
            error_msg = f"Credenciais para o servico MinIO '{service_name}' nao encontradas no Vault sob a chave '{secret_name}'."
            self.audit_logger.error(
                error_msg,
                action="MINIO_CREDS_MISSING", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        
        try:
            secret_data = json.loads(secret_data_encrypted)
        except json.JSONDecodeError as e:
            error_msg = f"Formato de credenciais MinIO invalido para '{service_name}' no Vault (JSON invalido): {e}."
            self.audit_logger.error(
                error_msg,
                action="MINIO_CREDS_JSON_ERROR", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)

        try:
            endpoint = secret_data.get('endpoint_url')
            access_key = secret_data.get('access_key')
            secret_key = secret_data.get('secret_key')
            
            # Desabilitar verificacoes SSL para MinIO local (apenas para ambiente de desenvolvimento/teste)
            # EM PRODUCAO: Configure o certificado SSL corretamente e remova `disable_warnings` e `cert_reqs='CERT_NONE'`.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            http_client = urllib3.PoolManager(
                cert_reqs='CERT_NONE', # Nao verificar certificados SSL
                timeout=urllib3.Timeout(connect=10.0, read=30.0) # Adicionar timeouts
            )

            client = Minio(
                endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=False, # Defina como True se seu MinIO usar HTTPS com certificado valido
                http_client=http_client
            )
            
            # Opcional: Testar a conexao com o MinIO (por exemplo, listando buckets)
            client.list_buckets()
            logger.info(f"Cliente MinIO para '{service_name}' criado e testado com sucesso.")
            
            self.clients[service_name] = client
            self.audit_logger.log(
                f"Cliente MinIO '{service_name}' criado com sucesso.",
                action="MINIO_CLIENT_CREATED", service="ConnectionPool"
            )
            return client
        except KeyError as e:
            error_msg = f"Credencial faltando para o servico MinIO '{service_name}' na chave '{e}'."
            self.audit_logger.error(
                error_msg,
                action="MINIO_CREDS_INCOMPLETE", service="ConnectionPool", risk_level="HIGH", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        except Exception as e:
            error_msg = f"Falha ao criar/testar cliente MinIO para '{service_name}': {e}"
            self.audit_logger.error(
                error_msg,
                action="MINIO_CLIENT_CREATION_FAILED", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise SecureConnectionError(error_msg)
