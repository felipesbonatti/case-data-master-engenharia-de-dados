"""
====================================================================================
MÓDULO: POOL DE CONEXÕES SEGURAS 
====================================================================================

DESCRIÇÃO:
    Este módulo implementa um Pool de Conexões Seguras (SecureConnectionPool),
    essencial para centralizar e gerenciar o acesso a serviços externos (bancos de dados,
    armazenamento de objetos) de forma segura e eficiente. Ele atua como um ponto único
    para obtenção de Engines de Banco de Dados (SQLAlchemy) e Clientes de Armazenamento
    de Objetos (MinIO/S3), garantindo que todas as credenciais sejam recuperadas
    do Vault de Segurança e que as conexões sejam reutilizadas quando possível.

ARQUITETURA:
    - Gerenciamento Centralizado: Oferece uma interface unificada para acessar diversos serviços.
    - Integração com Vault: As credenciais são sempre buscadas no Vault de Segurança.
    - Reutilização de Conexões: Armazena e retorna instâncias de engines/clientes existentes
      para otimizar recursos e performance.
    - Tratamento de Exceções: Lida com falhas de configuração e conexão de forma robusta.
    - Observabilidade: Integra-se com um sistema de auditoria para registrar eventos de conexão.

COMPONENTES E FUNCIONALIDADES:
    - SecureConnectionPool Class: Classe principal para gerenciar o pool de conexões.
    - get_engine(service_name): Retorna uma engine SQLAlchemy para conexão com banco de dados.
    - get_client(service_name): Retorna um cliente MinIO (compatível com S3) para armazenamento de objetos.
    - Integração com VaultManager: Para acesso seguro ao Vault.
    - Integração com AuditLogger: Para registrar eventos de conexão e falhas.
    - Tratamento de SecureConnectionError e ConfigurationError: Exceções customizadas
      para erros específicos de conexão e configuração, proporcionando maior clareza.

SEGURANÇA E CONFORMIDADE:
    - Credenciais nunca expostas no código ou em logs.
    - Autenticação de serviços externos via segredos recuperados do Vault.
    - Logs de auditoria para cada tentativa de conexão, sucesso ou falha.
    - Desativação de warnings SSL (para MinIO local de teste) com nota de produção.

OTIMIZAÇÃO E ESCALABILIDADE:
    - Reutilização de instâncias de Engine e Client para reduzir overhead de conexão.
    - Design modular que facilita a adição de novos tipos de conexão.
====================================================================================
"""

import os
import logging
import json # Para desserializar segredos do Vault
from typing import Dict, Any, Optional
from pathlib import Path # Para manipulação de caminhos robusta

import urllib3 # Para gerenciar avisos SSL com o cliente Minio
from minio import Minio
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

# Importações dos módulos de segurança customizados 
from security_system.vault_manager_helper import VaultManager # O gerenciador de segredos real
from security_system.audit import AuditLogger # O logger de auditoria
from security_system.exceptions import SecureConnectionError, ConfigurationError

# Configuração do logger para este módulo (assumindo configuração externa ou básica)
logger = logging.getLogger(__name__)

class SecureConnectionPool:
    """
    Gerencia um pool de conexões seguras para diversos serviços externos,
    como bancos de dados e armazenamento de objetos. As credenciais são
    recuperadas do Vault de Segurança para garantir a confidencialidade.
    """

    def __init__(self, security_manager: VaultManager, audit_logger: Optional[AuditLogger] = None):
        """
        Inicializa o SecureConnectionPool.

        Args:
            security_manager (VaultManager): Uma instância OBRIGATÓRIA do VaultManager,
                                             responsável por acessar os segredos.
            audit_logger (Optional[AuditLogger]): Uma instância do AuditLogger para registrar eventos.
                                                  Se não fornecida, uma instância básica será criada.

        Raises:
            ConfigurationError: Se security_manager não for uma instância válida de VaultManager.
        """
        if not isinstance(security_manager, VaultManager):
            raise ConfigurationError("security_manager deve ser uma instância válida de VaultManager.")
        
        self.security_manager: VaultManager = security_manager

        # Tenta usar o AuditLogger fornecido ou cria um básico se não for fornecido
        self.audit_logger: AuditLogger
        if audit_logger:
            self.audit_logger = audit_logger
        else:
            try:
                # Idealmente, os caminhos seriam configuráveis, mas para um pool
                # que pode ser instanciado em diferentes contextos, podemos usar padrões
                # ou exigir que os caminhos sejam passados.
                airflow_home_path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
                default_audit_path = airflow_home_path / 'logs' / 'security_audit' / 'default_audit.csv'
                default_system_log_path = airflow_home_path / 'logs' / 'security_audit' / 'default_system.log'
                
                # Garante que os diretórios existam
                default_audit_path.parent.mkdir(parents=True, exist_ok=True)
                default_system_log_path.parent.mkdir(parents=True, exist_ok=True)
                self.audit_logger = AuditLogger(str(default_audit_path), str(default_system_log_path))
                logger.warning("AuditLogger não fornecido. Usando uma instância padrão. Considere fornecer um AuditLogger configurado.")
            except ImportError:
                logger.error("AuditLogger não encontrado e não foi fornecido. Não será possível auditar conexões.")
                # Fallback para um logger que apenas imprime (apenas para evitar crash)
                class NoOpAuditLogger:
                    def log(self, *args, **kwargs): pass
                    def info(self, *args, **kwargs): pass
                    def error(self, *args, **kwargs): pass
                self.audit_logger = NoOpAuditLogger()
            except Exception as e:
                logger.error(f"Falha inesperada ao inicializar AuditLogger padrão: {e}. Auditoria de conexões será limitada.")
                class NoOpAuditLogger:
                    def log(self, *args, **kwargs): pass
                    def info(self, *args, **kwargs): pass
                    def error(self, *args, **kwargs): pass
                self.audit_logger = NoOpAuditLogger()

        self.engines: Dict[str, Engine] = {} # Armazena engines SQLAlchemy
        self.clients: Dict[str, Any] = {}    # Armazena clientes MinIO

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
            f"Requisição de engine de DB: '{service_name}'",
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
            error_msg = f"Credenciais para o serviço de DB '{service_name}' não encontradas no Vault sob a chave '{secret_name}'."
            self.audit_logger.error(
                error_msg,
                action="DB_CREDS_MISSING", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        
        try:
            secret_data = json.loads(secret_data_encrypted)
        except json.JSONDecodeError as e:
            error_msg = f"Formato de credenciais DB inválido para '{service_name}' no Vault (JSON inválido): {e}."
            self.audit_logger.error(
                error_msg,
                action="DB_CREDS_JSON_ERROR", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)

        try:
            # A URL base define o dialeto (e.g., 'postgresql+psycopg2://')
            db_url = f"{secret_data.get('dialect', 'postgresql')}+{secret_data.get('driver', 'psycopg2')}://"

            # Parâmetros de conexão explícitos para o driver psycopg2
            connect_args = {
                "host": secret_data.get('host'),
                "port": secret_data.get('port'),
                "user": secret_data.get('user'),
                "password": secret_data.get('password'),
                "dbname": secret_data.get('database'), # 'database' para psycopg2, não 'dbname'
            }
            logger.debug(f"Criando engine com connect_args: {connect_args}")
            
            engine = create_engine(db_url, connect_args=connect_args)
            
            # Opcional: Testar a conexão para verificar se a engine funciona
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
            error_msg = f"Credencial faltando para o serviço de DB '{service_name}' na chave '{e}'."
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
        Recupera ou cria um cliente MinIO para o serviço especificado.

        Args:
            service_name (str): Nome do serviço MinIO (e.g., 'minio_local').
                                 As credenciais são buscadas no Vault sob '{service_name}_credentials'.
                                 O nome padrão 'minio_local' é para compatibilidade com exemplos.

        Returns:
            minio.Minio: Uma instância do cliente Minio.

        Raises:
            ConfigurationError: Se as credenciais não forem encontradas ou estiverem incompletas/inválidas no Vault.
            SecureConnectionError: Se houver uma falha ao criar o cliente MinIO.
        """
        logger.info(f"Tentando obter cliente MinIO para o serviço: '{service_name}'")
        self.audit_logger.log(
            f"Requisição de cliente MinIO: '{service_name}'",
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
            error_msg = f"Credenciais para o serviço MinIO '{service_name}' não encontradas ou inválidas no Vault sob a chave '{secret_name}'."
            self.audit_logger.error(
                error_msg,
                action="MINIO_CREDS_MISSING", service="ConnectionPool", risk_level="CRITICAL", error_message=error_msg
            )
            logger.error(error_msg)
            raise ConfigurationError(error_msg)
        
        try:
            secret_data = json.loads(secret_data_encrypted)
        except json.JSONDecodeError as e:
            error_msg = f"Formato de credenciais MinIO inválido para '{service_name}' no Vault (JSON inválido): {e}."
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
            
            # Desabilitar verificações SSL para MinIO local (apenas para ambiente de desenvolvimento/teste)
            # EM PRODUÇÃO: Configure o certificado SSL corretamente e remova `disable_warnings` e `cert_reqs='CERT_NONE'`.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            http_client = urllib3.PoolManager(
                cert_reqs='CERT_NONE', # Não verificar certificados SSL
                timeout=urllib3.Timeout(connect=10.0, read=30.0) # Adicionar timeouts
            )

            client = Minio(
                endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=False, # Defina como True se seu MinIO usar HTTPS com certificado válido
                http_client=http_client
            )
            
            # Opcional: Testar a conexão com o MinIO (por exemplo, listando buckets)
            client.list_buckets()
            logger.info(f"Cliente MinIO para '{service_name}' criado e testado com sucesso.")
            
            self.clients[service_name] = client
            self.audit_logger.log(
                f"Cliente MinIO '{service_name}' criado com sucesso.",
                action="MINIO_CLIENT_CREATED", service="ConnectionPool"
            )
            return client
        except KeyError as e:
            error_msg = f"Credencial faltando para o serviço MinIO '{service_name}' na chave '{e}'."
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
