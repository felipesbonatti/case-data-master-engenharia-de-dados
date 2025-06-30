"""
====================================================================================
MÓDULO: PROTEÇÃO DE DADOS (MASCARAMENTO E PRIVACIDADE)
====================================================================================

DESCRIÇÃO:
    Este módulo implementa funcionalidades avançadas de proteção de dados,
    incluindo mascaramento (pseudonimização, anonimização) e privacidade diferencial.
    É uma ferramenta essencial para garantir a conformidade com regulamentações
    de privacidade (como LGPD/GDPR) e proteger informações sensíveis em datasets
    utilizados para análise, teste ou treinamento de modelos.

ARQUITETURA DE PROTEÇÃO DE DADOS:
    - Mascaramento Flexível: Suporte a diversas técnicas (hash, fake, estático, parcial).
    - Privacidade Diferencial: Adição de ruído controlado para proteger a privacidade
      individual em dados agregados.
    - Integração com Vault: Recuperação segura de chaves de mascaramento.
    - Integração com Auditoria: Registro detalhado de todas as operações de proteção.
    - Tratamento de Exceções: Resiliência contra dados inválidos ou configurações incorretas.

COMPONENTES E FUNCIONALIDADES:
    - DataProtection Class: Classe principal para orquestrar as operações de proteção.
    - mask_data: Aplica diferentes métodos de mascaramento a séries de dados.
    - add_differential_privacy: Adiciona ruído Laplaciano para garantir privacidade diferencial.
    - _get_masking_key: Recupera chaves de mascaramento do Vault de Segurança.
    - Integração com VaultManager e AuditLogger.

MÉTODOS DE MASCARAMENTO:
    - hash: Substitui o valor por um hash criptográfico (SHA256), irreversível.
    - fake: Substitui o valor por dados sintéticos realistas (e.g., nome falso, e-mail falso).
    - static: Substitui o valor por uma string estática predefinida (e.g., "[MASCARADO]").
    - partial: Mascara parte do valor original (e.g., "CPF-***.***.123-**").

SEGURANÇA E CONFORMIDADE (LGPD/GDPR):
    - Pseudonimização: Uso de hashing e dados fake para reduzir a identificabilidade direta.
    - Anonimização: Privacidade diferencial para proteger a privacidade em dados agregados.
    - Rastreabilidade: Logs de auditoria para cada operação de proteção de dados.
    - Gerenciamento de Chaves: Chaves de mascaramento gerenciadas de forma segura no Vault.
====================================================================================
"""

import pandas as pd
import hashlib
from faker import Faker
import re # Mantido caso 're' seja usado em futuros métodos de mascaramento
import logging
import os
import numpy as np
from typing import Dict, Any, Optional
from pathlib import Path # Para manipulação de caminhos robusta

# Importações dos módulos de segurança customizados
from security_system.vault_manager_helper import VaultManager # O gerenciador de segredos real
from security_system.audit import AuditLogger # O logger de auditoria
from security_system.exceptions import SecurityViolation, ValidationError, KeyManagementError, SecuritySystemBaseError, ConfigurationError

# Configuração do logger para este módulo (assume configuração externa ou básica)
logger = logging.getLogger(__name__)

class DataProtection:
    """
    Fornece funcionalidades para proteção de dados, incluindo diversas técnicas
    de mascaramento e aplicação de privacidade diferencial. Integra-se com um
    Vault de segurança para gerenciamento de chaves e um sistema de auditoria.
    """

    def __init__(self, security_manager: VaultManager, audit_logger: Optional[AuditLogger] = None):
        """
        Inicializa a classe DataProtection.

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
        self.faker = Faker('pt_BR')
        
        # Inicialização do AuditLogger
        self.audit: AuditLogger
        if audit_logger:
            self.audit = audit_logger
        else:
            try:
                # Tenta criar um AuditLogger padrão se nenhum for fornecido
                airflow_home_path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
                default_audit_path = airflow_home_path / 'logs' / 'security_audit' / 'default_audit.csv'
                default_system_log_path = airflow_home_path / 'logs' / 'security_audit' / 'default_system.log'
                
                # Garante que os diretórios existam
                default_audit_path.parent.mkdir(parents=True, exist_ok=True)
                default_system_log_path.parent.mkdir(parents=True, exist_ok=True)
                self.audit = AuditLogger(str(default_audit_path), str(default_system_log_path))
                logger.warning("AuditLogger nao fornecido para DataProtection. Usando instancia padrao.")
            except ImportError:
                logger.error("AuditLogger nao encontrado e nao foi fornecido. O logging de auditoria pode estar desabilitado para este modulo.")
                class NoOpAuditLogger:
                    def log(self, *args, **kwargs): pass
                    def info(self, *args, **kwargs): pass
                    def error(self, *args, **kwargs): pass
                self.audit = NoOpAuditLogger()
            except Exception as e:
                logger.error(f"Falha inesperada ao inicializar AuditLogger padrao: {e}. Auditoria de conexoes sera limitada.")
                class NoOpAuditLogger:
                    def log(self, *args, **kwargs): pass
                    def info(self, *args, **kwargs): pass
                    def error(self, *args, **kwargs): pass
                self.audit = NoOpAuditLogger()
        
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        self._masking_key: Optional[bytes] = None # Chave de mascaramento cacheada

    def _get_masking_key(self) -> bytes:
        """
        Recupera a chave de mascaramento do Vault de Seguranca.
        Em caso de falha, tenta usar uma chave de fallback de variavel de ambiente.

        Returns:
            bytes: A chave de mascaramento codificada em UTF-8.

        Raises:
            KeyManagementError: Se nao for possivel obter uma chave de mascaramento valida
                                (nem do Vault, nem do fallback).
        """
        if self._masking_key is not None:
            return self._masking_key

        try:
            # VaultManager.get_secret retorna uma string (a chave em si, se armazenada como uma string)
            key_from_vault = self.security_manager.get_secret("data_masking_key")
            
            if key_from_vault and isinstance(key_from_vault, str):
                self._masking_key = key_from_vault.encode('utf-8')
                self.logger.info("Chave de mascaramento recuperada do Vault.")
                if self.audit: self.audit.log("Chave de mascaramento recuperada do Vault.", action="MASKING_KEY_RETRIEVED", service="DataProtection")
            else:
                # Fallback para variavel de ambiente se nao encontrada no Vault ou formato invalido
                fallback_key = os.getenv('FALLBACK_MASKING_KEY', 'default_fallback_key_for_masking_do_not_use_in_prod')
                self._masking_key = fallback_key.encode('utf-8')
                self.logger.warning("Chave de mascaramento 'data_masking_key' nao encontrada ou invalida no Vault. Usando chave de fallback.")
                if self.audit: self.audit.log("Chave de mascaramento de fallback usada (Vault nao forneceu chave valida).", level="WARNING", action="MASKING_KEY_FALLBACK", service="DataProtection", risk_level="MEDIUM")
            
            return self._masking_key

        except Exception as e:
            # Caso ocorra um erro ao tentar acessar o Vault
            fallback_key = os.getenv('FALLBACK_MASKING_KEY', 'default_fallback_key_for_masking_do_not_use_in_prod')
            self._masking_key = fallback_key.encode('utf-8')
            
            error_message = f"Erro critico ao obter chave de mascaramento do Vault: {e}. Usando chave de fallback. Verifique o Vault e a configuracao da chave."
            self.logger.error(error_message, exc_info=True)
            if self.audit: self.audit.log(error_message, level="ERROR", action="MASKING_KEY_VAULT_ERROR_FALLBACK_USED", service="DataProtection", risk_level="CRITICAL", error_message=str(e), stack_trace_needed=True)
            
            # Re-lança uma excecao customizada apos tentar o fallback e logar
            raise KeyManagementError(f"Falha critica na gestao da chave de mascaramento: {error_message}")


    def mask_data(self, data_series: pd.Series, masking_method: str, column_name: str = "N/A", **kwargs) -> pd.Series:
        """
        Aplica uma tecnica de mascaramento a uma Series de dados Pandas.

        Args:
            data_series (pd.Series): A serie de dados a ser mascarada.
            masking_method (str): O metodo de mascaramento a ser aplicado ('hash', 'fake', 'static', 'partial').
            column_name (str): O nome da coluna sendo mascarada (para fins de logging e metodos 'fake'). Padrao e "N/A".
            kwargs: Argumentos adicionais especificos para alguns metodos:
                      - 'static_value' (para 'static'): O valor estatico a ser usado.
                      - 'start_len', 'end_len', 'mask_char' (para 'partial'): Parametros para mascaramento parcial.

        Returns:
            pd.Series: Uma nova serie de dados com os valores mascarados.

        Raises:
            SecuritySystemBaseError: Se o metodo de mascaramento nao for suportado ou ocorrer uma falha durante o mascaramento.
        """
        masked_data = data_series.copy()
        operation_details = {"column": column_name, "method": masking_method}
        log_column_name = column_name if column_name else "N/A"

        self.logger.info(f"Iniciando mascaramento da coluna '{log_column_name}' usando o metodo '{masking_method}'.")
        if self.audit: self.audit.log(f"Iniciando mascaramento de dados.", action="DATA_MASKING_START", resource=log_column_name, details=operation_details)

        try:
            if masking_method == 'hash':
                masking_key = self._get_masking_key() # Recupera a chave para hashing com salt
                masked_data = data_series.apply(
                    lambda x: hashlib.sha256(f"{str(x)}{masking_key.decode('utf-8')}".encode('utf-8')).hexdigest()
                    if pd.notna(x) else np.nan # Garante que NaN permaneca NaN
                )
                if self.audit: self.audit.log(f"Dados mascarados por hash (com salt) na coluna '{log_column_name}'.", action="DATA_MASKED_HASH", resource=log_column_name, compliance_status="LGPD_PSEUDONYMIZED", details=operation_details)
            
            elif masking_method == 'fake':
                # Mapeamento para tipos de dados fake comuns
                if column_name == 'email':
                    masked_data = data_series.apply(lambda x: self.faker.email() if pd.notna(x) else np.nan)
                elif column_name == 'nome' or column_name == 'name':
                    masked_data = data_series.apply(lambda x: self.faker.name() if pd.notna(x) else np.nan)
                elif column_name == 'endereco' or column_name == 'address':
                    masked_data = data_series.apply(lambda x: self.faker.address() if pd.notna(x) else np.nan)
                elif column_name == 'telefone' or column_name == 'phone':
                    masked_data = data_series.apply(lambda x: self.faker.phone_number() if pd.notna(x) else np.nan)
                elif column_name == 'cpf':
                    masked_data = data_series.apply(lambda x: self.faker.cpf() if pd.notna(x) else np.nan)
                else:
                    # Fallback para um tipo generico se a coluna nao for reconhecida
                    masked_data = data_series.apply(lambda x: self.faker.word() if pd.notna(x) else np.nan)
                if self.audit: self.audit.log(f"Dados mascarados por dados fake na coluna '{log_column_name}'.", action="DATA_MASKED_FAKE", resource=log_column_name, compliance_status="LGPD_PSEUDONYMIZED", details=operation_details)
            
            elif masking_method == 'static':
                static_value = kwargs.get('static_value', '[DADO_MASCARADO]')
                masked_data = data_series.apply(lambda x: static_value if pd.notna(x) else np.nan)
                if self.audit: self.audit.log(f"Dados mascarados por valor estatico ('{static_value}') na coluna '{log_column_name}'.", action="DATA_MASKED_STATIC", resource=log_column_name, compliance_status="LGPD_ANONYMIZED", details=operation_details)
            
            elif masking_method == 'partial':
                start_len = kwargs.get('start_len', 0)
                end_len = kwargs.get('end_len', 0)
                mask_char = str(kwargs.get('mask_char', '*')) # Garante que mask_char e string
                
                if not isinstance(start_len, int) or not isinstance(end_len, int) or start_len < 0 or end_len < 0:
                    raise ValueError("start_len e end_len devem ser inteiros nao negativos para mascaramento parcial.")

                def partial_mask_func(value):
                    if pd.isna(value): return np.nan
                    s_value = str(value)
                    
                    # Evita erro se start_len + end_len for maior que o comprimento da string
                    if start_len + end_len >= len(s_value):
                        return mask_char * len(s_value) # Mascara tudo
                    
                    core_len = len(s_value) - start_len - end_len
                    return s_value[:start_len] + (mask_char * core_len) + s_value[len(s_value)-end_len:]
                
                masked_data = data_series.apply(partial_mask_func)
                if self.audit: self.audit.log(f"Dados mascarados parcialmente na coluna '{log_column_name}'.", action="DATA_MASKED_PARTIAL", resource=log_column_name, compliance_status="LGPD_PSEUDONYMIZED", details=operation_details)
            
            else:
                raise ValueError(f"Metodo de mascaramento '{masking_method}' nao suportado.")
            
            self.logger.info(f"Mascaramento da coluna '{log_column_name}' concluido com sucesso.")
            if self.audit: self.audit.log(f"Mascaramento de dados concluido.", action="DATA_MASKING_COMPLETE", resource=log_column_name, details=operation_details)
        
        except (ValueError, KeyError, TypeError) as e:
            error_msg = f"Erro de validacao/configuracao ao mascarar dados na coluna '{log_column_name}' com metodo '{masking_method}': {e}"
            if self.audit: self.audit.log(error_msg, level="ERROR", action="DATA_MASK_VALIDATION_FAIL", resource=log_column_name, details={"error": str(e), **operation_details}, stack_trace_needed=True)
            self.logger.error(error_msg, exc_info=True)
            raise ValidationError(f"Falha na validacao/configuracao ao mascarar dados: {e}")
        except KeyManagementError as e:
            # Re-lança a excecao original de gerenciamento de chave
            raise
        except Exception as e:
            error_msg = f"Erro inesperado ao mascarar dados na coluna '{log_column_name}' com metodo '{masking_method}': {e}"
            if self.audit: self.audit.log(error_msg, level="CRITICAL", action="DATA_MASK_UNEXPECTED_FAIL", resource=log_column_name, details={"error": str(e), **operation_details}, stack_trace_needed=True)
            self.logger.critical(error_msg, exc_info=True)
            raise SecuritySystemBaseError(f"Falha critica e inesperada ao mascarar dados: {e}")
            
        return masked_data

    def add_differential_privacy(self, df: pd.DataFrame, column_name: str, epsilon: float, sensitivity: float) -> pd.DataFrame:
        """
        Aplica privacidade diferencial a uma coluna numerica de um DataFrame usando o mecanismo Laplaciano.
        Isso adiciona ruido calibrado para proteger a privacidade individual.

        Args:
            df (pd.DataFrame): O DataFrame original.
            column_name (str): O nome da coluna numerica a qual a privacidade diferencial sera aplicada.
            epsilon (float): O parametro de privacidade (menor epsilon = mais privacidade, mais ruido).
                             Deve ser > 0.
            sensitivity (float): A sensibilidade da funcao (maxima mudanca na saida da consulta
                                 quando um unico individuo e adicionado/removido).

        Returns:
            pd.DataFrame: Uma copia do DataFrame com a coluna especificada contendo ruido Laplaciano.

        Raises:
            ValueError: Se a coluna nao for encontrada, nao for numerica, ou se epsilon for invalido.
            SecuritySystemBaseError: Para erros inesperados durante a aplicacao da privacidade diferencial.
        """
        self.logger.info(f"Iniciando aplicacao de privacidade diferencial na coluna '{column_name}'. Epsilon: {epsilon}, Sensibilidade: {sensitivity}.")
        if self.audit: self.audit.log(f"Aplicando privacidade diferencial.", action="DIFFERENTIAL_PRIVACY_START", resource=column_name, details={"epsilon": epsilon, "sensitivity": sensitivity})

        if column_name not in df.columns:
            error_msg = f"Coluna '{column_name}' nao encontrada no DataFrame para aplicacao de privacidade diferencial."
            self.logger.error(error_msg)
            if self.audit: self.audit.log(error_msg, level="ERROR", action="DP_COLUMN_NOT_FOUND", resource=column_name, error_message=error_msg)
            raise ValueError(error_msg)
            
        if not pd.api.types.is_numeric_dtype(df[column_name]):
            error_msg = f"Coluna '{column_name}' nao e numerica. A privacidade diferencial (Laplaciana) so pode ser aplicada a colunas numericas."
            self.logger.error(error_msg)
            if self.audit: self.audit.log(error_msg, level="ERROR", action="DP_NON_NUMERIC_COLUMN", resource=column_name, error_message=error_msg)
            raise ValueError(error_msg)

        if not isinstance(epsilon, (int, float)) or epsilon <= 0:
            error_msg = f"Epsilon deve ser um numero positivo. Valor fornecido: {epsilon}."
            self.logger.error(error_msg)
            if self.audit: self.audit.log(error_msg, level="ERROR", action="DP_INVALID_EPSILON", resource=column_name, error_message=error_msg)
            raise ValueError(error_msg)
            
        if not isinstance(sensitivity, (int, float)) or sensitivity < 0:
            error_msg = f"Sensibilidade deve ser um numero nao negativo. Valor fornecido: {sensitivity}."
            self.logger.error(error_msg)
            if self.audit: self.audit.log(error_msg, level="ERROR", action="DP_INVALID_SENSITIVITY", resource=column_name, error_message=error_msg)
            raise ValueError(error_msg)

        try:
            scale = sensitivity / epsilon
            # Adiciona ruido Laplaciano a cada valor na coluna
            noise = np.random.laplace(0, scale, len(df))
            
            df_dp = df.copy()
            df_dp[column_name] = df_dp[column_name] + noise
            
            self.logger.info(f"Privacidade diferencial aplicada a coluna '{column_name}'. Ruido Laplaciano com escala {scale:.4f}.")
            if self.audit: self.audit.log(
                f"Privacidade diferencial aplicada a coluna '{column_name}'.",
                action="DIFFERENTIAL_PRIVACY_APPLIED",
                resource=column_name,
                compliance_status="LGPD_ANONYMIZED", # Privacidade diferencial e uma tecnica de anonimizacao forte
                details={"epsilon": epsilon, "sensitivity": sensitivity, "scale": scale}
            )
            return df_dp
        except Exception as e:
            error_msg = f"Erro inesperado ao aplicar privacidade diferencial na coluna '{column_name}': {e}"
            self.logger.critical(error_msg, exc_info=True)
            if self.audit: self.audit.log(error_msg, level="CRITICAL", action="DIFFERENTIAL_PRIVACY_FAIL", resource=column_name, error_message=str(e), stack_trace_needed=True)
            raise SecuritySystemBaseError(f"Falha critica ao aplicar privacidade diferencial: {e}")
