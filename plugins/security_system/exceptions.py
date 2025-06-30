"""
====================================================================================
MÓDULO: EXCEÇÕES CUSTOMIZADAS DO SISTEMA DE SEGURANÇA 
====================================================================================

DESCRIÇÃO:
    Este módulo define uma hierarquia de exceções customizadas para o sistema de
    segurança de dados. Ao utilizar exceções específicas, é possível capturar e
    tratar erros de forma mais granular e informativa, facilitando a depuração,
    auditoria e a implementação de respostas automatizadas a incidentes de segurança.
    Todas as exceções derivam de `AirflowException` para garantir compatibilidade
    e tratamento adequado pelo Apache Airflow.

HIERARQUIA DE EXCEÇÕES:
    - SecuritySystemBaseError (Base para todas as exceções de segurança)
        - KeyManagementError (Problemas com chaves de criptografia/mascaramento)
        - ConfigurationError (Configurações ausentes ou inválidas)
        - AuditLogError (Problemas no sistema de log de auditoria)
        - VaultAccessError (Falhas ao acessar o Vault de segredos)
        - SecurityViolation (Detecção de uma violação de segurança)
        - ValidationError (Falhas em validações de dados ou de segurança)
        - SecureConnectionError (Erros em operações de conexão segura)

BENEFÍCIOS DA ABORDAGEM:
    - Clareza: O tipo da exceção indica a natureza exata do problema.
    - Diagnóstico Aprimorado: Campos adicionais nas exceções fornecem contexto relevante.
    - Tratamento Específico: Permite blocos `try-except` mais focados.
    - Rastreabilidade: Facilita a identificação da origem e do tipo de falha em logs e sistemas de monitoramento.
    - Padrão Airflow: Compatibilidade total com o mecanismo de tratamento de exceções do Airflow.
====================================================================================
"""

from airflow.exceptions import AirflowException

class SecuritySystemBaseError(AirflowException):
    """
    Exceção base para todos os erros relacionados ao sistema de segurança de dados.
    Todas as exceções específicas do sistema de segurança devem herdar desta classe.
    """
    def __init__(self, message: str, original_exception: Exception = None, details: dict = None):
        """
        Inicializa a exceção base do sistema de segurança.

        Args:
            message (str): Uma mensagem descritiva do erro.
            original_exception (Exception, optional): A exceção original que causou este erro,
                                                      útil para rastreamento. Padrão é None.
            details (dict, optional): Um dicionário com detalhes adicionais contextuais sobre o erro.
                                      Padrão é um dicionário vazio.
        """
        super().__init__(message)
        self.original_exception = original_exception
        self.details = details if details is not None else {}

class KeyManagementError(SecuritySystemBaseError):
    """
    Levantada quando ocorre um problema durante as operações de gerenciamento de chaves
    (e.g., falha ao gerar, armazenar, recuperar ou usar chaves de criptografia/mascaramento).
    """
    def __init__(self, message: str = "Erro durante a operacao de gerenciamento de chaves.", operation: str = "unknown", **kwargs):
        """
        Inicializa a exceção de gerenciamento de chaves.

        Args:
            message (str): Mensagem descritiva do erro.
            operation (str, optional): A operacao especifica de gerenciamento de chaves que falhou.
                                       Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.operation = operation
        # Garante que o detalhe da operacao esteja sempre presente
        self.details["operation"] = operation if "operation" not in self.details else self.details["operation"]

class ConfigurationError(SecuritySystemBaseError):
    """
    Levantada quando configuracoes necessarias estao faltando, sao invalidas,
    ou mal formatadas, impedindo a correta operacao de um componente.
    """
    def __init__(self, message: str = "Configuracao invalida ou ausente.", config_item: str = "unknown", **kwargs):
        """
        Inicializa a excecao de erro de configuracao.

        Args:
            message (str): Mensagem descritiva do erro.
            config_item (str, optional): O item de configuracao especifico que causou o problema.
                                         Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.config_item = config_item
        # Garante que o item de configuracao esteja sempre presente
        self.details["config_item"] = config_item if "config_item" not in self.details else self.details["config_item"]

class AuditLogError(SecuritySystemBaseError):
    """
    Levantada quando ocorre um problema com o sistema de log de auditoria,
    como falha ao escrever logs, inicializar o logger ou acessar o arquivo de auditoria.
    """
    def __init__(self, message: str = "Erro durante a operacao de log de auditoria.", log_event: str = "unknown", **kwargs):
        """
        Inicializa a excecao de erro de log de auditoria.

        Args:
            message (str): Mensagem descritiva do erro.
            log_event (str, optional): O tipo de evento de log que falhou.
                                       Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.log_event = log_event
        # Garante que o evento de log esteja sempre presente
        self.details["log_event"] = log_event if "log_event" not in self.details else self.details["log_event"]

class VaultAccessError(SecuritySystemBaseError):
    """
    Levantada quando ha um problema ao acessar, modificar ou se comunicar com o
    Vault de seguranca (e.g., credenciais invalidas, caminho do Vault inacessivel, erro de criptografia).
    """
    def __init__(self, message: str = "Erro ao acessar o vault de seguranca.", vault_path: str = "unknown", **kwargs):
        """
        Inicializa a excecao de erro de acesso ao Vault.

        Args:
            message (str): Mensagem descritiva do erro.
            vault_path (str, optional): O caminho do Vault que estava sendo acessado.
                                        Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.vault_path = vault_path
        # Garante que o caminho do Vault esteja sempre presente
        self.details["vault_path"] = vault_path if "vault_path" not in self.details else self.details["vault_path"]

class SecurityViolation(SecuritySystemBaseError):
    """
    Levantada quando uma violacao de politica de seguranca, tentativa de acesso nao autorizado,
    ou qualquer outra atividade suspeita que comprometa a seguranca e detectada.
    """
    def __init__(self, message: str = "Violacao de seguranca detectada.", violation_type: str = "unknown", **kwargs):
        """
        Inicializa a excecao de violacao de seguranca.

        Args:
            message (str): Mensagem descritiva da violacao.
            violation_type (str, optional): O tipo especifico de violacao detectada.
                                            Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.violation_type = violation_type
        # Garante que o tipo de violacao esteja sempre presente
        self.details["violation_type"] = violation_type if "violation_type" not in self.details else self.details["violation_type"]

class ValidationError(SecuritySystemBaseError):
    """
    Levantada quando uma validacao de dados falha (e.g., dados fora do esquema esperado,
    inconsistencias de integridade, dados sensiveis nao mascarados).
    Pode ser usada para falhas de validacao de negocios com impacto de seguranca.
    """
    def __init__(self, message: str = "Erro de validacao de dados.", field: str = "unknown", **kwargs):
        """
        Inicializa a excecao de erro de validacao.

        Args:
            message (str): Mensagem descritiva do erro.
            field (str, optional): O campo ou item de dados especifico que falhou na validacao.
                                   Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.field = field
        # Garante que o campo esteja sempre presente
        self.details["field"] = field if "field" not in self.details else self.details["field"]

class SecureConnectionError(SecuritySystemBaseError):
    """
    Levantada quando ocorre um erro nas operacoes de conexao segura a servicos externos
    (e.g., falha de handshake SSL, autenticacao TLS, problemas de certificado).
    """
    def __init__(self, message: str = "Erro em operacao de conexao segura.", conn_id: str = "unknown", **kwargs):
        """
        Inicializa a excecao de erro de conexao segura.

        Args:
            message (str): Mensagem descritiva do erro.
            conn_id (str, optional): O identificador da conexao que falhou.
                                     Padrao e "unknown".
            **kwargs: Argumentos adicionais a serem passados para a classe base `SecuritySystemBaseError`.
        """
        super().__init__(message, **kwargs)
        self.conn_id = conn_id
        # Garante que o ID da conexao esteja sempre presente
        self.details["conn_id"] = conn_id if "conn_id" not in self.details else self.details["conn_id"]