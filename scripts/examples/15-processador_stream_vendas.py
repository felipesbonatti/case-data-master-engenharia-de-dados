#!/usr/bin/env python3

import csv
import os
import sys
import time
import traceback
from datetime import datetime
from threading import Thread
from typing import Any, Dict, List, Optional
from pathlib import Path
import logging # Importar logging para uso consistente
import json # Necessario para lidar com credenciais JSON do Vault
import boto3 # Cliente Minio/S3
from botocore.exceptions import ClientError # Para erros especificos do boto3 S3

# ---
# META-INFORMACOES E ARQUITETURA
# ---
"""
====================================================================================
PROCESSADOR DE STREAM DE VENDAS: TEMPO REAL COM SEGURANCA E AUDITORIA 
====================================================================================

DESCRICAO:
    Este script Python implementa um processador de stream de eventos de vendas,
    demonstrando a ingestao, transformacao e persistencia de dados em tempo real
    em um ambiente enterprise. Ele integra-se nativamente com o sistema de seguranca
    desenvolvido (Vault e Auditoria) e utiliza o MinIO/S3 para armazenamento de
    eventos processados, simulando um fluxo de dados de alta disponibilidade e conformidade.

ARQUITETURA DO FLUXO DE STREAMING:
    Simulador de Stream de Vendas (fila_eventos) --> Processador de Stream Seguro
    (Seguranca Vault, Regras de Negocio, Auditoria) --> Data Lake (MinIO/S3)
    (Dados Processados, Particionamento)

DESIGN PATTERNS E ABORDAGENS:
    - Facade Pattern: A classe `SecureStreamProcessor` unifica operacoes complexas.
    - Defense in Depth: Multiplas camadas de seguranca (Vault, Auditoria, validacao).
    - Compliance-Driven: "LGPD Ready" e "SOX Ready" com rastreabilidade completa.
    - Processamento Assincrono: Simula a leitura de fila em tempo real.

COMPONENTES TECNICOS:
    - Python `threading`: Para simular processamento continuo em segundo plano.
    - `boto3`: AWS SDK para integracao robusta com MinIO/S3.
    - `plugins.security_system.vault_manager_helper.VaultManager`: Gerenciador de segredos criptografados.
    - `plugins.security_system.audit.AuditLogger`: Sistema de auditoria de eventos de seguranca e dados.
    - `plugins.security_system.exceptions`: Excecoes customizadas para tratamento de erros granular.
    - `simulador_stream_vendas`: Modulo externo que simula a fonte de eventos.

CARACTERISTICAS TECNICAS AVANCADAS:
    - Processamento Continuo: Loop de leitura de fila com timeout para evitar bloqueios.
    - Persistencia Local Temporaria: Eventos sao primeiro escritos em CSV local antes do upload.
    - Particionamento de Dados: Arquivos sao organizados no MinIO/S3 por data (AAAA-MM-DD).
    - Nomenclatura Unica de Arquivos: Garante atomicidade e evita sobrescrita de dados.
    - Upload Incremental: Arquivo local e re-uploadado a cada evento (demonstrativo; em producao, seriam microsservicos/batches).
    - Tratamento de Erros por Evento: Falhas em um evento nao interrompem o processamento de outros.
    - Auditoria Detalhada: Cada etapa critica e logada para conformidade e rastreabilidade.

INSTRUCOES DE EXECUCAO:
    1.  Configurar Vault: Execute `scripts/setup_vault_secrets.py` para popular o Vault com credenciais MinIO.
        Certifique-se de que `SECURITY_VAULT_SECRET_KEY` esteja definida no ambiente.
    2.  Iniciar Simulador: Em um terminal SEPARADO, execute `python3 simulador_stream_vendas.py`.
        Isso iniciara a geracao de eventos na fila.
    3.  Iniciar Processador: Execute este script.
        Ex: `python3 [caminho_para_este_script]/processador_stream_vendas.py`
        (Assegure-se de que `PLUGINS_PATH` e os caminhos de log/data estao corretos ou via `configure.py`).
"""

# Configuração do logger para este script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
logger = logging.getLogger(__name__)

# ---
# CONFIGURACOES E PATHS DINAMICOS
# ---
class StreamProcessorConfig:
    """Centraliza as configuracoes para o processador de stream."""

    # Caminho base do AIRFLOW_HOME, usado para resolver caminhos de plugins e logs.
    AIRFLOW_HOME: Path = Path(os.getenv('AIRFLOW_HOME', '/opt/airflow'))
    
    # Caminhos para componentes do sistema de seguranca customizado
    PLUGINS_BASE_PATH: Path = AIRFLOW_HOME / 'plugins'
    AUDIT_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'stream_audit.csv'
    SYSTEM_LOG_PATH: Path = AIRFLOW_HOME / 'logs' / 'security_audit' / 'stream_system.log'
    VAULT_JSON_PATH: Path = AIRFLOW_HOME / 'plugins' / 'security_system' / 'vault.json' # Caminho correto para vault.json

    # Variavel de ambiente para a chave mestra do Vault (CRITICA!)
    SECRET_KEY: Optional[str] = os.getenv('SECURITY_VAULT_SECRET_KEY')

    # Configuracoes do MinIO/S3
    MINIO_CREDS_KEY: str = "minio_local_credentials" # Chave no Vault para credenciais MinIO
    TARGET_BUCKET_NAME: str = "vendas-stream-processado" # Bucket de destino no MinIO/S3

    # Configuracoes de armazenamento local para persistencia temporaria
    LOCAL_STREAM_OUTPUT_DIR: Path = AIRFLOW_HOME / 'data' / 'stream_processado'

    # Outras configuracoes
    QUEUE_TIMEOUT_SECONDS: int = 5 # Timeout para pegar eventos da fila (evita bloqueio infinito)


# ---
# SISTEMA DE IMPORTACAO ROBUSTA COM FALLBACK PARA PLUGINS
# ---
# Adiciona o caminho base dos plugins ao sys.path para importacao.
# Isso e vital se o script for executado diretamente e nao pelo Airflow.
if str(StreamProcessorConfig.PLUGINS_BASE_PATH) not in sys.path:
    sys.path.insert(0, str(StreamProcessorConfig.PLUGINS_BASE_PATH))

try:
    # Importa componentes do sistema de seguranca desenvolvido
    from security_system.audit import AuditLogger
    from security_system.vault_manager_helper import VaultManager # Mudar para VaultManager
    from security_system.exceptions import ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError
except ImportError as e:
    logger.critical(f"ERRO DE IMPORTACAO: Modulos de seguranca customizados nao encontrados. Detalhes: {e}", exc_info=True)
    logger.critical("Dica: Verifique se o caminho para os plugins esta correto e se as dependencias foram instaladas.")
    logger.critical(f"PLUGINS_PATH configurado: {StreamProcessorConfig.PLUGINS_BASE_PATH}")
    sys.exit(1) # Saida critica se os modulos de seguranca nao puderem ser carregados

# Importacao do simulador de stream (dependencia externa)
try:
    from simulador_stream_vendas import fila_eventos
except ImportError:
    logger.critical("ERRO: simulador_stream_vendas.py nao encontrado ou inacessivel.", exc_info=True)
    logger.critical("Execute primeiro em um terminal separado: python3 simulador_stream_vendas.py")
    sys.exit(1) # Saida critica se o simulador nao for encontrado

# ---
# CLASSE PRINCIPAL: PROCESSADOR DE STREAM SEGURO
# ---
class SecureStreamProcessor:
    """
    Processador de stream de eventos de vendas, seguro e com auditoria completa.
    Ele gerencia a ingestao, validacao, transformacao e persistencia de eventos
    para o Data Lake (MinIO/S3).
    """
    
    def __init__(self):
        """
        Inicializa o processador com todos os componentes de seguranca e storage.
        
        PROCESSO DE INICIALIZACAO:
        1. Inicializacao de componentes de seguranca (Vault, Auditoria).
        2. Inicializacao do cliente de armazenamento (MinIO/S3) com credenciais seguras.
        3. Configuracao da estrutura de armazenamento local para persistencia temporaria.
        4. Criacao do arquivo CSV local com cabecalhos.
        """
        logger.info("Inicializando o Processador de Stream Seguro...")
        
        # 1. Inicializacao de componentes de seguranca
        self._init_security_components()
        
        # 2. Inicializacao do cliente de armazenamento
        self._init_storage_components()
        
        # 3. Configuracao da estrutura de armazenamento local e arquivo CSV
        self._setup_local_storage()
        
        logger.info("Processador inicializado com sucesso!")
        self.audit.log("Processador de Stream inicializado com sucesso.", action="STREAM_PROCESSOR_INIT_SUCCESS")

    def _init_security_components(self) -> None:
        """
        Inicializa componentes de seguranca e auditoria (`AuditLogger`, `VaultManager`).
        A auditoria e inicializada primeiro para capturar todos os eventos subsequentes,
        incluindo falhas de inicializacao do Vault.

        Raises:
            ValueError: Se a SECRET_KEY do Vault nao estiver definida.
            ConfigurationError: Para problemas de configuracao do Vault ou AuditLogger.
            SecuritySystemBaseError: Para erros inesperados do sistema de seguranca.
        """
        logger.info("-> Inicializando componentes de seguranca...")
        if not StreamProcessorConfig.SECRET_KEY:
            error_msg = "ERRO CRITICO: A variavel de ambiente 'SECURITY_VAULT_SECRET_KEY' nao esta definida."
            logger.critical(error_msg)
            raise ValueError(error_msg)
            
        try:
            # Inicializacao do AuditLogger (primeiro componente critico)
            # Garante que os diretorios para logs de auditoria existam
            StreamProcessorConfig.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            StreamProcessorConfig.SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.audit = AuditLogger(
                audit_file_path=str(StreamProcessorConfig.AUDIT_LOG_PATH),
                system_log_file_path=str(StreamProcessorConfig.SYSTEM_LOG_PATH)
            )
            self.audit.log("AuditLogger inicializado para o Processador de Stream.", action="AUDIT_LOGGER_INIT")
            logger.info("-> AuditLogger inicializado.")

            # Inicializacao do gerenciador de segredos criptografados (VaultManager)
            # Garante que o diretorio do vault.json exista
            StreamProcessorConfig.VAULT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.vault_manager = VaultManager( # Mudar para self.vault_manager
                vault_path=str(StreamProcessorConfig.VAULT_JSON_PATH),
                secret_key=StreamProcessorConfig.SECRET_KEY,
                logger=self.audit # Passa o AuditLogger para o VaultManager
            )
            self.audit.log("VaultManager inicializado para o Processador de Stream.", action="VAULT_MANAGER_INIT")
            logger.info("-> VaultManager inicializado.")

            self.audit.log("Componentes de seguranca inicializados com sucesso.", action="SECURITY_COMPONENTS_INIT_SUCCESS")
            logger.info("-> Componentes de seguranca configurados.")

        except (ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError) as e:
            error_msg = f"Falha ao inicializar componentes de seguranca: {e}"
            logger.critical(error_msg, exc_info=True)
            self.audit.critical(error_msg, action="SECURITY_INIT_FAIL", error_message=str(e), stack_trace_needed=True)
            raise ConfigurationError(error_msg) # Re-lanca como um erro de configuracao
        except Exception as e:
            error_msg = f"Erro inesperado na inicializacao dos componentes de seguranca: {e}"
            logger.critical(error_msg, exc_info=True)
            self.audit.critical(error_msg, action="SECURITY_INIT_UNEXPECTED_FAIL", error_message=str(e), stack_trace_needed=True)
            raise SecuritySystemBaseError(error_msg)


    def _init_storage_components(self) -> None:
        """
        Inicializa o cliente MinIO/S3 e define as configuracoes de armazenamento.
        Isso inclui a obtencao segura do cliente S3 e a definicao do bucket de destino.

        Raises:
            ConfigurationError: Se as credenciais MinIO forem incompletas ou invalidas.
            SecureConnectionError: Para falhas de conexao com o MinIO.
        """
        logger.info("-> Inicializando componentes de armazenamento (MinIO/S3)...")
        self.s3_client = self._get_secure_minio_client()
        self.bucket_name = StreamProcessorConfig.TARGET_BUCKET_NAME # Bucket dedicado para stream de vendas

        # Verifica ou cria o bucket no MinIO
        try:
            if not self.s3_client.bucket_exists(self.bucket_name):
                logger.info(f"-> Bucket '{self.bucket_name}' nao existe. Criando...")
                self.s3_client.create_bucket(self.bucket_name) # Usar create_bucket para boto3
                logger.info(f"-> Bucket '{self.bucket_name}' criado com sucesso.")
                self.audit.log(f"Bucket '{self.bucket_name}' criado no MinIO.", action="MINIO_BUCKET_CREATED")
            else:
                logger.info(f"-> Bucket '{self.bucket_name}' ja existe.")
                self.audit.log(f"Bucket '{self.bucket_name}' verificado. Ja existe.", action="MINIO_BUCKET_CHECK_EXISTING")
        except Exception as e:
            error_msg = f"Falha ao verificar/criar o bucket MinIO '{self.bucket_name}': {e}"
            logger.critical(error_msg, exc_info=True)
            self.audit.critical(error_msg, action="MINIO_BUCKET_CREATE_FAIL", error_message=str(e), stack_trace_needed=True)
            raise SecureConnectionError(error_msg) # Erro de conexao/storage


        self.audit.log("Componentes de armazenamento inicializados.", action="STORAGE_INIT")
        logger.info("-> Componentes de armazenamento configurados.")

    def _get_secure_minio_client(self) -> boto3.client:
        """
        Obtem e retorna um cliente Boto3 S3 para MinIO, usando credenciais seguras do Vault.
        Inclui validacao de integridade das credenciais e auditoria da operacao.

        Returns:
            boto3.client: Uma instancia do cliente Boto3 S3 configurada para MinIO.

        Raises:
            ConfigurationError: Se as credenciais MinIO forem incompletas ou invalidas no Vault.
            SecureConnectionError: Para falhas ao criar ou testar a conexao com o MinIO.
        """
        self.audit.log("Recuperando credenciais MinIO do vault.", action="GET_MINIO_CREDS_FROM_VAULT")
        
        # Usar self.vault_manager para obter segredo
        minio_creds_encrypted = self.vault_manager.get_secret(StreamProcessorConfig.MINIO_CREDS_KEY)
        
        if not minio_creds_encrypted:
            error_msg = f"Credenciais '{StreamProcessorConfig.MINIO_CREDS_KEY}' nao encontradas no Vault."
            self.audit.critical(error_msg, action="MINIO_CREDS_MISSING", error_message=error_msg)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)

        try:
            minio_creds = json.loads(minio_creds_encrypted) # Desserializar JSON
        except json.JSONDecodeError as e:
            error_msg = f"Formato de credenciais MinIO no Vault invalido (JSON invalido): {e}."
            self.audit.critical(error_msg, action="MINIO_CREDS_JSON_ERROR", error_message=str(e), stack_trace_needed=True)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)

        required_keys = ["endpoint_url", "access_key", "secret_key"]
        missing_keys = [key for key in required_keys if not minio_creds.get(key)]
        if missing_keys:
            error_msg = f"Credenciais MinIO incompletas no Vault (faltando: {', '.join(missing_keys)})."
            self.audit.critical(error_msg, action="MINIO_CREDS_INCOMPLETE", error_message=error_msg)
            logger.critical(error_msg)
            raise ConfigurationError(error_msg)

        try:
            s3_client = boto3.client(
                "s3",
                endpoint_url=minio_creds["endpoint_url"],
                aws_access_key_id=minio_creds["access_key"],
                aws_secret_access_key=minio_creds["secret_key"],
                verify=False # PARA TESTE/DEV. Em producao, use True e valide certificados SSL!
            )
            # Teste de conexao basico: listar buckets para verificar autenticacao
            s3_client.list_buckets()
            self.audit.log("Cliente MinIO criado e testado com sucesso.", action="MINIO_CLIENT_CREATED")
            logger.info("-> Cliente MinIO/S3 obtido e conectado com sucesso.")
            return s3_client
        except Exception as e:
            error_msg = f"Falha ao criar ou testar cliente Minio/S3: {e}"
            self.audit.critical(error_msg, action="MINIO_CLIENT_CREATION_FAIL", error_message=str(e), stack_trace_needed=True)
            logger.critical(error_msg, exc_info=True)
            raise SecureConnectionError(error_msg)


    def _setup_local_storage(self) -> None:
        """
        Configura a estrutura de armazenamento local para persistencia temporaria de eventos.
        Cria o diretorio de saida diario e inicializa o arquivo CSV local com cabecalhos.
        """
        # Particionamento automatico por data para organizacao e performance
        today_dir = datetime.now().strftime("%Y-%m-%d")
        self.local_output_path: Path = StreamProcessorConfig.LOCAL_STREAM_OUTPUT_DIR / today_dir
        
        # Garante que o diretorio local exista
        try:
            self.local_output_path.mkdir(parents=True, exist_ok=True)
            self.audit.log(f"Diretorio local para stream processado criado: {self.local_output_path}", action="LOCAL_STORAGE_DIR_CREATED")
            logger.info(f"-> Diretorio local para stream: {self.local_output_path}")
        except OSError as e:
            error_msg = f"Falha ao criar diretorio de armazenamento local '{self.local_output_path}': {e}"
            self.audit.critical(error_msg, action="LOCAL_STORAGE_DIR_FAIL", error_message=str(e), stack_trace_needed=True)
            logger.critical(error_msg, exc_info=True)
            raise SecureConnectionError(error_msg)

        # Nomenclatura unica de arquivos para evitar conflitos em caso de reprocessamento ou multiplos processadores
        self.local_file_name: str = f"vendas_stream_{int(time.time())}.csv"
        self.local_file_path: Path = self.local_output_path / self.local_file_name
        
        # Caminho remoto no MinIO (para upload)
        self.minio_remote_path: str = f"{today_dir}/{self.local_file_name}"

        # Criacao do arquivo CSV local com cabecalhos estruturados
        try:
            with open(self.local_file_path, "w", newline="", encoding='utf-8') as f:
                fieldnames = ["customer_state", "price", "timestamp", "processed_at"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
            self.audit.log(f"Arquivo CSV local inicializado: {self.local_file_path}", action="LOCAL_CSV_INIT")
            logger.info(f"-> Arquivo CSV local inicializado: {self.local_file_path}")
        except IOError as e:
            error_msg = f"Falha ao inicializar o arquivo CSV local '{self.local_file_path}': {e}"
            self.audit.critical(error_msg, action="LOCAL_CSV_INIT_FAIL", error_message=str(e), stack_trace_needed=True)
            logger.critical(error_msg, exc_info=True)
            raise SecureConnectionError(error_msg)

        self.audit.log("Estrutura de armazenamento local configurada.", action="LOCAL_STORAGE_SETUP")
        logger.info("-> Armazenamento local configurado.")

    def processar_evento(self, evento: Dict[str, Any]) -> None:
        """
        Processa um evento individual do stream de vendas, aplicando regras de negocio,
        enriquecendo os dados e persistindo-os localmente e no MinIO/S3.

        Args:
            evento (Dict[str, Any]): O dicionario representando o evento de venda recebido.
        """
        try:
            # ===============================================================================
            # VALIDACAO E TRANSFORMACAO DOS DADOS DO EVENTO
            # ===============================================================================
            # Conversao segura do valor 'price' com tratamento de erro
            try:
                price = float(evento.get("price", 0))
            except (ValueError, TypeError):
                self.audit.warning(f"Evento com 'price' invalido: {evento.get('price')}. Pulando processamento.", action="STREAM_EVENT_INVALID_PRICE", details=str(evento))
                logger.warning(f"Evento invalido (preco): {evento.get('price')}. Pulando.")
                return # Pula o evento se o preco for invalido

            # Aplicacao da regra de negocio: filtrar vendas > R$ 100
            if price > 100:
                # Estruturacao do evento processado com enriquecimento
                processed_at_timestamp = datetime.now().isoformat()
                evento_processado = {
                    "customer_state": evento.get("customer_state", "UNKNOWN"),
                    "price": price,
                    "timestamp": evento.get("timestamp", datetime.now().isoformat()), # Mantem o timestamp original, fallback para now
                    "processed_at": processed_at_timestamp # Timestamp de auditoria/processamento
                }

                # ===============================================================================
                # PERSISTENCIA LOCAL 
                # ===============================================================================
                # Append atomico no arquivo CSV local
                with open(self.local_file_path, "a", newline="", encoding='utf-8') as f:
                    fieldnames = ["customer_state", "price", "timestamp", "processed_at"]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writerow(evento_processado)

                logger.info(f"Evento processado e salvo localmente: {evento_processado['customer_state']} - R$ {price:.2f}")
                
                # ===============================================================================
                # AUDITORIA DE PROCESSAMENTO PARA COMPLIANCE E GOVERNANCA
                # ===============================================================================
                self.audit.log(
                    "Evento de venda processado",
                    action="STREAM_EVENT_PROCESSED",
                    details=f"State: {evento_processado['customer_state']}, Value: R$ {price:.2f}, ProcessedAt: {processed_at_timestamp}",
                    compliance_status="LGPD_PROCESSED", # Indica que dados foram processados conforme regras
                    resource=f"venda_id:{evento.get('order_id', 'N/A')}" # Se houver um order_id no evento
                )
                
                # ===============================================================================
                # UPLOAD AUTOMATICO PARA STORAGE DISTRIBUIDO (MINIO/S3)
                # ===============================================================================
                # Este upload ocorre a cada evento. Em um cenario real, isso seria batched
                # ou via um servico de streaming como Kafka Connect.
                self._upload_to_minio()
            else:
                self.audit.log(f"Evento de venda ignorado (preco <= R$ 100): R$ {price:.2f}",
                               level="INFO", action="STREAM_EVENT_SKIPPED_RULE", details=f"Price: {price}")
                logger.info(f"Evento ignorado (preco <= R$100): R$ {price:.2f}")

        except Exception as e:
            # ===============================================================================
            # TRATAMENTO DE ERRO ISOLADO POR EVENTO
            # ===============================================================================
            logger.error(f"Erro ao processar evento: {e}")
            self.audit.error(f"Erro no processamento do stream de vendas: {e}",
                               level="ERROR",
                               action="STREAM_PROCESS_ERROR",
                               error_message=str(e),
                               stack_trace_needed=True, # Solicita stack trace para este erro
                               details=str(evento)) # Inclui o evento causador no log de erro


    def _upload_to_minio(self) -> None:
        """
        Realiza o upload seguro do arquivo CSV local para o MinIO/S3.
        Este metodo implementa uma estrategia de sobrescrita e audita a operacao.
        """
        try:
            # ===============================================================================
            # UPLOAD SEGURO PARA MINIO COM AUDITORIA
            # ===============================================================================
            self.s3_client.upload_file(
                str(self.local_file_path), # Caminho local do arquivo CSV
                self.bucket_name,          # Bucket de destino no MinIO/S3
                self.minio_remote_path     # Caminho remoto (chave de objeto)
            )
            
            logger.info(f"Enviado para MinIO: s3://{self.bucket_name}/{self.minio_remote_path}")
            
            # Auditoria de upload bem-sucedido
            self.audit.log(
                "Upload MinIO realizado com sucesso",
                action="MINIO_UPLOAD_SUCCESS",
                details=f"Bucket: {self.bucket_name}, Path: {self.minio_remote_path}, Local: {self.local_file_path.name}"
            )
            
        except Exception as e:
            # ===============================================================================
            # TRATAMENTO DE FALHA DE UPLOAD (NAO BLOQUEANTE PARA O PROCESSADOR)
            # ===============================================================================
            # Uma falha de upload nao deve interromper o processamento do stream.
            # Os eventos continuarao a ser armazenados localmente.
            logger.warning(f"Falha no upload MinIO: {e}")
            
            # Auditoria de falha para investigacao posterior
            self.audit.error(f"Falha no upload Minio: {e}",
                               level="ERROR",
                               action="MINIO_UPLOAD_FAIL",
                               error_message=str(e),
                               details=f"Bucket: {self.bucket_name}, Path: {self.minio_remote_path}")


    def start(self) -> None:
        """
        Inicia o loop principal de processamento de stream.
        Este loop continuamente pega eventos da fila do simulador e os processa.
        """
        logger.info("\nProcessador de Stream iniciado. Aguardando eventos... (Pressione Ctrl+C para parar)")
        
        eventos_processados = 0
        
        try:
            # ===============================================================================
            # LOOP PRINCIPAL DE CONSUMO DE STREAM
            # ===============================================================================
            while True:
                try:
                    # Recupera evento da fila com timeout (evita bloqueio infinito)
                    evento = fila_eventos.get(timeout=StreamProcessorConfig.QUEUE_TIMEOUT_SECONDS)
                    
                    # Processamento do evento individual
                    self.processar_evento(evento)
                    eventos_processados += 1
                    
                except Exception as e: # Captura excecoes do fila_eventos.get(), incluindo Timeout
                    if isinstance(e, type(KeyboardInterrupt)): # Se for KeyboardInterrupt, re-lanca para o bloco outer try
                        raise
                    
                    logger.warning(f"Timeout ou erro ao pegar evento da fila: {e}. Encerrando loop de consumo.")
                    self.audit.warning(f"Timeout ou erro ao pegar evento da fila: {e}. Encerrando.", action="STREAM_QUEUE_ERROR", error_message=str(e))
                    break # Sai do loop se a fila estiver vazia por timeout ou outros erros
                    
        except KeyboardInterrupt:
            # Graceful shutdown solicitado pelo usuario (Ctrl+C)
            logger.info("\nInterrupcao solicitada pelo usuario (Ctrl+C). Encerrando processador.")
            self.audit.log("Processador de Stream interrompido pelo usuario.", action="STREAM_PROCESSOR_INTERRUPTED")
            
        finally:
            # ===============================================================================
            # FINALIZACAO DO PROCESSADOR COM METRICAS E AUDITORIA
            # ===============================================================================
            logger.info(f"\nProcessamento finalizado: {eventos_processados} eventos processados.")
            
            self.audit.log(
                f"Processador de Stream encerrado - {eventos_processados} eventos processados",
                action="STREAM_PROCESSOR_STOPPED",
                details=f"Arquivo final local: {self.local_file_path}, Bucket: {self.bucket_name}, Path remoto: {self.minio_remote_path}",
                total_events_processed=eventos_processados
            )

# ===============================================================================
# PONTO DE ENTRADA PRINCIPAL COM TRATAMENTO ROBUSTO DE ERROS GERAIS
# ===============================================================================
if __name__ == "__main__":
    # Esta secao `if __name__ == "__main__"` garante que o codigo abaixo
    # so sera executado quando o script for chamado diretamente.
    try:
        # Inicializacao e execucao do processador de stream
        processor = SecureStreamProcessor()
        processor.start()
        
    except (ConfigurationError, SecureConnectionError, VaultAccessError, SecuritySystemBaseError) as e:
        # Erros de configuracao ou falhas criticas na inicializacao do sistema de seguranca/conexao
        logger.critical(f"ERRO CRITICO NA INICIALIZACAO: {e}")
        logger.critical("Por favor, verifique:")
        logger.critical(f"- Se a variavel de ambiente 'SECURITY_VAULT_SECRET_KEY' esta definida.")
        logger.critical(f"- Se o Vault existe em '{StreamProcessorConfig.VAULT_JSON_PATH}' e contem as credenciais '{StreamProcessorConfig.MINIO_CREDS_KEY}'.")
        logger.critical(f"- Se o MinIO esta acessivel em seu endpoint configurado nas credenciais.")
        traceback.print_exc() # Imprime o stack trace completo para depuracao
        sys.exit(1) # Sai com codigo de erro
        
    except ImportError as e:
        # Erro de importacao do simulador ou de outras dependencias principais
        logger.critical(f"ERRO DE DEPENDENCIA: {e}")
        logger.critical("Verifique se 'simulador_stream_vendas.py' esta no mesmo diretorio ou acessivel no PYTHONPATH.")
        traceback.print_exc()
        sys.exit(1) # Sai com codigo de erro
        
    except Exception as e:
        # Captura qualquer outro erro fatal nao previsto
        logger.critical(f"ERRO FATAL INESPERADO: O processador de stream encerrou abruptamente. Detalhes: {e}")
        traceback.print_exc() # Imprime o stack trace completo para depuracao
        sys.exit(1) # Sai com codigo de erro
        
    finally:
        # Bloco finally para garantir que mensagens de encerramento sejam exibidas
        logger.info("\nProcessador de Stream encerrado.")
