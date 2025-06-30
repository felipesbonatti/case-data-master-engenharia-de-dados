"""
====================================================================================
MÓDULO DE AUDITORIA E GOVERNANÇA DE DADOS 
====================================================================================

DESCRIÇÃO:
    Este módulo implementa um sistema de auditoria centralizado, essencial para
    a governança, segurança e compliance de dados em um ambiente de Engenharia de Dados.
    Ele registra eventos chave do pipeline, como operações de dados, acessos a sistemas
    seguros, resultados de validações e incidentes de segurança, em formatos estruturados
    e de fácil análise.

ARQUITETURA:
    - Registro Duplo: Eventos são registrados em um arquivo CSV de auditoria (para fácil
      análise tabular e conformidade) e em um arquivo de log textual (para debug e rastreabilidade).
    - Logging Nível de Sistema: Integração com o sistema de logging padrão do Python para
      gerenciamento de fluxo de logs.
    - Geração de Relatórios: Capacidade de gerar relatórios consolidados para autoridades
      ou equipes internas, filtrando informações sensíveis.

COMPONENTES E FUNCIONALIDADES:
    - AuditLogger Class: Classe principal para registrar eventos de auditoria.
    - Registro de Eventos Diversos: Suporte para logs gerais, operações específicas (upload, transferência, validação),
      e incidentes de segurança.
    - Metadados Ricos: Cada log pode incluir 'dag_id', 'task_id', 'user', 'action', 'compliance_status',
      'risk_level' e outros detalhes contextuais.
    - Compliance LGPD: Campos específicos e lógicas para indicar o status de conformidade
      com a LGPD em eventos de dados.
    - Geração de Relatórios: Ferramentas para extrair, filtrar e sumarizar dados de auditoria
      em relatórios para conformidade e análise de segurança.
    - Resiliência: Tratamento robusto de erros para garantir que o sistema de log continue
      operando mesmo sob condições adversas.

FORMATO DO LOG DE AUDITORIA (CSV):
    - timestamp: Data e hora do evento (ISO 8601).
    - level: Nível de severidade do log (INFO, WARNING, ERROR, CRITICAL).
    - dag_id: ID da DAG envolvida, se aplicável.
    - task_id: ID da tarefa da DAG envolvida, se aplicável.
    - user: Usuário ou processo que acionou o evento.
    - action: Ação específica registrada (ex: FILE_UPLOAD, VAULT_ACCESS, VALIDATION_FAILURE).
    - details: Mensagem detalhada do evento, pode conter JSON para metadados complexos.
    - compliance_status: Status de conformidade (ex: LGPD_OK, LGPD_VIOLATION, LGPD_NA).
    - risk_level: Nível de risco associado ao evento (ex: LOW, MEDIUM, HIGH, CRITICAL).
    - service: Serviço ou componente que gerou o log (ex: MINIO, POSTGRES, VAULT).
    - error_message: Mensagem de erro específica, se for um evento de erro.
    - stack_trace_needed: Booleano indicando se um stack trace é relevante para o erro.
====================================================================================
"""

import logging
import csv
import os
from datetime import datetime, timedelta
import pandas as pd
import json

class AuditLogger:
    """
    Classe para registrar eventos de auditoria em um sistema de Engenharia de Dados.
    Registra logs em um arquivo CSV estruturado e em um arquivo de log textual.
    """

    def __init__(self, audit_file_path: str, system_log_file_path: str):
        """
        Inicializa o AuditLogger com os caminhos para os arquivos de log de auditoria e de sistema.

        Args:
            audit_file_path (str): Caminho completo para o arquivo CSV de auditoria.
            system_log_file_path (str): Caminho completo para o arquivo de log textual do sistema.

        Raises:
            ValueError: Se os caminhos de log não forem fornecidos.
        """
        self.audit_file_path = audit_file_path
        self.system_log_file_path = system_log_file_path

        if not self.audit_file_path or not self.system_log_file_path:
            error_msg = "CRÍTICO (AuditLogger): Caminhos de log para auditoria e sistema não foram fornecidos."
            # Usa o logger raiz para este erro, caso o logger interno não esteja totalmente configurado
            logging.critical(error_msg) 
            raise ValueError(error_msg)

        # Garante que os diretórios dos arquivos de log existam antes de qualquer operação
        self._ensure_log_paths_exist()

        # Configura o logger interno do Python para logs de sistema
        self.logger = logging.getLogger('security_system.AuditLogger_Enterprise')
        self.logger.propagate = False # Impede que logs sejam propagados para handlers da raiz
        self.logger.setLevel(logging.INFO)

        # Remove handlers existentes para evitar duplicação em re-inicializações do Airflow
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        # Adiciona handlers de arquivo
        self._setup_file_handlers()
        
        # Inicializa o arquivo CSV de auditoria com o cabeçalho, se necessário
        self._init_audit_csv_file()
        self.logger.info("AuditLogger inicializado com sucesso.")

    def _ensure_log_paths_exist(self) -> None:
        """
        Garante que os diretórios pai para os arquivos de log existam.
        Cria os diretórios recursivamente se não existirem.
        """
        for file_path_str in [self.audit_file_path, self.system_log_file_path]:
            if file_path_str:
                directory = os.path.dirname(file_path_str)
                if directory and not os.path.exists(directory):
                    try:
                        os.makedirs(directory, exist_ok=True)
                        self.logger.info(f"Diretório '{directory}' criado para logs de auditoria.")
                    except OSError as e:
                        self.logger.error(f"FALHA ao criar diretório para logs de auditoria '{directory}': {e}")

    def _setup_file_handlers(self) -> None:
        """
        Configura os handlers de arquivo para o logger interno do sistema.
        Um handler para o arquivo de log do sistema é adicionado.
        """
        try:
            handler = logging.FileHandler(self.system_log_file_path, mode='a', encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s|%(levelname)s|%(name)s|%(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.info(f"Handler de arquivo de sistema configurado para: {self.system_log_file_path}")
        except Exception as e:
            self.logger.error(f"Falha ao configurar handler de arquivo de sistema: {e}")

    def _init_audit_csv_file(self) -> None:
        """
        Inicializa o arquivo CSV de auditoria, escrevendo o cabeçalho
        se o arquivo não existir ou estiver vazio.
        """
        # Verifica se o arquivo não existe ou se está vazio (tamanho 0)
        write_header = not os.path.exists(self.audit_file_path) or os.path.getsize(self.audit_file_path) == 0
        
        if write_header:
            try:
                with open(self.audit_file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Define explicitamente o cabeçalho para garantir consistência
                    writer.writerow([
                        'timestamp', 'level', 'dag_id', 'task_id', 'user', 'action',
                        'details', 'compliance_status', 'risk_level', 'service',
                        'error_message', 'stack_trace_needed'
                    ])
                self.logger.info(f"Arquivo CSV de auditoria inicializado com cabeçalho em: {self.audit_file_path}")
            except Exception as e:
                self.logger.critical(f"FALHA CRÍTICA: Não foi possível inicializar o arquivo CSV de auditoria em '{self.audit_file_path}': {e}", exc_info=True)
                raise # Re-lança para garantir que o problema seja notado

    def log(self, message: str, level: str = "INFO", **kwargs) -> None:
        """
        Registra um evento de auditoria no arquivo CSV e no log do sistema.

        Args:
            message (str): A mensagem detalhada do evento.
            level (str): O nível de severidade do log (INFO, WARNING, ERROR, CRITICAL).
            kwargs: Argumentos adicionais para enriquecer o log:
                - dag_id (str): ID da DAG.
                - task_id (str): ID da tarefa.
                - user (str): Usuário ou processo que acionou o evento.
                - action (str): Ação específica realizada (ex: FILE_UPLOAD, VAULT_ACCESS).
                - compliance_status (str): Status de conformidade (ex: 'LGPD_OK', 'LGPD_VIOLATION').
                - risk_level (str): Nível de risco (ex: 'LOW', 'MEDIUM', 'HIGH').
                - service (str): Serviço ou componente (ex: 'MINIO', 'POSTGRES', 'VAULT').
                - error_message (str): Mensagem de erro específica, se for um evento de erro.
                - stack_trace_needed (bool): Indica se um stack trace é relevante.
        """
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'level': level.upper(),
            'dag_id': kwargs.get('dag_id', 'system'),
            'task_id': kwargs.get('task_id', 'system'),
            'user': kwargs.get('user', 'airflow_process'),
            'action': kwargs.get('action', 'GENERIC_EVENT'),
            'details': message,
            'compliance_status': kwargs.get('compliance_status', 'LGPD_NA'),
            'risk_level': kwargs.get('risk_level', level.upper()), # Padrão para o nível do log
            'service': kwargs.get('service', 'N/A'),
            'error_message': kwargs.get('error_message', ''),
            'stack_trace_needed': kwargs.get('stack_trace_needed', False)
        }

        try:
            with open(self.audit_file_path, 'a', newline='', encoding='utf-8') as f:
                # Usa DictWriter para garantir que os campos correspondam ao cabeçalho
                writer = csv.DictWriter(f, fieldnames=list(log_data.keys()))
                writer.writerow(log_data)
            
            # Log para o logger interno do sistema também
            log_message_system = (
                f"AUDIT_CSV_WRITE|LEVEL:{log_data['level']}|ACTION:{log_data['action']}|"
                f"DAG:{log_data['dag_id']}|TASK:{log_data['task_id']}|USER:{log_data['user']}|"
                f"DETAILS:{message}"
            )
            # Usa o método de log apropriado com base no nível
            getattr(self.logger, level.lower(), self.logger.info)(log_message_system)
        except Exception as e:
            # Esta é uma falha no próprio sistema de log, que é crítica.
            # Loga no logger interno e no console (stdout/stderr)
            critical_error_msg = f"FALHA CRÍTICA NO LOGGER DE AUDITORIA: Não foi possível escrever no CSV: {e}"
            self.logger.critical(critical_error_msg, exc_info=True) # exc_info=True para stack trace

    def info(self, message: str, action: str = "INFO_EVENT", compliance_status: str = "LGPD_OK", **kwargs) -> None:
        """
        Registra um evento informativo de auditoria.
        Args:
            message (str): Mensagem do log.
            action (str): Ação específica (padrão 'INFO_EVENT').
            compliance_status (str): Status de conformidade (padrão 'LGPD_OK').
            kwargs: Outros argumentos para o log.
        """
        self.log(message, level="INFO", action=action, compliance_status=compliance_status, **kwargs)

    def warning(self, message: str, action: str = "WARNING_EVENT", compliance_status: str = "LGPD_WARNING", risk_level: str = "MEDIUM", **kwargs) -> None:
        """
        Registra um evento de aviso de auditoria.
        Args:
            message (str): Mensagem do log.
            action (str): Ação específica (padrão 'WARNING_EVENT').
            compliance_status (str): Status de conformidade (padrão 'LGPD_WARNING').
            risk_level (str): Nível de risco (padrão 'MEDIUM').
            kwargs: Outros argumentos para o log.
        """
        self.log(message, level="WARNING", action=action, compliance_status=compliance_status, risk_level=risk_level, **kwargs)

    def error(self, message: str, action: str = "ERROR_EVENT", compliance_status: str = "LGPD_BREACH", risk_level: str = "HIGH", error_message: str = "", stack_trace_needed: bool = False, **kwargs) -> None:
        """
        Registra um evento de erro de auditoria.
        Args:
            message (str): Mensagem do log.
            action (str): Ação específica (padrão 'ERROR_EVENT').
            compliance_status (str): Status de conformidade (padrão 'LGPD_BREACH').
            risk_level (str): Nível de risco (padrão 'HIGH').
            error_message (str): Mensagem de erro detalhada.
            stack_trace_needed (bool): Indica se um stack trace é necessário.
            kwargs: Outros argumentos para o log.
        """
        self.log(message, level="ERROR", action=action, compliance_status=compliance_status, risk_level=risk_level, error_message=error_message, stack_trace_needed=stack_trace_needed, **kwargs)

    def generate_report(self, start_date: str, end_date: str) -> dict:
        """
        Gera um relatório sumário de eventos de auditoria para um período específico.

        Args:
            start_date (str): Data de início do período no formato ISO (YYYY-MM-DDTHH:MM:SS).
            end_date (str): Data de fim do período no formato ISO (YYYY-MM-DDTHH:MM:SS).

        Returns:
            dict: Um dicionário contendo o relatório sumário e, opcionalmente, detalhes de erro.
        """
        try:
            start_dt = datetime.fromisoformat(start_date)
            end_dt = datetime.fromisoformat(end_date)
            
            if not os.path.exists(self.audit_file_path):
                self.logger.warning(f"Arquivo de auditoria não encontrado em '{self.audit_file_path}'. Nenhum relatório pode ser gerado.")
                return {"error": "Arquivo de auditoria não encontrado.", "periodo": f"{start_date} a {end_date}"}
            
            df = pd.read_csv(self.audit_file_path, parse_dates=['timestamp'], infer_datetime_format=True)
            
            if df.empty:
                self.logger.info("Arquivo de auditoria vazio. Nenhum evento para relatar.")
                return {"message": "Arquivo de auditoria vazio", "periodo": f"{start_date} a {end_date}"}
            
            # Garante que o timestamp não tem timezone para comparação
            df['timestamp'] = pd.to_datetime(df['timestamp']).dt.tz_localize(None) 
            
            mask = (df['timestamp'] >= start_dt) & (df['timestamp'] <= end_dt)
            period_df = df.loc[mask].copy()
            
            if period_df.empty:
                self.logger.info(f"Nenhum evento encontrado no período {start_date} a {end_date}.")
                return {"message": "Nenhum evento encontrado para o período", "periodo": f"{start_date} a {end_date}"}
            
            total_events = len(period_df)
            compliance_ok_count = period_df[period_df['compliance_status'] == 'LGPD_OK'].shape[0]
            
            report = {
                'periodo': f"{start_date} a {end_date}",
                'total_eventos': total_events,
                'distribuicao_acoes': period_df['action'].value_counts().to_dict(),
                'taxa_conformidade_lgpd': round((compliance_ok_count / total_events * 100) if total_events > 0 else 0, 2),
                'eventos_risco_alto': period_df[period_df['risk_level'] == 'HIGH'].shape[0],
                'principais_violacoes': period_df[period_df['compliance_status'] != 'LGPD_OK']['details'].value_counts().head(5).to_dict(),
                'usuarios_ativos': period_df['user'].nunique(),
                'detalhes_eventos_criticos': period_df[period_df['level'].isin(['ERROR', 'CRITICAL'])].to_dict(orient='records')
            }
            
            self._generate_authority_report(period_df) # Gera um relatório separado para autoridades
            
            self.log(
                message=f"Relatório de auditoria gerado para o período {start_date} a {end_date}",
                action="AUDIT_REPORT_GENERATED", # Ação mais descritiva
                details=json.dumps({
                    'total_eventos': report['total_eventos'],
                    'taxa_conformidade': report['taxa_conformidade_lgpd']
                })
            )
            self.logger.info(f"Relatório de auditoria gerado com sucesso para o período: {start_date} a {end_date}")
            return report
            
        except Exception as e:
            self.logger.error(f"Falha ao gerar relatório de auditoria: {str(e)}", exc_info=True)
            self.log(
                message=f"Falha ao gerar relatório de auditoria para o período {start_date} a {end_date}. Erro: {str(e)}",
                action="AUDIT_REPORT_GENERATION_FAILED",
                level="ERROR",
                risk_level="HIGH",
                error_message=str(e),
                stack_trace_needed=True
            )
            return {"error": str(e)}

    def _generate_authority_report(self, df: pd.DataFrame) -> None:
        """
        Gera um relatório de auditoria simplificado para autoridades,
        removendo colunas que não são estritamente necessárias para conformidade
        e aplicando permissões de arquivo restritivas.

        Args:
            df (pd.DataFrame): DataFrame contendo os dados de auditoria do período.
        """
        # Colunas a serem removidas para o relatório de autoridades
        columns_to_drop = ['user', 'risk_level', 'error_message', 'stack_trace_needed', 'service']
        authority_df = df.drop(columns=[col for col in columns_to_drop if col in df.columns], errors='ignore').copy()
        
        report_dir = os.path.dirname(self.audit_file_path)
        if not report_dir: report_dir = "." # Caso o caminho seja apenas o nome do arquivo, usar o diretório atual
        
        report_path = os.path.join(report_dir, f"lgpd_authority_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        try:
            authority_df.to_csv(report_path, index=False, encoding='utf-8')
            # Define permissões de arquivo restritivas (apenas leitura para proprietário e grupo)
            os.chmod(report_path, 0o440) # rw-r----- (0o640 para leitura/escrita pelo proprietário, leitura pelo grupo)
            
            self.log(
                message=f"Relatório para autoridades gerado em: {report_path}",
                action='AUTHORITY_REPORT_GENERATED',
                compliance_status='LGPD_OK', # Geração do relatório é um evento de compliance
                risk_level='LOW',
                details=f"Caminho: {report_path}. Permissões: 0o440."
            )
            self.logger.info(f"Relatório para autoridades gerado com sucesso em: {report_path}")
        except Exception as e:
            self.logger.error(f"Falha ao gerar relatório para autoridades em '{report_path}': {e}", exc_info=True)
            self.log(
                message=f"Falha ao gerar relatório para autoridades. Erro: {str(e)}",
                action='AUTHORITY_REPORT_GENERATION_FAILED',
                level='ERROR',
                risk_level='CRITICAL', # Falha na geração de relatório de compliance é crítica
                error_message=str(e),
                stack_trace_needed=True
            )

    def get_audit_data(self, days: int = 7) -> pd.DataFrame:
        """
        Recupera dados de auditoria dos últimos 'n' dias.

        Args:
            days (int): Número de dias para retroceder na busca de dados.

        Returns:
            pd.DataFrame: DataFrame contendo os dados de auditoria filtrados.
                          Retorna um DataFrame vazio se o arquivo não existir ou houver erro.
        """
        try:
            if not os.path.exists(self.audit_file_path):
                self.logger.warning(f"Arquivo de auditoria não encontrado em '{self.audit_file_path}'. Retornando DataFrame vazio.")
                return pd.DataFrame()
            
            df = pd.read_csv(self.audit_file_path, parse_dates=['timestamp'], infer_datetime_format=True)
            
            if df.empty:
                self.logger.info("Arquivo de auditoria está vazio. Retornando DataFrame vazio.")
                return pd.DataFrame()
            
            # Localiza o timestamp para evitar problemas de comparação de timezone
            df['timestamp'] = pd.to_datetime(df['timestamp']).dt.tz_localize(None) 
            
            cutoff = datetime.now() - timedelta(days=days)
            filtered_df = df[df['timestamp'] >= cutoff].copy()
            self.logger.info(f"Dados de auditoria recuperados para os últimos {days} dias. Registros: {len(filtered_df)}")
            return filtered_df
        except Exception as e:
            self.logger.error(f"Falha ao recuperar dados de auditoria: {str(e)}", exc_info=True)
            # Loga o incidente no próprio sistema de auditoria se possível
            self.log(
                message=f"Falha interna ao recuperar dados de auditoria. Erro: {str(e)}",
                action="AUDIT_DATA_RETRIEVAL_FAILED",
                level="ERROR",
                risk_level="HIGH",
                error_message=str(e),
                stack_trace_needed=True,
                service="AuditLogger_Internal"
            )
            return pd.DataFrame()

    def log_operation(self, dag_id: str, task_id: str, operation: str, metadata: dict = None, user: str = 'airflow_process') -> None:
        """
        Registra uma operação genérica do pipeline.

        Args:
            dag_id (str): ID da DAG associada à operação.
            task_id (str): ID da tarefa associada à operação.
            operation (str): Descrição da operação (ex: 'DATA_TRANSFORM', 'DATABASE_WRITE').
            metadata (dict, optional): Metadados adicionais para a operação. Padrão é None.
            user (str, optional): Usuário ou processo que realizou a operação. Padrão é 'airflow_process'.
        """
        details_msg = f"Operação: {operation}"
        if metadata:
            details_msg += f" | Metadados: {json.dumps(metadata, ensure_ascii=False)}"
        
        self.log(
            message=details_msg,
            action=f"OP_{operation.upper()}", # Prefixo 'OP_' para operações de pipeline
            dag_id=dag_id,
            task_id=task_id,
            user=user,
            level="INFO",
            compliance_status="LGPD_OK" # Operações padrão são geralmente OK
        )

    def log_incident(self, severity: str, dag_id: str = 'N/A', task_id: str = 'N/A', error: str = '', stack_trace: bool = False, **kwargs) -> None:
        """
        Registra um incidente de segurança ou erro grave.

        Args:
            severity (str): Nível de severidade do incidente (ex: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
            dag_id (str, optional): ID da DAG associada. Padrão é 'N/A'.
            task_id (str, optional): ID da tarefa associada. Padrão é 'N/A'.
            error (str, optional): Mensagem de erro ou descrição do incidente. Padrão é ''.
            stack_trace (bool, optional): Indica se um stack trace é relevante e deve ser procurado. Padrão é False.
            kwargs: Argumentos adicionais para o log.
        """
        # Mapeamento de severidade para compliance_status e risk_level
        compliance_status = "LGPD_BREACH" if severity.upper() in ["CRITICAL", "URGENT", "HIGH"] else "LGPD_WARNING"
        risk_level = severity.upper() # O risk_level é igual à severidade do incidente

        self.log(
            message=f"INCIDENTE DETECTADO: {error}",
            level=severity.upper(),
            action="SECURITY_INCIDENT", # Ação específica para incidentes de segurança
            dag_id=dag_id,
            task_id=task_id,
            user=kwargs.get('user', 'security_system'),
            risk_level=risk_level,
            compliance_status=compliance_status,
            error_message=error,
            stack_trace_needed=stack_trace,
            service=kwargs.get('service', 'SECURITY_SYSTEM'),
            **kwargs # Passa quaisquer outros kwargs adicionais
        )

    def log_upload(self, local_path: str, remote_path: str, dag_id: str = 'N/A', task_id: str = 'N/A', user: str = 'airflow_process', **kwargs) -> None:
        """
        Registra um evento de upload de arquivo para armazenamento de objetos.

        Args:
            local_path (str): Caminho local do arquivo de origem.
            remote_path (str): Caminho de destino no armazenamento de objetos (bucket/key).
            dag_id (str, optional): ID da DAG. Padrão é 'N/A'.
            task_id (str, optional): ID da tarefa. Padrão é 'N/A'.
            user (str, optional): Usuário ou processo. Padrão é 'airflow_process'.
            kwargs: Argumentos adicionais para o log.
        """
        self.log(
            message=f"Arquivo enviado de '{local_path}' para '{remote_path}'.",
            action="FILE_UPLOAD",
            dag_id=dag_id,
            task_id=task_id,
            user=user,
            service="MinIO/S3",
            compliance_status="LGPD_OK", # Assume sucesso por padrão, ajustar em caso de falha
            **kwargs
        )

    def log_transfer(self, object_key: str, source_bucket: str, dest_bucket: str, dag_id: str = 'N/A', task_id: str = 'N/A', user: str = 'airflow_process', **kwargs) -> None:
        """
        Registra um evento de transferência (movimentação/cópia) de objeto entre buckets.

        Args:
            object_key (str): Chave (nome) do objeto.
            source_bucket (str): Nome do bucket de origem.
            dest_bucket (str): Nome do bucket de destino.
            dag_id (str, optional): ID da DAG. Padrão é 'N/A'.
            task_id (str, optional): ID da tarefa. Padrão é 'N/A'.
            user (str, optional): Usuário ou processo. Padrão é 'airflow_process'.
            kwargs: Argumentos adicionais para o log.
        """
        self.log(
            message=f"Objeto '{object_key}' transferido de '{source_bucket}' para '{dest_bucket}'.",
            action="OBJECT_TRANSFER",
            dag_id=dag_id,
            task_id=task_id,
            user=user,
            service="MinIO/S3_Lifecycle",
            compliance_status="LGPD_OK", # Assume sucesso por padrão
            details=json.dumps({"object_key": object_key, "source": source_bucket, "destination": dest_bucket}),
            **kwargs
        )

    def log_validation(self, results: dict = None, success: bool = None, stats: dict = None, failed_expectations: list = None, metadata: dict = None, **kwargs) -> None:
        """
        Registra um evento de validação de dados (geralmente com Great Expectations).

        Args:
            results (dict, optional): Resultados completos da validação (e.g., Great Expectations ValidationResult as dict).
            success (bool, optional): Booleano indicando o sucesso geral da validação.
            stats (dict, optional): Estatísticas sumárias da validação.
            failed_expectations (list, optional): Lista de expectativas que falharam.
            metadata (dict, optional): Metadados adicionais da validação.
            kwargs: Argumentos adicionais para o log.
        """
        is_success: bool = False # Padrão para falha
        if success is not None:
            is_success = success
        elif results and isinstance(results, dict):
            is_success = results.get('success', False)
        elif results and hasattr(results, 'success'): # Para objetos Great Expectations
            is_success = getattr(results, 'success', False)
        
        validation_status_action = "VALIDATION_SUCCESS" if is_success else "VALIDATION_FAILURE"
        log_level = "INFO" if is_success else "ERROR"
        compliance = "LGPD_OK" if is_success else "LGPD_VIOLATION"
        risk_level = "LOW" if is_success else "HIGH"

        details_dict_for_csv: Dict[str, Any] = {}
        if results:
            if isinstance(results, dict):
                details_dict_for_csv['ge_success'] = results.get('success')
                details_dict_for_csv['ge_statistics'] = results.get('statistics')
                if 'results' in results:
                    details_dict_for_csv['ge_failed_expectations_types'] = [
                        r.get('expectation_config', {}).get('expectation_type', 'N/A')
                        for r in results.get('results', []) if not r.get('success')
                    ]
            elif hasattr(results, 'success'): # Para objetos Great Expectations
                details_dict_for_csv['ge_success'] = getattr(results, 'success', None)
                if hasattr(results, 'statistics'): details_dict_for_csv['ge_statistics'] = getattr(results, 'statistics', None)
                if hasattr(results, 'results'):
                    details_dict_for_csv['ge_failed_expectations_types'] = [
                        getattr(r.expectation_config, 'expectation_type', 'N/A')
                        for r in getattr(results, 'results', []) if not getattr(r, 'success', True)
                    ]
        
        # Inclui metadados passados diretamente ou de objetos/dicionários
        if stats: details_dict_for_csv['manual_stats'] = stats
        if failed_expectations: details_dict_for_csv['manual_failed_expectations'] = failed_expectations
        if metadata: details_dict_for_csv['custom_metadata'] = metadata

        details_message = json.dumps(details_dict_for_csv, ensure_ascii=False)

        self.log(
            message=f"Status de Validação: {validation_status_action}. Sucesso Geral: {is_success}",
            action=validation_status_action,
            level=log_level,
            compliance_status=compliance,
            risk_level=risk_level,
            details=details_message,
            service="Data_Validation",
            **kwargs # Passa quaisquer outros kwargs adicionais
        )
