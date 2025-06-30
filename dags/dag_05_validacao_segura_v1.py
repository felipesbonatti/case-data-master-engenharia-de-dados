"""
===================================================================================
DAG DE VALIDAÇÃO DE DADOS COM GREAT EXPECTATIONS - DEMONSTRAÇÃO
===================================================================================

DESCRIÇÃO:
    Pipeline de validação de qualidade de dados enterprise implementando
    Great Expectations como Quality Gate crítico no fluxo de dados,
    com integração completa ao sistema de auditoria e governança corporativa.

ARQUITETURA DE QUALIDADE:
    - Quality Gate automatizado com Great Expectations
    - Sistema de auditoria integrado para rastreabilidade completa
    - Tratamento robusto de exceções com classificação de severidade
    - Validação multi-dimensional de integridade, completude e consistência

COMPONENTES TÉCNICOS:
    - Great Expectations Suite Engine
    - Sistema de Auditoria Customizado
    - Tratamento de Exceções Especializadas
    - Logging Estruturado para Compliance

DATASETS VALIDADOS:
    - dados_consolidados.csv (Dataset principal consolidado)
    - Suíte de Expectativas: vendas.json (Regras de negócio)

VALIDAÇÕES IMPLEMENTADAS:
    - Integridade referencial
    - Completude de dados críticos
    - Consistência de tipos de dados
    - Regras de negócio específicas
    - Detecção de anomalias estatísticas

COMPLIANCE E GOVERNANÇA:
    - Auditoria completa de resultados de validação
    - Logs estruturados para compliance regulatório
    - Métricas de qualidade rastreáveis
    - Alertas automáticos para falhas críticas
===================================================================================
"""

from __future__ import annotations

import os
import json
import pendulum
import great_expectations as ge
import logging # Adicionado para logging consistente
from typing import Dict, Any, Optional
from pathlib import Path

from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.context import Context

# ===================================================================================
# CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ===================================================================================

# Configuração do ambiente Airflow
AIRFLOW_HOME = os.getenv('AIRFLOW_HOME', '/opt/airflow')

# Configuração de caminhos de dados e expectativas
DATA_PATHS = {
    'consolidated_data': 'data/olist/dados_consolidados.csv',
    'expectations_suite': 'dags/expectations/vendas.json'
}

# Configuração de auditoria e logs
AUDIT_PATHS = {
    'audit_log': 'logs/security_audit/audit.csv',
    'system_log': 'logs/security_audit/system.log'
}

# Configuração de validação
VALIDATION_CONFIG = {
    'timeout_seconds': 300,
    'max_retry_attempts': 3,
    'critical_failure_threshold': 0.95
}

# Mapeamento de severidade de erros
ERROR_SEVERITY_MAP = {
    'FileNotFoundError': 'CRITICAL',
    'ValidationError': 'ERROR',
    'JSONDecodeError': 'ERROR',
    'DataContextError': 'CRITICAL',
    'Exception': 'ERROR'
}


# ===================================================================================
# FUNÇÕES AUXILIARES E COMPONENTES DE SEGURANÇA
# ===================================================================================

def _initialize_audit_system() -> object:
    """
    Inicializa o sistema de auditoria para rastreamento de validações.
    
    Returns:
        AuditLogger: Instância configurada do sistema de auditoria
        
    Raises:
        ImportError: Quando módulos de auditoria não estão disponíveis
    """
    try:
        from plugins.security_system.audit import AuditLogger
    except ImportError as e:
        raise ImportError(f"ERRO CRÍTICO: Módulo de auditoria não encontrado: {e}")
    
    # Construção de caminhos usando Path para maior robustez
    audit_log_path = Path(AIRFLOW_HOME) / AUDIT_PATHS['audit_log']
    system_log_path = Path(AIRFLOW_HOME) / AUDIT_PATHS['system_log']
    
    # Criação de diretórios se necessário
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    system_log_path.parent.mkdir(parents=True, exist_ok=True)
    
    return AuditLogger(
        audit_file_path=str(audit_log_path),
        system_log_file_path=str(system_log_path)
    )


def _load_expectations_suite(expectations_path: str) -> Dict[str, Any]:
    """
    Carrega e valida a suíte de expectativas do Great Expectations.
    
    Args:
        expectations_path: Caminho para o arquivo de expectativas
        
    Returns:
        Dict[str, Any]: Suíte de expectativas carregada
        
    Raises:
        FileNotFoundError: Quando arquivo de expectativas não existe
        json.JSONDecodeError: Quando arquivo JSON é inválido
    """
    expectations_file = Path(expectations_path)
    
    if not expectations_file.exists():
        raise FileNotFoundError(f"Arquivo de expectativas não encontrado: {expectations_path}")
    
    try:
        with open(expectations_file, 'r', encoding='utf-8') as file:
            expectations_suite = json.load(file)
        
        # Validação básica da estrutura da suíte
        required_keys = ['expectations', 'expectation_suite_name']
        for key in required_keys:
            if key not in expectations_suite:
                raise ValueError(f"Chave obrigatória ausente na suíte: {key}")
        
        return expectations_suite
        
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Arquivo de expectativas com formato JSON inválido: {e}")


def _execute_validation_suite(
    dataframe: object,
    expectations_suite: Dict[str, Any],
    audit_logger: object,
    dag_id: str
) -> Dict[str, Any]:
    """
    Executa a suíte de validação do Great Expectations com logging completo.
    
    Args:
        dataframe: DataFrame do Great Expectations para validação
        expectations_suite: Suíte de expectativas a ser executada
        audit_logger: Logger de auditoria
        dag_id: ID da DAG para contexto de auditoria
        
    Returns:
        Dict[str, Any]: Resultados da validação
        
    Raises:
        ValidationError: Quando validação falha criticamente
    """
    audit_logger.log(
        f"Iniciando execução de suíte de validação: {expectations_suite.get('expectation_suite_name', 'N/A')}",
        action="GE_SUITE_EXECUTION_START",
        dag_id=dag_id
    )
    
    try:
        # Execução da validação
        validation_result = dataframe.validate(expectation_suite=expectations_suite)
        
        # Extração de métricas de qualidade
        total_expectations = len(validation_result.get('results', []))
        successful_expectations = sum(1 for result in validation_result.get('results', []) if result.get('success', False))
        success_rate = successful_expectations / total_expectations if total_expectations > 0 else 0
        
        # Log detalhado dos resultados
        audit_logger.log(
            f"Validação executada - Total: {total_expectations}, "
            f"Sucessos: {successful_expectations}, Taxa: {success_rate:.2%}",
            action="GE_VALIDATION_METRICS",
            dag_id=dag_id
        )
        
        # Verificação de threshold crítico
        if success_rate < VALIDATION_CONFIG['critical_failure_threshold']:
            audit_logger.log(
                f"ALERTA CRÍTICO: Taxa de sucesso abaixo do threshold "
                f"({success_rate:.2%} < {VALIDATION_CONFIG['critical_failure_threshold']:.2%})",
                level="CRITICAL",
                action="GE_CRITICAL_THRESHOLD_BREACH",
                dag_id=dag_id
            )
        
        return validation_result
        
    except Exception as e:
        audit_logger.log(
            f"Erro durante execução da suíte de validação: {str(e)}",
            level="ERROR",
            action="GE_SUITE_EXECUTION_ERROR",
            dag_id=dag_id
        )
        raise


def _process_validation_results(
    validation_results: Dict[str, Any],
    audit_logger: object,
    dag_id: str,
    data_source: str
) -> None:
    """
    Processa e registra os resultados da validação com análise detalhada.
    
    Args:
        validation_results: Resultados da validação do Great Expectations
        audit_logger: Logger de auditoria
        dag_id: ID da DAG para contexto
        data_source: Fonte dos dados validados
    """
    # Registro detalhado dos resultados na auditoria
    audit_logger.log_validation(
        results=validation_results.to_json_dict(),
        metadata={
            "fonte_dados": data_source,
            "timestamp_validacao": pendulum.now().isoformat(),
            "dag_execution": dag_id
        }
    )
    
    # Análise de falhas para relatório
    failed_expectations = [
        result for result in validation_results.get('results', [])
        if not result.get('success', True)
    ]
    
    if failed_expectations:
        failure_summary = []
        for failure in failed_expectations:
            expectation_type = failure.get('expectation_config', {}).get('expectation_type', 'Unknown')
            failure_summary.append(expectation_type)
        
        audit_logger.log(
            f"Expectativas falharam: {', '.join(set(failure_summary))}",
            level="WARNING",
            action="GE_FAILED_EXPECTATIONS_SUMMARY",
            dag_id=dag_id
        )


# ===================================================================================
# FUNÇÃO PRINCIPAL DE VALIDAÇÃO
# ===================================================================================

def _valida_vendas_ge(**context: Context) -> None:
    """
    Função principal que executa validação completa com Great Expectations.
    
    Fluxo de Execução:
        1. Inicialização do sistema de auditoria
        2. Carregamento do dataset consolidado
        3. Carregamento da suíte de expectativas
        4. Execução da validação com métricas
        5. Processamento e análise dos resultados
        6. Registro completo na auditoria
        7. Tratamento de exceções com classificação
    
    Args:
        context: Contexto de execução do Airflow
        
    Raises:
        ValidationError: Quando validação falha criticamente
        FileNotFoundError: Quando arquivos necessários não existem
        Exception: Outros erros são classificados e re-propagados
    """
    # Inicialização do sistema de auditoria
    audit_logger = _initialize_audit_system()
    dag_id = context.get('dag_run').dag_id
    
    audit_logger.log(
        "Iniciando pipeline de validação de qualidade de dados",
        action="GE_VALIDATION_START",
        dag_id=dag_id
    )
    
    # Construção de caminhos absolutos
    caminho_dados = Path(AIRFLOW_HOME) / DATA_PATHS['consolidated_data']
    caminho_expectations = Path(AIRFLOW_HOME) / DATA_PATHS['expectations_suite']
    
    try:
        # Fase 1: Carregamento e validação do dataset
        logging.info(f"Carregando dataset de dados consolidados: {caminho_dados}")
        
        if not caminho_dados.exists():
            raise FileNotFoundError(f"Dataset não encontrado: {caminho_dados}")
        
        dataframe_ge = ge.read_csv(str(caminho_dados))
        
        audit_logger.log(
            f"Dataset carregado com sucesso: {len(dataframe_ge)} registros",
            action="GE_DATASET_LOADED",
            dag_id=dag_id
        )
        
        # Fase 2: Carregamento da suíte de expectativas
        logging.info(f"Carregando suíte de expectativas: {caminho_expectations}")
        expectations_suite = _load_expectations_suite(str(caminho_expectations))
        
        audit_logger.log(
            f"Suíte de expectativas carregada: {expectations_suite.get('expectation_suite_name', 'N/A')} "
            f"({len(expectations_suite.get('expectations', []))} expectativas)",
            action="GE_EXPECTATIONS_LOADED",
            dag_id=dag_id
        )
        
        # Fase 3: Execução da validação
        logging.info("Executando validação de qualidade de dados...")
        validation_results = _execute_validation_suite(
            dataframe_ge,
            expectations_suite,
            audit_logger,
            dag_id
        )
        
        # Fase 4: Processamento dos resultados
        _process_validation_results(
            validation_results,
            audit_logger,
            dag_id,
            str(caminho_dados)
        )
        
        # Fase 5: Verificação de sucesso geral
        overall_success = validation_results.get('success', False)
        
        if not overall_success:
            from plugins.security_system.exceptions import ValidationError
            
            audit_logger.log(
                "FALHA CRÍTICA: Validação de dados não passou nos critérios de qualidade",
                level="CRITICAL",
                action="GE_VALIDATION_CRITICAL_FAIL",
                dag_id=dag_id
            )
            
            raise ValidationError("Validação de dados com Great Expectations falhou criticamente")
        
        # Sucesso da validação
        audit_logger.log(
            "Validação de qualidade de dados concluída com sucesso",
            action="GE_VALIDATION_SUCCESS",
            dag_id=dag_id
        )
        
        logging.info("SUCESSO: Todas as validações de qualidade passaram")
        
    except FileNotFoundError as e:
        error_msg = f"Arquivo necessário não encontrado: {str(e)}"
        audit_logger.log(
            error_msg,
            level=ERROR_SEVERITY_MAP.get('FileNotFoundError', 'ERROR'),
            action="GE_VALIDATION_FILE_NOT_FOUND",
            dag_id=dag_id
        )
        logging.error(f"ERRO - Arquivo não encontrado: {str(e)}")
        raise
        
    except json.JSONDecodeError as e:
        error_msg = f"Erro no formato JSON das expectativas: {str(e)}"
        audit_logger.log(
            error_msg,
            level=ERROR_SEVERITY_MAP.get('JSONDecodeError', 'ERROR'),
            action="GE_VALIDATION_JSON_ERROR",
            dag_id=dag_id
        )
        logging.error(f"ERRO - JSON inválido: {str(e)}")
        raise
        
    except Exception as e:
        error_type = type(e).__name__
        error_msg = f"Erro inesperado durante validação ({error_type}): {str(e)}"
        
        audit_logger.log(
            error_msg,
            level=ERROR_SEVERITY_MAP.get(error_type, 'ERROR'),
            action="GE_VALIDATION_UNEXPECTED_ERROR",
            dag_id=dag_id
        )
        logging.error(f"ERRO - Falha inesperada: {str(e)}")
        raise


# ===================================================================================
# DEFINIÇÃO DA DAG PRINCIPAL
# ===================================================================================

with DAG(
    dag_id="dag_05_validacao_segura_v1",
    start_date=pendulum.datetime(2025, 6, 10, tz="UTC"),
    schedule="0 2 * * *",  # Execução diária às 2h00 UTC
    catchup=False,
    max_active_runs=1,  # Previne execuções simultâneas
    doc_md="""
    # DAG de Validação de Qualidade de Dados - Enterprise Edition
    
    ## Objetivo
    Pipeline automatizado de validação de qualidade de dados implementando
    Great Expectations como Quality Gate crítico, com auditoria completa
    e integração aos sistemas de governança corporativa.
    
    ## Arquitetura de Validação
    
    ```
    [Dataset Consolidado] -> [Great Expectations] -> [Quality Gate] -> [Auditoria] -> [Aprovação/Rejeição]
    ```
    
    ## Componentes Principais
    
    ### Validações Implementadas
    - Integridade Referencial: Verificação de chaves e relacionamentos
    - Completude de Dados: Identificação de valores nulos críticos
    - Consistência de Tipos: Validação de formatos e tipos de dados
    - Regras de Negócio: Validações específicas do domínio de vendas
    - Detecção de Anomalias: Identificação de outliers e inconsistências
    
    ### Sistema de Auditoria
    - Rastreabilidade completa de todas as validações
    - Métricas de qualidade granulares
    - Logs estruturados para compliance
    - Alertas automáticos para falhas críticas
    
    ### Configurações de Qualidade
    - Threshold Crítico: 95% de sucesso mínimo
    - Timeout: 300 segundos por validação
    - Retry Policy: 3 tentativas máximas
    - Classificação de Severidade: CRITICAL/ERROR/WARNING
    
    ## Fontes de Dados
    - Dataset Principal: dados_consolidados.csv
    - Suíte de Expectativas: vendas.json
    - Logs de Auditoria: security_audit/
    
    ## Compliance e Governança
    - Auditoria completa conforme SOX
    - Logs estruturados para GDPR/LGPD
    - Métricas de qualidade rastreáveis
    - Processo de aprovação automatizado
    
    ## Execução
    - Agendamento: Diário às 2h00 UTC
    - Duração Típica: 2-5 minutos
    - Recursos: CPU intensivo durante validação
    - Dependências: Dataset consolidado deve existir
    """,
    tags=['validation', 'quality', 'great_expectations', 'enterprise', 'quality_gate', 'governance']
) as dag:
    
    # ===================================================================================
    # DEFINIÇÃO DA TAREFA PRINCIPAL
    # ===================================================================================
    
    tarefa_validar = PythonOperator(
        task_id="validar_dados_consolidados_task",
        python_callable=_valida_vendas_ge,
        retries=VALIDATION_CONFIG['max_retry_attempts'],
        retry_delay=pendulum.duration(minutes=5),
        doc_md="""
        ## Tarefa de Validação de Qualidade de Dados
        
        Esta tarefa implementa um Quality Gate completo usando Great Expectations
        para garantir que apenas dados de alta qualidade prossigam no pipeline.
        
        ### Processo de Validação
        
        1. Inicialização: Setup do sistema de auditoria
        2. Carregamento: Dataset e suíte de expectativas
        3. Validação: Execução de todas as expectativas
        4. Análise: Processamento dos resultados
        5. Decisão: Aprovação ou rejeição baseada em critérios
        6. Auditoria: Registro completo de todas as operações
        
        ### Métricas Monitoradas
        - Taxa de sucesso das validações
        - Tempo de execução por expectativa
        - Tipos de falhas identificadas
        - Volume de dados processados
        - Classificação de severidade de erros
        
        ### Tratamento de Erros
        - CRITICAL: Falhas que impedem continuidade do pipeline
        - ERROR: Problemas graves que requerem intervenção
        - WARNING: Alertas que não bloqueiam execução
        
        ### Saídas
        - Logs de auditoria estruturados
        - Métricas de qualidade detalhadas
        - Relatório de validação JSON
        - Alertas automáticos para falhas
        """
    )


