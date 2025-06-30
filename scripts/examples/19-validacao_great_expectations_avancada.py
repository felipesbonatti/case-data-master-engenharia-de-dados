#!/usr/bin/env python3

import great_expectations as ge
import json
import sys
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# Configuração do logger para este script
# Em um ambiente de produção, esta configuração seria centralizada.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s - %(filename)s:%(lineno)d')
logger = logging.getLogger(__name__)

# Adiciona o diretório dos plugins ao path para encontrar os módulos de segurança.
# Isso é crucial se o script for executado diretamente e não pelo ambiente Airflow,
# onde os plugins já estariam no PYTHONPATH.
plugins_path = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins')))
if str(plugins_path) not in sys.path:
    sys.path.insert(0, str(plugins_path))

# Importações dos módulos de segurança customizados.
try:
    # Apenas tenta carregar para mostrar que o script está ciente do framework de segurança.
    # Não usei AirflowSecurityManager ou AuditLogger diretamente neste script.
    from security_system.vault_manager_helper import VaultManager # Exemplo de importação, se fosse usar
    from security_system.audit import AuditLogger # Exemplo de importação, se fosse usar
    from security_system.exceptions import ConfigurationError, SecureConnectionError # Exemplo de importação
    logger.info("Módulos de segurança (se presentes) carregados. Este script usa Great Expectations diretamente.")
except ImportError as e:
    logger.warning(f"AVISO: Módulos de segurança customizados não encontrados. Validação continuará, mas sem integração de segurança. Detalhes: {e}")


"""
====================================================================================
SCRIPT STANDALONE: VALIDACAO DE DADOS DE VENDAS COM GREAT EXPECTATIONS 
====================================================================================

DESCRICAO:
    Este script Python standalone realiza validacoes de qualidade de dados no
    dataset consolidado de vendas Olist (`dados_consolidados.csv`), utilizando
    a biblioteca Great Expectations. Ele simula um Quality Gate critico
    que precede a promocao dos dados para Data Marts ou outras aplicacoes
    analiticas, garantindo a integridade, completude e consistencia dos dados.

OBJETIVO PRINCIPAL:
    - Carregar um dataset de vendas de uma fonte local.
    - Carregar um conjunto de regras de qualidade (expectativas) de um arquivo JSON.
    - Aplicar formalmente essas expectativas ao dataset.
    - Executar as validacoes e gerar um relatorio detalhado.
    - Retornar um codigo de status (`0` para sucesso, `1` para falha) para
      integracao com sistemas de orquestracao como o Apache Airflow.

COMPONENTES TECNICOS:
    - `great_expectations`: Biblioteca primaria para definicao e execucao de expectativas de dados.
    - `pandas` (integrado via GE): Utilizado internamente pelo Great Expectations para manipulacao de DataFrames.
    - `json`: Para carregar as definicoes de expectativas de um arquivo JSON.
    - `pathlib`: Para gerenciamento robusto e multi-plataforma de caminhos de arquivos.
    - `logging`: Para registrar o progresso e diagnosticar problemas durante a execucao.

EXPECTATIVAS IMPLEMENTADAS:
    O script carrega expectativas de um arquivo JSON, permitindo flexibilidade
    e extensibilidade nas regras de qualidade. Exemplos comuns incluem:
    - Verificacao de nao-nulidade em chaves primarias.
    - Validacao de valores em um conjunto predefinido (e.g., status de pedidos).
    - Checagem de faixas de valores numericos (e.g., precos nao negativos).
    - Verificacao de tipos de dados.

ROBUSTEZ E TRATAMENTO DE ERROS:
    - Verificacao de Existencia de Arquivos: Garante que os arquivos de dados e expectativas
      existam antes de tentar carrega-los, evitando erros de tempo de execucao.
    - Tratamento de Erros de Carregamento: Captura excecoes durante a leitura de CSV e JSON.
    - Relatorio Detalhado: O Great Expectations gera um relatorio abrangente,
      facilitando a identificacao de quais expectativas falharam e por que.
    - Codigos de Saida (Exit Codes): O script termina com `0` em caso de sucesso e `1`
      em caso de falha, fundamental para automacao e orquestracao.
====================================================================================
"""

# ---
# CONFIGURACOES DO SCRIPT
# Centraliza caminhos de arquivos e outras configuracoes para facil manutencao.
# ---
class ValidationConfig:
    """Configuracoes para o script de validacao de dados de vendas."""

    # Caminho para o arquivo CSV de dados consolidados.
    # Pode ser ajustado via variavel de ambiente 'SALES_DATA_PATH_TO_VALIDATE' para portabilidade.
    DATA_FILE: Path = Path(os.getenv('SALES_DATA_PATH_TO_VALIDATE', 'data/olist/dados_consolidados.csv'))

    # Caminho para o arquivo JSON contendo as definicoes das expectativas do Great Expectations.
    # Pode ser ajustado via variavel de ambiente 'SALES_EXPECTATIONS_PATH'.
    EXPECTATIONS_FILE: Path = Path(os.getenv('SALES_EXPECTATIONS_PATH', 'dags/expectations/vendas_expectations.json'))

# ---
# FUNCOES AUXILIARES
# ---

def validar_arquivos_existem() -> bool:
    """
    Verifica se os arquivos de dados e de expectativas necessarios existem no sistema de arquivos.

    Retorna:
        bool: True se todos os arquivos existirem, False caso contrario.
        Em caso de falha, imprime uma mensagem de erro e loga.
    """
    files_to_check = [ValidationConfig.DATA_FILE, ValidationConfig.EXPECTATIONS_FILE]
    
    for file_path in files_to_check:
        if not file_path.exists():
            error_msg = f"ERRO: Arquivo nao encontrado: '{file_path}'."
            if file_path == ValidationConfig.DATA_FILE:
                logger.critical("Certifique-se de que o pipeline de consolidacao de dados foi executado e o arquivo gerado.")
            elif file_path == ValidationConfig.EXPECTATIONS_FILE:
                logger.critical("Verifique o caminho ou a existencia do arquivo JSON de expectativas.")
            return False
    logger.info("Todos os arquivos necessarios foram encontrados.")
    return True

def carregar_dados() -> Optional[ge.dataset.PandasDataset]:
    """
    Carrega o arquivo CSV de dados consolidado em um DataFrame Great Expectations.

    Retorna:
        Optional[ge.dataset.PandasDataset]: O DataFrame GE se o carregamento for bem-sucedido,
                                             None caso contrario.
    """
    logger.info(f"Carregando dados de: '{ValidationConfig.DATA_FILE}'")
    
    try:
        # Usa Great Expectations para ler o CSV, que o prepara para validacao
        df = ge.read_csv(str(ValidationConfig.DATA_FILE))
        logger.info(f"Dados carregados com sucesso. {len(df)} registros encontrados.")
        logger.info(f"Sucesso! {len(df)} registros carregados.")
        return df
    except Exception as e:
        error_msg = f"ERRO ao carregar dados do arquivo '{ValidationConfig.DATA_FILE}': {e}"
        logger.critical(error_msg, exc_info=True)
        return None

def carregar_expectativas() -> Optional[Dict[str, Any]]:
    """
    Carrega as definicoes de expectativas de qualidade de dados de um arquivo JSON.

    Retorna:
        Optional[Dict[str, Any]]: Um dicionario contendo as definicoes das expectativas,
                                  ou None em caso de erro.
    """
    logger.info(f"Carregando expectativas de: '{ValidationConfig.EXPECTATIONS_FILE}'")
    
    try:
        with open(ValidationConfig.EXPECTATIONS_FILE, "r", encoding='utf-8') as f:
            expectations = json.load(f)
        
        num_expectations = len(expectations.get('expectations', []))
        logger.info(f"Expectativas carregadas com sucesso. {num_expectations} expectativas encontradas.")
        logger.info(f"Sucesso! {num_expectations} expectativas carregadas.")
        return expectations
    except json.JSONDecodeError as e:
        error_msg = f"ERRO ao decodificar JSON do arquivo de expectativas '{ValidationConfig.EXPECTATIONS_FILE}': {e}"
        logger.critical(error_msg, exc_info=True)
        return None
    except Exception as e:
        error_msg = f"ERRO ao carregar expectativas do arquivo '{ValidationConfig.EXPECTATIONS_FILE}': {e}"
        logger.critical(error_msg, exc_info=True)
        return None

def main() -> None:
    """
    Funcao principal do script de validacao de dados.
    Orquestra o carregamento de dados e expectativas, executa a validacao
    e imprime um relatorio final com o status de sucesso ou falha.
    """
    logger.info("=" * 60)
    logger.info("INICIANDO VALIDACAO DE DADOS DE VENDAS COM GREAT EXPECTATIONS")
    logger.info("=" * 60)
    
    # 1. Verificar se arquivos existem e sao acessiveis
    if not validar_arquivos_existem():
        sys.exit(1) # Sai se arquivos essenciais nao forem encontrados
        
    # 2. Carregar dados
    df = carregar_dados()
    if df is None:
        sys.exit(1) # Sai se o carregamento de dados falhar

    # 3. Carregar expectativas
    expectations_suite = carregar_expectativas()
    if expectations_suite is None:
        sys.exit(1) # Sai se o carregamento das expectativas falhar
    
    # 4. Executar validacao
    logger.info("Executando validacao final com base nas regras definidas...")
    
    # O Great Expectations permite validar passando um expectation_suite diretamente.
    # As expectativas sao aplicadas e validadas como parte deste unico comando.
    validation_result = df.validate(expectation_suite=expectations_suite)

    # 5. Analise e exibicao dos resultados
    logger.info("Validacao finalizada. Relatorio de resultados:")
    # Loga o resultado completo como JSON para rastreabilidade
    logger.info(json.dumps(validation_result.to_json_dict(), indent=2))
    
    logger.info("RESULTADOS DA VALIDACAO:")
    logger.info(validation_result) # O Great Expectations tem uma otima representacao em string

    total_expectations = validation_result.statistics.get("evaluated_expectations", 0)
    successful = validation_result.statistics.get("successful_expectations", 0)
    success_rate = (successful / total_expectations * 100) if total_expectations > 0 else 0
    
    logger.info(f"Total de expectativas avaliadas: {total_expectations}")
    logger.info(f"Expectativas atendidas com sucesso: {successful}")
    logger.info(f"Taxa de sucesso geral: {success_rate:.1f}%")
    logger.info(f"Status geral da validacao: {'APROVADO' if validation_result.success else 'REPROVADO'}")
    
    if not validation_result.success:
        logger.warning("DETALHES DAS FALHAS:")
        for result in validation_result.results:
            if not result.success:
                # Adapta a exibicao dos detalhes da falha
                details = result.result # Dicionario de detalhes da falha
                unexpected_count = details.get('unexpected_count', 'N/A')
                partial_unexpected_list = details.get('partial_unexpected_list', [])
                
                logger.warning(f"Expectativa Falha: '{result.expectation_config.expectation_type}' na coluna '{result.expectation_config.kwargs.get('column', 'N/A')}'")
                logger.warning(f"Mensagem: {result.expectation_config.comment if hasattr(result.expectation_config, 'comment') else 'Sem comentario.'}")
                logger.warning(f"Inesperados: {unexpected_count} (Exemplos: {partial_unexpected_list[:5]})") # Mostra ate 5 exemplos
                logger.warning(f"Expectativa FAILED: {result.expectation_config.expectation_type}. Detalhes: {result.to_json_dict()}")
        
        final_message = "VALIDACAO FALHOU! Uma ou mais regras de qualidade de dados foram violadas. Reveja os dados e o relatorio detalhado acima."
        logger.error(final_message)
        sys.exit(1) # Sai com codigo de erro para indicar falha
    else:
        final_message = "VALIDACAO APROVADA! Todos os testes de qualidade passaram com sucesso. Os dados estao prontos para o proximo estagio."
        logger.info(final_message)
        sys.exit(0) # Sai com codigo de sucesso

# ---
# PONTO DE ENTRADA PRINCIPAL DO SCRIPT
# ---
if __name__ == "__main__":
    # Garante que os diretorios de dados e expectativas existam.
    # O configure.py faria isso em um setup maior.
    ValidationConfig.DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    ValidationConfig.EXPECTATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)

    try:
        main()
    except Exception:
        # Captura qualquer excecao nao tratada na funcao principal para sair com codigo de erro
        logger.critical("O script de validacao de dados terminou com um erro critico e inesperado.")
        sys.exit(1) # Garante que o script saia com erro se algo inesperado acontecer
