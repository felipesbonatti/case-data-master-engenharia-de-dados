import os
import sys
import shutil
import time
import logging
from pathlib import Path
from typing import List, Tuple, Optional

"""
====================================================================================
SCRIPT DE CONFIGURACAO E VALIDACAO AUTOMATICA 
====================================================================================

DESCRICAO:
    Este script automatiza o processo de adaptacao de um projeto de engenharia de dados
    desenvolvido em um ambiente local para execucao em qualquer outra
    maquina ou ambiente conteinerizado (e.g., Docker/Linux). Ele realiza a substituicao
    de caminhos de arquivo hardcoded (placeholders), valida a integridade da estrutura
    do projeto resultante e implementa um sistema robusto de backup e rollback automatico
    para garantir a seguranca das operacoes.

OBJETIVO PRINCIPAL:
    - Facilitar a portabilidade do projeto entre diferentes sistemas operacionais e ambientes.
    - Substituir caminhos de arquivo absolutos por caminhos relativos ao ambiente de execucao.
    - Validar a estrutura de diretorios e a presenca de arquivos criticos apos a configuracao.
    - Fornecer um mecanismo de backup para o estado original do projeto.
    - Implementar um rollback automatico em caso de falha na configuracao ou validacao.
    - Gerar um log detalhado de todas as operacoes para auditoria e depuracao.

COMPONENTES E FUNCIONALIDADES:
    - Backup Automatico: Cria uma copia de seguranca do projeto antes de qualquer modificacao.
    - Substituicao de Placeholders: Encontra e atualiza strings de caminho em arquivos de codigo e configuracao.
    - Validacao de Integridade: Verifica a existencia de arquivos e diretorios cruciais apos a configuracao.
    - Rollback Transacional: Restaura o projeto para o estado pre-configuracao em caso de erro.
    - Logging Completo: Todas as etapas, sucessos, avisos e erros sao registrados em um arquivo de log.
    - Gerenciamento de Excecoes: Utiliza excecoes customizadas para erros especificos (BackupError, ConfigurationError).

ARQUITETURA DE ROBUSTEZ:
    - Defesa em Profundidade: Backup + Substituicao + Validacao + Rollback = Alta Resiliencia.
    - Idempotencia (Simulada): O processo e projetado para ser re-executavel, embora um rollback
      seja a melhor pratica para reverter falhas.
    - Compatibilidade: Usa `pathlib` para garantir a compatibilidade de caminhos entre sistemas.
====================================================================================
"""

# ---
# CONFIGURACOES GLOBAIS DO SCRIPT
# ---

class Config:
    """Centraliza todas as configuracoes e parametros do script."""
    
    # Caminho placeholder (hardcoded) no ambiente de desenvolvimento original.
    # Este e o texto que o script ira procurar e substituir.
    PLACEHOLDER_PATH: str = /Users/felps/

    # Nome do arquivo de log para este script de setup.
    LOG_FILE_NAME: str = "setup_configuration.log"

    # Nomes de diretorios/arquivos a serem ignorados durante a busca e backup.
    IGNORED_ITEMS: Tuple[str, ...] = ('venv', 'project_backup_', '.git', '__pycache__', '.pytest_cache', '.env', 'setup_configuration.log')
    
    # Extensoes de arquivo validas para processamento (substituicao de placeholders).
    VALID_EXTENSIONS: Tuple[str, ...] = ('.py', '.cfg', '.json', '.md', '.yml', '.yaml', '.txt', '.sh', '.csv')

    # Caminhos criticos que devem existir apos a configuracao (para validacao).
    CRITICAL_PATHS: List[str] = [
        "airflow.cfg",
        "requirements.txt",
        "dags",
        "plugins/security_system/vault.py", # Caminho do plugin security_system/vault.py
        "plugins/security_system/vault_manager_helper.py", # Caminho do plugin vault_manager_helper.py
        "scripts/setup_vault_secrets.py",
        "configure.py", # O proprio script de configuracao
        # "data/olist/dados_consolidados.csv" 
    ]

# ---
# SETUP DE LOGGING
# ---

# Variavel global para armazenar o diretorio de backup (para uso no rollback).
BACKUP_DIR: Optional[Path] = None

def setup_logging() -> logging.Logger:
    """
    Configura o sistema de logging para o script, direcionando logs para um arquivo
    e para a saida padrao (console).

    Retorna:
        logging.Logger: A instancia do logger configurada.
    """
    # Cria o diretorio para o log se nao existir (se o LOG_FILE_NAME for um caminho com pasta)
    log_file_path = Path(Config.LOG_FILE_NAME)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove handlers existentes para evitar duplicacao em re-execucoes do script
    root_logger = logging.getLogger()
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            handler.close()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        handlers=[
            logging.FileHandler(log_file_path, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging() # Inicializa o logger ao carregar o script

# ---
# EXCECOES CUSTOMIZADAS DO SCRIPT
# ---

class ConfigurationError(Exception):
    """Excecao customizada para erros de configuracao do projeto."""
    pass

class BackupError(Exception):
    """Excecao customizada para erros durante a operacao de backup."""
    pass

# ---
# FUNCOES DE SERVICO
# ---

def create_backup(target_path: Path) -> bool:
    """
    Cria um backup completo do diretorio do projeto antes de qualquer modificacao,
    ignorando arquivos e pastas temporarios/de controle de versao.

    Args:
        target_path (Path): Caminho do diretorio do projeto a ser feito backup.

    Retorna:
        bool: True se o backup foi criado com sucesso, False caso contrario.

    Levanta:
        BackupError: Se houver uma falha critica na criacao do backup.
    """
    global BACKUP_DIR
    BACKUP_DIR = Path(f"project_backup_{int(time.time())}") # Nome unico para a pasta de backup
    
    logger.info(f"[PASSO 1 de 5] Criando backup de seguranca em: '{BACKUP_DIR}'...")
    
    try:
        # Padroes de arquivos/pastas a serem ignorados no backup
        ignore_patterns_func = shutil.ignore_patterns(*Config.IGNORED_ITEMS)
        
        # Copia a arvore de diretorios
        shutil.copytree(str(target_path), str(BACKUP_DIR), ignore=ignore_patterns_func)
        
        # Verifica se o backup foi criado corretamente e nao esta vazio
        if not BACKUP_DIR.exists() or not any(BACKUP_DIR.iterdir()): # Verifica se esta vazio
            raise BackupError("Backup foi criado mas esta vazio ou inacessivel. Verifique permissoes ou conteudo.")
            
        logger.info("Backup criado com sucesso.")
        return True
        
    except Exception as e:
        error_msg = f"Erro critico ao criar backup para '{target_path}': {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise BackupError(error_msg) from e

def get_files_to_process(base_path: Path) -> List[Path]:
    """
    Coleta todos os arquivos no diretorio base e subdiretorios que precisam ter
    placeholders substituidos, ignorando diretorios e extensoes especificas.

    Args:
        base_path (Path): Diretorio base para a busca de arquivos.

    Retorna:
        List[Path]: Lista de objetos Path para os arquivos a serem processados.
    """
    files_to_process: List[Path] = []
    
    for root, dirs, files in os.walk(base_path):
        # Filtra diretorios a serem ignorados no walk
        # `dirs[:]` modifica a lista 'dirs' in-place, controlando o que os.walk visita
        dirs[:] = [d for d in dirs if d not in Config.IGNORED_ITEMS and not any(ign_prefix in d for ign_prefix in ('project_backup_', '.git'))]
        
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in Config.VALID_EXTENSIONS:
                files_to_process.append(file_path)
                
    logger.info(f"Encontrados {len(files_to_process)} arquivos para processamento de placeholders.")
    return files_to_process

def configure_paths(target_path: Path) -> int:
    """
    Encontra e substitui os placeholders de caminho nos arquivos do projeto.
    O placeholder `Config.PLACEHOLDER_PATH` e substituido pelo `target_path`.

    Args:
        target_path (Path): O novo caminho base para substituicao (caminho absoluto do projeto).

    Retorna:
        int: O numero de arquivos que foram modificados.

    Levanta:
        ConfigurationError: Se houver um erro na configuracao dos caminhos.
    """
    logger.info("\n[PASSO 2 de 5] Substituindo placeholders de caminho...")
    logger.info("Iniciando substituicao de placeholders nos arquivos.")
    
    # Normaliza o caminho para usar barras '/' (compatibilidade cross-platform)
    target_path_normalized = str(target_path).replace('\\', '/')
    
    logger.info(f"Placeholder a ser substituido: '{Config.PLACEHOLDER_PATH}'")
    logger.info(f"Novo caminho de destino:         '{target_path_normalized}'")
    
    try:
        files_to_process = get_files_to_process(Path('.')) # Busca no diretorio atual do script
        files_changed = 0
        
        for file_path in files_to_process:
            try:
                # Le o arquivo com encoding explicito e tratamento de erros
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # So modifica se o placeholder estiver presente no conteudo do arquivo
                if Config.PLACEHOLDER_PATH in content:
                    new_content = content.replace(Config.PLACEHOLDER_PATH, target_path_normalized)
                    
                    # Escreve o arquivo modificado
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    files_changed += 1
                    logger.info(f"Placeholder substituido em: '{file_path}'")
                    
            except (UnicodeDecodeError, PermissionError) as e:
                logger.warning(f"Nao foi possivel processar o arquivo '{file_path}' devido a permissao ou encoding: {str(e)}")
                continue # Continua para o proximo arquivo
            except Exception as e:
                error_msg = f"Erro inesperado ao processar o arquivo '{file_path}': {str(e)}"
                logger.error(error_msg, exc_info=True)
                raise ConfigurationError(error_msg) from e

        logger.info(f"Configuracao de caminhos concluida: {files_changed} arquivos modificados.")
        return files_changed
        
    except Exception as e:
        error_msg = f"Falha geral na configuracao de caminhos: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise ConfigurationError(error_msg) from e

def validate_setup(target_path: Path) -> Tuple[bool, List[str]]:
    """
    Verifica se a estrutura do projeto e arquivos criticos estao corretamente configurados
    e se todos os placeholders foram substituidos.

    Args:
        target_path (Path): Caminho base do projeto a ser validado.

    Retorna:
        Tuple[bool, List[str]]: Uma tupla contendo:
            - bool: True se a validacao passou, False caso contrario.
            - List[str]: Uma lista de problemas encontrados durante a validacao.
    """
    logger.info("\n[PASSO 3 de 5] Validando a nova configuracao...")
    logger.info("Iniciando validacao da configuracao do projeto.")
    
    problems: List[str] = []
    all_valid: bool = True
    
    # 1. Validacao de presenca de arquivos/pastas criticas
    logger.info("Verificando componentes criticos do projeto...")
    for path_str in Config.CRITICAL_PATHS:
        expected_path = target_path / path_str
        
        if expected_path.exists():
            logger.info(f"OK: Componente critico encontrado: '{path_str}'")
        else:
            problem = f"Componente critico AUSENTE: '{path_str}' (Caminho esperado: '{expected_path}')"
            logger.error(f"FALHA: {problem}")
            problems.append(problem)
            all_valid = False
            
    # 2. Validacao adicional: verifica se placeholders foram completamente substituidos
    logger.info("Verificando se todos os placeholders foram completamente substituidos...")
    files_with_placeholders = check_remaining_placeholders()
    
    if files_with_placeholders:
        logger.error("Placeholders restantes encontrados nos seguintes arquivos:")
        for fp in files_with_placeholders:
            problem = f"Placeholder '{Config.PLACEHOLDER_PATH}' ainda presente em: '{fp}'"
            logger.error(f"FALHA: Placeholder restante em '{fp}'")
            problems.append(problem)
        all_valid = False
    else:
        logger.info("Nenhum placeholder restante encontrado nos arquivos processados.")
        
    validation_status = "SUCESSO" if all_valid else "FALHA"
    logger.info(f"Validacao concluida com status: {validation_status}. Problemas: {len(problems)}")
    
    return all_valid, problems

def check_remaining_placeholders() -> List[Path]:
    """
    Verifica se ainda existem placeholders nao substituidos nos arquivos do projeto.

    Retorna:
        List[Path]: Uma lista de objetos Path para os arquivos que ainda contem o placeholder.
    """
    files_with_placeholders: List[Path] = []
    
    try:
        files_to_check = get_files_to_process(Path('.')) # Busca no diretorio atual
        
        for file_path in files_to_check:
            try:
                # Le o arquivo com tratamento de erro
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    if Config.PLACEHOLDER_PATH in f.read():
                        files_with_placeholders.append(file_path)
            except (UnicodeDecodeError, PermissionError) as e:
                logger.warning(f"Nao foi possivel ler o arquivo '{file_path}' para verificar placeholders: {str(e)}")
                continue # Continua para o proximo arquivo
            except Exception as e:
                logger.error(f"Erro inesperado ao verificar placeholders em '{file_path}': {str(e)}", exc_info=True)
                continue # Continua, mas loga o erro
    except Exception as e:
        logger.error(f"Erro geral ao coletar arquivos para verificar placeholders: {str(e)}", exc_info=True)
        
    return files_with_placeholders

def rollback_changes() -> bool:
    """
    Restaura o projeto para o estado original a partir do backup em caso de falha.

    Retorna:
        bool: True se o rollback foi bem-sucedido, False caso contrario.
    """
    logger.warning("\n[ACAO DE EMERGENCIA] Iniciando rollback...")
    
    global BACKUP_DIR # Acessa a variavel global do diretorio de backup

    if not BACKUP_DIR or not BACKUP_DIR.exists():
        error_msg = f"Impossivel fazer rollback: pasta de backup '{BACKUP_DIR}' nao encontrada ou nao definida."
        logger.error(error_msg)
        return False

    try:
        logger.info(f"Restaurando a partir de '{BACKUP_DIR}'...")
        
        # Lista todos os itens no diretorio atual para remocao, excluindo o proprio diretorio de backup e o arquivo de log
        items_to_remove = [item for item in Path('.').iterdir() if item != BACKUP_DIR and item.name != Path(Config.LOG_FILE_NAME).name]
        for item in items_to_remove:
            if item.is_dir():
                shutil.rmtree(str(item))
            else:
                item.unlink() # Remove arquivo
        
        # Move o conteudo do backup para o diretorio atual
        for item in BACKUP_DIR.iterdir():
            source = item
            destination = Path('.') / item.name
            shutil.move(str(source), str(destination))
        
        # Remove a pasta de backup apos a restauracao
        shutil.rmtree(str(BACKUP_DIR))
        
        logger.info("Rollback concluido. Projeto restaurado ao estado original.")
        return True
        
    except Exception as e:
        error_msg = f"ERRO CRITICO durante o rollback: {str(e)}"
        logger.critical(error_msg, exc_info=True)
        return False

def cleanup_successful_setup() -> None:
    """
    Realiza a limpeza de arquivos temporarios e pastas de backup apos
    uma configuracao bem-sucedida. O backup e mantido para revisao manual.
    """
    logger.info("\n[PASSO 4 de 5] Limpeza pos-configuracao...")
    
    global BACKUP_DIR

    try:
        if BACKUP_DIR and BACKUP_DIR.exists():
            logger.info(f"Backup mantido em '{BACKUP_DIR}' (remova manualmente se desejar).")
            # Em um cenario real, poderiamos ter uma opcao para remover o backup automaticamente
            # shutil.rmtree(str(BACKUP_DIR))
            # logger.info(f"Pasta de backup '{BACKUP_DIR}' removida.")
            
        logger.info("Limpeza pos-configuracao concluida.")
        
    except Exception as e:
        logger.warning(f"Erro na limpeza pos-configuracao: {str(e)}", exc_info=True)

def generate_setup_report(files_changed: int, validation_passed: bool, problems: List[str]) -> None:
    """
    Gera um relatorio final da configuracao, sumarizando o processo
    e o status da validacao.

    Args:
        files_changed (int): Numero de arquivos que foram modificados.
        validation_passed (bool): True se a validacao final passou, False caso contrario.
        problems (List[str]): Lista de problemas encontrados durante a validacao.
    """
    logger.info(f"\n[PASSO 5 de 5] Relatorio de Configuracao")
    logger.info("=" * 50)
    logger.info(f"Projeto:        {os.path.basename(os.getcwd())}")
    logger.info(f"Arquivos alterados: {files_changed}")
    logger.info(f"Validacao:      {'PASSOU' if validation_passed else 'FALHOU'}")
    
    if problems:
        logger.warning("Problemas encontrados:")
        for problem in problems:
            logger.warning(f"- {problem}")
            
    logger.info(f"Log detalhado:  {Config.LOG_FILE_NAME}")
    logger.info("=" * 50)
    
    logger.info(f"Relatorio final - Arquivos modificados: {files_changed}, Validacao: {'PASSOU' if validation_passed else 'FALHOU'}, Problemas: {len(problems)}")

# ---
# FUNCAO PRINCIPAL DO SCRIPT
# ---

def main() -> None:
    """
    Funcao principal que orquestra o processo de configuracao e validacao automatica.
    Implementa um fluxo com backup, configuracao, validacao, limpeza e rollback em caso de falha.
    """
    logger.info("--- Script de Configuracao e Validacao Automatica ---")
    logger.info("Versao Enterprise com Backup e Rollback Automatico")
    
    start_time = time.time()
    current_path = Path(os.getcwd())
    
    # Validacao inicial: verifica se o script esta sendo executado da raiz do projeto
    if not (current_path / "configure.py").exists():
        error_msg = "ERRO: Execute este script a partir da pasta raiz do projeto (onde 'configure.py' esta localizado)."
        logger.error(error_msg)
        sys.exit(1)
        
    logger.info("=== INICIO DA CONFIGURACAO AUTOMATICA ===")
    logger.info(f"Diretorio de trabalho atual: '{current_path}'")
    
    try:
        # 1. Passo de Backup
        logger.info("Iniciando Passo 1: Criacao de Backup.")
        create_backup(current_path)
        
        # 2. Passo de Configuracao (substituicao de caminhos)
        logger.info("Iniciando Passo 2: Configuracao de Caminhos.")
        files_changed = configure_paths(current_path)
        
        # 3. Passo de Validacao
        logger.info("Iniciando Passo 3: Validacao da Configuracao.")
        validation_passed, problems = validate_setup(current_path)
        
        # Se a validacao falhou, levanta um erro para disparar o rollback
        if not validation_passed:
            raise ConfigurationError(f"Validacao falhou. Problemas: {'; '.join(problems)}")
            
        # 4. Passo de Limpeza (apos sucesso)
        logger.info("Iniciando Passo 4: Limpeza Pos-Configuracao.")
        cleanup_successful_setup()
        
        # 5. Passo de Relatorio
        logger.info("Iniciando Passo 5: Geracao de Relatorio.")
        generate_setup_report(files_changed, validation_passed, problems)
        
        # Sucesso final!
        elapsed_time = time.time() - start_time
        logger.info(f"CONFIGURACAO CONCLUIDA COM SUCESSO em {elapsed_time:.1f} segundos!")
        logger.info("Proximos passos:")
        logger.info("1. Criar ambiente virtual: `python -m venv venv`")
        logger.info("2. Ativar ambiente: `source venv/bin/activate` (Linux/Mac) ou `.\\venv\\Scripts\\activate` (Windows PowerShell)")
        logger.info("3. Instalar dependencias: `pip install -r requirements.txt`")
        logger.info("4. Configurar suas credenciais reais no Vault (se ainda nao fez): `python scripts/setup_vault_secrets.py`")
        
        logger.info(f"=== CONFIGURACAO CONCLUIDA COM SUCESSO em {elapsed_time:.1f}s ===")
        
    except (BackupError, ConfigurationError) as e:
        # Captura erros especificos de backup ou configuracao que exigem rollback
        logger.error(f"Erro durante a configuracao: {str(e)}")
        logger.error(f"Erro na configuracao, executando rollback: {str(e)}", exc_info=True)
        
        # Tentativa de rollback automatico
        if rollback_changes():
            logger.info("Sistema restaurado ao estado original via rollback automatico.")
        else:
            logger.critical(f"ATENCAO: Rollback falhou. Restaure manualmente a partir de '{BACKUP_DIR}'")
        
        sys.exit(1) # Sai com codigo de erro
        
    except Exception as e:
        # Captura qualquer outro erro inesperado e fatal
        logger.critical(f"Erro inesperado no script configure.py: {str(e)}", exc_info=True)
        
        # Rollback em caso de erro inesperado antes de sair
        if rollback_changes():
            logger.info("Sistema restaurado ao estado original via rollback automatico.")
        else:
            logger.critical(f"ATENCAO: Rollback falhou. Restaure manualmente a partir de '{BACKUP_DIR}'")
        sys.exit(1) # Sai com codigo de erro

# ---
# PONTO DE ENTRADA PRINCIPAL DO SCRIPT
# ---

if __name__ == "__main__":
    main()
