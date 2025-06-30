import logging
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

"""
====================================================================================
MÓDULO: MONITORAMENTO DE SEGURANÇA E PERFORMANCE
====================================================================================

DESCRIÇÃO:
    Este módulo implementa um sistema de monitoramento de segurança e performance,
    projetado para detectar anomalias e atividades incomuns em um ambiente de
    engenharia de dados. Ele atua como um "sentinela", registrando eventos chave
    e verificando padrões que podem indicar potenciais ameaças à segurança ou
    problemas de performance do sistema.

ARQUITETURA DE MONITORAMENTO:
    - Registro de Atividades: Loga eventos de segurança e performance em um arquivo dedicado.
    - Detecção de Anomalias: Analisa padrões nos logs para identificar comportamentos incomuns.
    - Monitoramento de Recursos: Acompanha métricas de sistema como CPU e memória (simulado/placeholder).
    - Alertas: Emite avisos quando limiares são excedidos ou anomalias são detectadas.

COMPONENTES E FUNCIONALIDADES:
    - SecurityMonitor Class: Classe principal para o gerenciamento do monitoramento.
    - log_event: Registra eventos de segurança com detalhes estruturados.
    - check_unusual_activity: Verifica a ocorrência de múltiplos eventos específicos
      em um curto período, indicando atividade suspeita (ex: tentativas de login falhas).
    - get_cpu_usage / get_memory_usage: Métodos placeholder para integração futura
      com ferramentas de monitoramento de recursos reais.
    - check_memory_threshold: Alerta quando o uso de memória excede um limite predefinido.
    - Logging Robusto: Utiliza o módulo `logging` do Python para garantir o registro persistente
      e configurável dos eventos de monitoramento.

SEGURANÇA E ROBUSTEZ:
    - Rastreabilidade: Cria um registro cronológico de eventos de segurança.
    - Detecção Proativa: Ajuda a identificar padrões que podem preceder um incidente de segurança.
    - Resiliência: Tratamento de erros ao lidar com arquivos de log e parsear informações.
    - Paths Flexíveis: Suporte a paths de log configuráveis via variável de ambiente.
====================================================================================
"""

class SecurityMonitor:
    """
    Gerencia o monitoramento de segurança e performance do sistema,
    registrando eventos e detectando atividades incomuns ou violações de limiares.
    """

    def __init__(self, monitor_log_path: Optional[str] = None):
        """
        Inicializa o SecurityMonitor.

        Args:
            monitor_log_path (Optional[str]): Caminho para o diretório ou arquivo de log de monitoramento.
                                             Se None, tenta usar a variável de ambiente 'SECURITY_MONITOR_LOG_PATH'
                                             ou um caminho padrão.
        """
        # Define o caminho base para os logs de monitoramento
        self.monitor_log_path: Path = Path(monitor_log_path or os.getenv('SECURITY_MONITOR_LOG_PATH', '/opt/airflow/logs/security_monitor'))

        # Garante que o diretório de log exista
        log_dir_to_create = self.monitor_log_path if self.monitor_log_path.is_dir() else self.monitor_log_path.parent
        if not log_dir_to_create.exists():
            try:
                log_dir_to_create.mkdir(parents=True, exist_ok=True)
                logger.info(f"SecurityMonitor: Diretorio de log '{log_dir_to_create}' criado.")
            except OSError as e:
                logger.error(f"SecurityMonitor: Erro critico ao criar diretorio de log '{log_dir_to_create}': {e}")

        # Define o caminho completo do arquivo de log, com rotação diária se for um diretorio
        if self.monitor_log_path.is_dir():
            self.log_file: Path = self.monitor_log_path / f"security_activity_{datetime.now().strftime('%Y-%m-%d')}.log"
        else:
            self.log_file: Path = self.monitor_log_path # Caminho ja e um arquivo especifico

        self._initialize_logger()
        self.logger.info("SecurityMonitor inicializado com sucesso.")

    def _initialize_logger(self) -> None:
        """
        Configura o logger interno do Python para registrar eventos de monitoramento de seguranca.
        Adiciona um FileHandler para escrever logs no arquivo definido.
        """
        self.logger = logging.getLogger('security_system.SecurityMonitor')
        self.logger.propagate = False # Evita que os logs sejam duplicados por handlers da raiz
        self.logger.setLevel(logging.INFO)

        # Remove handlers existentes para evitar duplicação em re-inicializações do Airflow
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        # Adiciona o handler de arquivo
        try:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler = logging.FileHandler(self.log_file, encoding='utf-8', mode='a')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            self.logger.info(f"FileHandler configurado para logs de monitoramento em: {self.log_file}")
        except Exception as e:
            self.logger.critical(f"SecurityMonitor: Falha critica ao inicializar FileHandler para '{self.log_file}': {e}", exc_info=True)
            # Fallback para StreamHandler se o FileHandler falhar
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            self.logger.error("Falha ao configurar FileHandler, usando StreamHandler como fallback.")

    def log_event(self, event_type: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Registra um evento de seguranca ou performance no log de monitoramento.

        Args:
            event_type (str): O tipo do evento (ex: "LOGIN_FAILURE", "RESOURCE_ALERT").
            message (str): Uma mensagem descritiva do evento.
            details (Optional[Dict[str, Any]]): Um dicionario com detalhes adicionais do evento.
        """
        log_message = f"EVENT: {event_type} - {message}"
        if details:
            try:
                # Tenta serializar o dicionario 'details' para JSON para logs estruturados
                log_message += f" - Details: {json.dumps(details, ensure_ascii=False)}"
            except TypeError as e:
                # Fallback se 'details' nao for serializavel em JSON
                log_message += f" - Details (non-JSON serializable): {details} (Error: {e})"
                self.logger.error(f"Detalhes do log_event nao serializaveis em JSON para '{event_type}': {details}", exc_info=True)

        # Verifica se o logger e seus handlers estao operacionais antes de tentar logar
        if self.logger.handlers:
            self.logger.info(log_message)
        else:
            # Em caso de falha critica do logger, loga no console diretamente
            logging.critical(f"LOG_EVENT_FALLBACK (SecurityMonitor): Logger nao configurado. {log_message}")

    def check_unusual_activity(self, threshold_count: int = 3, time_frame_minutes: int = 5, activity_type: str = "login_failure") -> bool:
        """
        Verifica se ha atividade incomum baseada na frequencia de um tipo de evento.
        Por exemplo, multiplos 'login_failure' em um curto periodo.

        Args:
            threshold_count (int): O numero minimo de ocorrencias para considerar uma atividade incomum.
            time_frame_minutes (int): O periodo de tempo (em minutos) para verificar as ocorrencias.
            activity_type (str): O tipo de string para buscar nas linhas do log (ex: "LOGIN_FAILURE").

        Returns:
            bool: True se atividade incomum for detectada, False caso contrario.
        """
        now = datetime.now()
        recent_logs = []
        
        if not self.log_file.exists():
            self.logger.warning(f"Arquivo de log '{self.log_file}' nao encontrado para verificacao de atividade incomum.")
            return False

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if activity_type in line:
                        try:
                            # A linha de log padrao do Python e 'YYYY-MM-DD HH:MM:SS,ms - NAME - LEVEL - MESSAGE'
                            # Extrair a parte da data/hora corretamente
                            # Ex: '2025-06-10 10:30:00,123'
                            log_time_str_full = line.split(' - ')[0]
                            # Remove a parte dos milissegundos e parseia
                            log_time = datetime.strptime(log_time_str_full.split(',')[0], '%Y-%m-%d %H:%M:%S')
                            
                            if now - log_time < timedelta(minutes=time_frame_minutes):
                                recent_logs.append(line)
                        except (ValueError, IndexError) as e:
                            # Ignorar linhas que nao seguem o formato de timestamp esperado
                            self.logger.debug(f"Linha de log com formato inesperado ou erro de parse: '{line.strip()}'. Erro: {e}")
                            continue

                if len(recent_logs) >= threshold_count:
                    details_unusual = {
                        "activity_type": activity_type,
                        "occurrence_count": len(recent_logs),
                        "threshold_count": threshold_count,
                        "time_frame_minutes": time_frame_minutes,
                        "recent_logs_sample": recent_logs[:min(5, len(recent_logs))] # Amostra para evitar logs muito longos
                    }
                    self.logger.warning(
                        f"EVENT: UNUSUAL_ACTIVITY_DETECTED - Multiplas ocorrencias de '{activity_type}' detectadas.",
                        extra={'details': details_unusual}
                    )
                    return True
                else:
                    self.logger.info(f"Nenhuma atividade incomum do tipo '{activity_type}' detectada. Ocorrencias: {len(recent_logs)}.")
                    return False

        except FileNotFoundError:
            self.logger.error(f"Arquivo de log '{self.log_file}' nao encontrado durante a verificacao de atividade incomum.", exc_info=True)
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar atividade incomum do tipo '{activity_type}': {e}", exc_info=True)
            return False

    def get_cpu_usage(self) -> float:
        """
        Simula a obtencao do uso atual da CPU.
        Em um ambiente de producao, esta funcao integraria com ferramentas de monitoramento
        do sistema operacional (ex: psutil, cgroups, APIs de cloud provider).

        Returns:
            float: Uso simulado da CPU em porcentagem.
        """
        self.log_event("SYSTEM_MONITOR_CPU", "Requisicao de uso de CPU (placeholder).")
        # Placeholder para integracao real: return psutil.cpu_percent(interval=1)
        return 10.5 # Valor simulado

    def get_memory_usage(self) -> float:
        """
        Simula a obtencao do uso atual da memoria.
        Em um ambiente de producao, esta funcao integraria com ferramentas de monitoramento
        do sistema operacional (ex: psutil, cgroups, APIs de cloud provider).

        Returns:
            float: Uso simulado da memoria em MB.
        """
        self.log_event("SYSTEM_MONITOR_MEMORY", "Requisicao de uso de memoria (placeholder).")
        # Placeholder para integracao real: return psutil.virtual_memory().used / (1024 * 1024)
        return 256.0 # Valor simulado em MB

    def check_memory_threshold(self, threshold_mb: float, alert_percentage: float = 80.0) -> bool:
        """
        Verifica se o uso de memoria excede um limiar predefinido.

        Args:
            threshold_mb (float): O limiar maximo de memoria permitido em MB.
            alert_percentage (float): Porcentagem do limiar para disparar um alerta (e.g., 80% do threshold).

        Returns:
            bool: True se o uso de memoria exceder o limiar, False caso contrario.
        """
        used_mb_simulated = self.get_memory_usage()
        
        # Calcular o limite de alerta real, se aplicavel
        alert_threshold = threshold_mb * (alert_percentage / 100.0)

        details_mem = {
            "used_mb": used_mb_simulated,
            "configured_threshold_mb": threshold_mb,
            "alert_percentage": alert_percentage,
            "alert_threshold_mb": alert_threshold
        }
        
        if used_mb_simulated > threshold_mb:
            self.logger.warning(
                f"EVENT: MEMORY_THRESHOLD_EXCEEDED - Uso de memoria simulado {used_mb_simulated:.2f}MB EXCEDEU o limiar de {threshold_mb:.2f}MB.",
                extra={'details': details_mem}
            )
            return True
        elif used_mb_simulated > alert_threshold:
            self.logger.warning(
                f"EVENT: MEMORY_USAGE_HIGH - Uso de memoria simulado {used_mb_simulated:.2f}MB esta ALTO, acima de {alert_percentage:.0f}% do limiar de {threshold_mb:.2f}MB.",
                extra={'details': details_mem}
            )
            return False # Ainda nao excedeu o limite maximo, mas esta alto
        else:
            self.logger.info(
                f"EVENT: MEMORY_CHECK_OK - Uso de memoria simulado {used_mb_simulated:.2f}MB esta DENTRO do limiar de {threshold_mb:.2f}MB.",
                extra={'details': details_mem}
            )
            return False
