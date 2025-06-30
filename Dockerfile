# ===================================================================================
# DOCKERFILE: AMBIENTE APACHE AIRFLOW COM PYSPARK E MINIO/S3 
# ===================================================================================

# DESCRICAO:
# Este Dockerfile constroi a imagem Docker personalizada para os Workers e o Webserver
# do Apache Airflow em um ambiente de Engenharia de Dados. Ele instala todas as
# dependencias necessarias para executar DAGs que interagem com PySpark e MinIO/S3,
# garantindo um ambiente robusto, seguro e performatico para o processamento de Big Data.

# OBJETIVO PRINCIPAL:
# - Fornecer uma imagem base contendo Apache Airflow.
# - Instalar Java Runtime Environment (JRE) para compatibilidade com Apache Spark.
# - Baixar JARs necessarias para a integracao do Spark com S3A/MinIO.
# - Instalar pacotes Python adicionais (definidos em requirements.txt) para pipelines de dados.
# - Configurar variaveis de ambiente essenciais para o funcionamento do Spark e do sistema.
# - Implementar praticas de seguranca basicas para imagens Docker.

# COMPONENTES INSTALADOS:
# - Base: Imagem oficial do Apache Airflow (Python 3.11).
# - Runtime: OpenJDK Java Runtime Environment (JRE).
# - Ferramentas de Rede: `netcat-traditional` para health checks e `wget` para downloads.
# - JARs Spark S3A: `hadoop-aws.jar` e `aws-java-sdk-bundle.jar` para conectividade Spark-S3/MinIO.
# - Dependencias Python: Pacotes definidos em `requirements.txt` (Pandas, Great Expectations, etc.).

# ARQUITETURA DE CAMADAS DA IMAGEM:
# - Otimizacao de Cache: As instrucoes sao ordenadas para aproveitar o cache de camadas do Docker,
#   reconstruindo apenas as camadas que sofreram alteracoes.
# - Reducao de Tamanho: Comandos `apt-get clean` e `rm -rf` minimizam o tamanho final da imagem.

# SEGURANCA E BOAS PRATICAS:
# - Usuario Root Temporario: Operacoes que exigem privilegios de root (instalacao de pacotes)
#   sao feitas sob o usuario `root`, voltando para o usuario `airflow` padrao em seguida.
# - Variaveis de Ambiente: `JAVA_HOME` e configurado explicitamente para o Spark.
# - PATH para Spark-Submit: Garante que o `spark-submit` seja encontrado e executavel.
# ===================================================================================

# Inicia a partir da imagem oficial do Airflow com Python 3.11
# Esta e a base que ja contem o Airflow e suas dependencias essenciais.
FROM apache/airflow:2.9.2-python3.11

# Mudar para o usuario root temporariamente para poder instalar pacotes de sistema e baixar JARs.
USER root

# Instala pacotes de sistema necessarios:
# - default-jre-headless: Java Runtime Environment, essencial para o PySpark e suas dependencias.
# - wget: Utilizado para baixar as JARs do Maven Central.
# - netcat-traditional: Ferramenta de rede simples, comumente usada para health checks de servicos.
# - --no-install-recommends: Reduz o numero de pacotes instalados para manter a imagem mais leve.
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless \
    wget \
    netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configura a variavel de ambiente JAVA_HOME que o Spark precisa para encontrar sua instalacao Java.
ENV JAVA_HOME=/usr/lib/jvm/default-java

# Baixa as JARs do hadoop-aws e aws-java-sdk-bundle para o diretorio `/opt/airflow/jars/`.
# Estas JARs sao necessarias para o Spark acessar o MinIO/S3 usando o protocolo `s3a://`.
# - hadoop-aws: Conector do Hadoop para AWS S3 (compativel com MinIO).
# - aws-java-sdk-bundle: SDK Java da AWS, dependencia do hadoop-aws.
RUN mkdir -p /opt/airflow/jars/ && \
    wget https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-aws/3.3.1/hadoop-aws-3.3.1.jar -P /opt/airflow/jars/ && \
    wget https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-bundle/1.11.901/aws-java-sdk-bundle-1.11.901.jar -P /opt/airflow/jars/

# Volta para o usuario padrao do Airflow (`airflow`) para operacoes subsequentes.
# Esta e uma pratica de seguranca crucial para evitar que o processo principal do Airflow
# e suas tarefas sejam executados com privilegios desnecessarios de root.
USER airflow

# ADICIONA O DIRETORIO DOS EXECUTAVEIS DO PIP (`.local/bin`) AO PATH DO SISTEMA.
# Isso garante que ferramentas instaladas via `pip` (como `spark-submit` quando o PySpark e instalado)
# sejam encontradas e executaveis pelo shell sem a necessidade de um caminho absoluto,
# facilitando a execucao de comandos Spark dentro dos conteineres Airflow.
# Este e um passo CRITICO para a compatibilidade do PySpark.
ENV PATH="/home/airflow/.local/bin:${PATH}"

# Copia o arquivo de requerimentos Python para dentro da imagem Docker.
# O `requirements.txt` deve listar todas as bibliotecas Python que suas DAGs e scripts PySpark precisam.
COPY requirements.txt /requirements.txt

# Instala os pacotes Python listados no arquivo `requirements.txt`.
# - --no-cache-dir: Desabilita o cache de pacotes pip para reduzir o tamanho final da imagem Docker.
# Certifique-se de que o `requirements.txt` contenha: `apache-airflow[cncf.kubernetes, celery, postgres, redis, s3]`
# (ou os extras relevantes para sua configuracao), `pyspark`, `pandas`, `minio`, `psycopg2`, `sqlalchemy`, `cryptography`, `python-dotenv`, `faker`, `numpy`.
RUN pip install --no-cache-dir -r /requirements.txt
