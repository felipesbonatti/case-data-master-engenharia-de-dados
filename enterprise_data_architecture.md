# Arquitetura de Dados Enterprise

## Resumo 

Esta documentação descreve a arquitetura da plataforma de dados, dividida em três visões principais para maior clareza: **Fluxo de Dados**, **Segurança** e **Governança**. Essa abordagem com múltiplas visões permite uma análise detalhada de cada pilar da solução, facilitando o entendimento, a manutenção e a evolução do projeto.

---

## 1. Visão Geral: Fluxo de Dados (Data Flow View)

### Objetivo
Este diagrama mostra o fluxo principal de valor, desde a ingestão dos dados de múltiplas fontes até a entrega de insights nos dashboards de BI. Ele representa a jornada do dado através das camadas da **Arquitetura Medallion**, focando na movimentação, transformação e enriquecimento progressivo dos dados.

### Características Principais
- **Arquitetura em Camadas**: Implementação do padrão Medallion (Bronze, Silver, Gold)
- **Orquestração Centralizada**: Apache Airflow para gerenciamento de pipelines
- **Múltiplas Fontes de Dados**: APIs externas e datasets estruturados
- **Entrega Multi-Canal**: Dashboards executivos e analíticos

```mermaid
graph TD
    subgraph "Fontes de Dados"
        API_BC["API Banco Central<br/>(IPCA, Selic)"]
        API_WEATHER["API Meteorologia<br/>(Dados Climáticos)"]
        DS_OLIST["Dataset Olist<br/>(Dados Transacionais)"]
    end

    subgraph "Orquestração (Apache Airflow)"
        INGESTION["Pipeline de Ingestão<br/>Coleta e Validação Inicial"]
        TRANSFORMATION["Pipeline de Transformação<br/>Limpeza, Mascaramento PII, Processamento Spark"]
        LOAD["Pipeline de Carga<br/>Carga no DW e Star Schema"]
    end

    subgraph "Armazenamento (MinIO & PostgreSQL)"
        BRONZE["<b>BRONZE</b><br/>(Dados Brutos)"]
        SILVER["<b>SILVER</b><br/>(Dados Limpos)"]
        GOLD["<b>GOLD</b><br/>(Dados Agregados)"]
        DWH["<b>DATA WAREHOUSE</b><br/>(PostgreSQL - Star Schema)"]
    end

    subgraph "Consumo de BI"
        GRAFANA["Dashboard Executivo<br/>(Grafana)"]
        STREAMLIT["Dashboard Analítico<br/>(Streamlit)"]
    end

    %% --- Conexões do Fluxo Principal ---
    API_BC --> INGESTION
    API_WEATHER --> INGESTION
    DS_OLIST --> INGESTION
    
    INGESTION --> BRONZE
    BRONZE --> TRANSFORMATION
    TRANSFORMATION --> SILVER
    SILVER --> GOLD
    GOLD --> LOAD
    LOAD --> DWH
    DWH --> GRAFANA
    DWH --> STREAMLIT
    
    %% --- Estilo ---
    classDef fontes fill:#1565C0,stroke:#0D47A1,color:white,font-weight:bold
    classDef orquestracao fill:#2E7D32,stroke:#1B5E20,color:white,font-weight:bold
    classDef armazenamento fill:#E65100,stroke:#BF360C,color:white,font-weight:bold
    classDef consumo fill:#7B1FA2,stroke:#4A148C,color:white,font-weight:bold

    class API_BC,API_WEATHER,DS_OLIST fontes
    class INGESTION,TRANSFORMATION,LOAD orquestracao
    class BRONZE,SILVER,GOLD,DWH armazenamento
    class GRAFANA,STREAMLIT consumo
```

---

## 2. Visão de Segurança (Security View)

### Objetivo
A segurança nesta arquitetura não é uma etapa, mas um **pilar transversal** que sustenta todo o processo. Este diagrama ilustra como os componentes do Framework de Segurança Customizado se integram e protegem o pipeline em pontos críticos.

### Componentes de Segurança
- **Enterprise Vault Manager**: Gerenciamento centralizado de credenciais e secrets
- **PII Protection Service**: Serviço de proteção e mascaramento de dados pessoais
- **Secure Connection Pool**: Pool de conexões seguras para todos os endpoints

### *"Como garantimos a confidencialidade, integridade e disponibilidade dos dados em cada etapa do fluxo?"*

```mermaid
graph TD
    subgraph "Framework de Segurança"
        SEC_VAULT["Enterprise Vault Manager<br/>🔐 Gerenciamento de Credenciais"]
        SEC_PII["PII Protection Service<br/>🛡️ Proteção de Dados Pessoais"]
        SEC_CONN["Secure Connection Pool<br/>🔗 Conexões Seguras"]
    end
    
    subgraph "Componentes do Pipeline"
        INGESTION["Pipeline de Ingestão<br/>📥 DAGs de Coleta"]
        TRANSFORMATION["Processamento Spark<br/>⚙️ DAG de Transformação"]
        LOAD["Carga no DW<br/>📤 DAG de Load"]
    end

    subgraph "Controles de Segurança"
        AUTH["Autenticação<br/>Multi-Fator"]
        ENCRYPT["Criptografia<br/>End-to-End"]
        AUDIT["Auditoria<br/>em Tempo Real"]
    end

    %% --- Conexões de Segurança ---
    SEC_VAULT -.->|"Fornece Credenciais"| INGESTION
    SEC_VAULT -.->|"Fornece Credenciais"| TRANSFORMATION
    SEC_VAULT -.->|"Fornece Credenciais"| LOAD
    
    SEC_PII -.->|"Aplica Mascaramento"| TRANSFORMATION
    SEC_CONN -.->|"Garante Conexão Segura"| LOAD
    
    AUTH -.->|"Protege"| SEC_VAULT
    ENCRYPT -.->|"Protege"| SEC_CONN
    AUDIT -.->|"Monitora"| SEC_PII
    
    %% --- Estilos ---
    classDef security fill:#7B1FA2,stroke:#4A148C,color:white,font-weight:bold
    classDef pipeline fill:#2E7D32,stroke:#1B5E20,color:white,font-weight:bold
    classDef controls fill:#D32F2F,stroke:#B71C1C,color:white,font-weight:bold

    class SEC_VAULT,SEC_PII,SEC_CONN security
    class INGESTION,TRANSFORMATION,LOAD pipeline
    class AUTH,ENCRYPT,AUDIT controls
```

---

## 3. Visão de Governança e Qualidade (Governance & Quality View)

### Objetivo
A confiança nos dados é o ativo mais valioso gerado por este pipeline. Esta visão detalha os mecanismos de **Governança e Garantia de Qualidade** implementados, mostrando como a validação automatizada e uma trilha de auditoria completa garantem a exatidão e conformidade dos dados.

### Componentes de Governança
- **Great Expectations**: Framework de validação e teste de qualidade de dados
- **Compliance Audit Engine**: Motor de auditoria e conformidade regulatória
- **Data Quality Gates**: Portões de qualidade automatizados no pipeline

### Benefícios
- **Confiabilidade**: Dados validados em cada etapa
- **Rastreabilidade**: Trilha completa de auditoria
- **Automação**: Validação sem intervenção manual
- **Conformidade**: Aderência às políticas de governança

```mermaid
graph TD
    subgraph "Ferramentas de Governança"
        GE_SUITE["Great Expectations<br/>📋 Validação de Qualidade"]
        SEC_AUDIT["Compliance Audit Engine<br/>🔍 Motor de Auditoria"]
        DQ_GATES["Data Quality Gates<br/>🚪 Portões de Qualidade"]
    end
    
    subgraph "Etapas do Pipeline"
        TRANSFORMATION["Processamento Spark<br/>⚙️ DAG de Transformação"]
        LOAD["Carga no DW<br/>📤 DAG de Load"]
        VALIDATION["Validação<br/>✅ Testes Automatizados"]
    end

    subgraph "Resultados e Artefatos"
        GOLD_LAYER["Camada Gold<br/>🏆 Dados Certificados"]
        AUDIT_LOGS["Logs de Auditoria<br/>📜 Trilha Completa"]
        QUALITY_REPORTS["Relatórios de Qualidade<br/>📈 Métricas e KPIs"]
    end

    subgraph "Dashboards de Monitoramento"
        MONITORING["Dashboard de Governança<br/>📊 Monitoramento em Tempo Real"]
        ALERTS["Sistema de Alertas<br/>🚨 Notificações Automáticas"]
    end

    %% --- Conexões de Governança ---
    TRANSFORMATION -->|"Dados para Validar"| GE_SUITE
    GE_SUITE -->|"Valida Qualidade"| DQ_GATES
    DQ_GATES -->|"Aprova/Rejeita"| GOLD_LAYER
    
    TRANSFORMATION -->|"Registra Operations"| SEC_AUDIT
    LOAD -->|"Registra Load Events"| SEC_AUDIT
    VALIDATION -->|"Registra Validações"| SEC_AUDIT
    
    SEC_AUDIT --> AUDIT_LOGS
    GE_SUITE --> QUALITY_REPORTS
    
    AUDIT_LOGS --> MONITORING
    QUALITY_REPORTS --> MONITORING
    MONITORING --> ALERTS
    
    %% --- Estilos ---
    classDef governance fill:#D32F2F,stroke:#B71C1C,color:white,font-weight:bold
    classDef pipeline fill:#2E7D32,stroke:#1B5E20,color:white,font-weight:bold
    classDef results fill:#E65100,stroke:#BF360C,color:white,font-weight:bold
    classDef monitoring fill:#1565C0,stroke:#0D47A1,color:white,font-weight:bold

    class GE_SUITE,SEC_AUDIT,DQ_GATES governance
    class TRANSFORMATION,LOAD,VALIDATION pipeline
    class GOLD_LAYER,AUDIT_LOGS,QUALITY_REPORTS results
    class MONITORING,ALERTS monitoring
```

---

## Tecnologias Utilizadas

### 🔧 **Orquestração e Processamento**
- **Apache Airflow**: Orquestração de pipelines e workflow management
- **Apache Spark**: Processamento distribuído de big data
- **Python**: Linguagem principal para desenvolvimento dos pipelines

### 🗄️ **Armazenamento**
- **MinIO**: Object storage para as camadas Bronze, Silver e Gold
- **PostgreSQL**: Data warehouse relacional com star schema
- **Redis**: Cache para otimização de performance

### 🔒 **Segurança**
- **HashiCorp Vault**: Gerenciamento de secrets e credenciais
- **Custom PII Service**: Mascaramento de dados pessoais
- **SSL/TLS**: Criptografia em trânsito

### 📊 **Visualização**
- **Grafana**: Dashboards executivos e monitoramento
- **Streamlit**: Interface analítica interativa
- **Great Expectations**: Documentação automática de dados

### 🌐 **Fontes de Dados**
- **API Banco Central**: Indicadores econômicos (IPCA, Selic)
- **API Meteorologia**: Dados climáticos em tempo real
- **Dataset Olist**: Dados transacionais de e-commerce

---
