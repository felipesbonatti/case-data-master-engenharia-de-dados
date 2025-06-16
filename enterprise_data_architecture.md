# Arquitetura de Dados 

```mermaid
graph TB
    
    subgraph "DATA SOURCES LAYER"
        direction TB
        API_BC["Central Bank API<br/>IPCA & Economic Indicators"]
        API_WEATHER["Weather Intelligence API<br/>Climate Data Integration"]
        DS_OLIST["E-commerce Dataset<br/>Olist Transactional Data"]
        STREAM_SALES["Real-time Sales Stream<br/>Live Transaction Feed"]
    end

    subgraph "ENTERPRISE SECURITY FRAMEWORK"
        direction TB
        SEC_VAULT["Enterprise Vault Manager<br/>(AirflowSecurityManager)"]
        SEC_AUDIT["Compliance Audit Engine<br/>(AuditLogger)"]
        SEC_PII["PII Protection Service<br/>(DataProtection)"]
        SEC_CONN["Secure Connection Pool<br/>(SecureConnectionPool)"]
    end

    subgraph "ORCHESTRATION LAYER - APACHE AIRFLOW"
        direction TB
        
        subgraph "Data Ingestion Pipeline"
            DAG_01["dag_01_coleta_segura<br/>Multi-source Data Collection"]
            DAG_02["dag_consolida_olist<br/>Dataset Harmonization"]
            DAG_03["dag_coleta_e_validacao<br/>Basic Validation & Storage Prep"]
        end
        
        subgraph "Data Transformation Pipeline"
            DAG_04["dag_03_mascaramento_dados<br/>Privacy-Safe Transformation"]
            DAG_05["dag_05_validacao_segura<br/>Great Expectations Quality Gate"]
            DAG_06["dag_04_spark_processamento<br/>Distributed Data Processing"]
        end
        
        subgraph "Data Lake Load & Lifecycle"
            DAG_07["dag_upload_bronze<br/>Raw Data Persistence"]
            DAG_08["dag_upload_silver<br/>Clean Data Repository"]
            DAG_09["dag_gerenciamento_lifecycle<br/>Data Retention Policies"]
        end
        
        subgraph "Data Warehouse Load"
            DAG_10["dag_minio_para_postgresql<br/>Analytics Data Movement"]
            DAG_11["dag_06_carrega_star_schema<br/>Dimensional Model Load"]
        end
    end

    subgraph "ENTERPRISE STORAGE ARCHITECTURE"
        direction TB
        
        subgraph "Object Storage - MinIO S3 Compatible"
            BRONZE_LAYER["BRONZE LAYER<br/>Raw Ingested Data<br/>Retention: 7 years"]
            SILVER_LAYER["SILVER LAYER<br/>Cleaned & Validated Data<br/>Retention: 5 years"]
            GOLD_LAYER["ANALYTICS LAYER<br/>Analytics-Ready Data<br/>Retention: 3 years"]
            ARCHIVE_LAYER["COLD STORAGE<br/>Compressed Archives<br/>Long-term Retention"]
        end
        
        subgraph "Enterprise Data Warehouse"
            PG_WAREHOUSE["PostgreSQL Enterprise DW<br/>High-Availability Cluster"]
            OLIST_STAGE_TABLE["Staging Table: dados_olist"]
            DIMENSIONAL_MODEL["Star Schema Architecture<br/>Fact & Dimension Tables"]
        end
    end

    subgraph "GOVERNANCE & QUALITY ASSURANCE"
        direction TB
        GE_SUITE["Great Expectations<br/>Data Quality Framework"]
        AUDIT_LOGS_FILES["Centralized Audit Logs<br/>CSV / System Files"]
        MONITORING["Pipeline Monitoring<br/>Alerting & Observability"]
        COMPLIANCE["Regulatory Compliance<br/>Data Lineage Tracking"]
    end

    %% ===========================================
    %% PRIMARY DATA FLOW CONNECTIONS
    %% ===========================================
    
    %% Source to Ingestion
    API_BC --> DAG_01
    API_WEATHER --> DAG_01
    STREAM_SALES --> DAG_01
    DS_OLIST --> DAG_02

    %% Ingestion Pipeline Flow
    DAG_01 --> DAG_03
    DAG_02 --> DAG_03
    DAG_03 --> DAG_07
    DAG_07 --> BRONZE_LAYER

    %% Transformation Pipeline Flow
    BRONZE_LAYER --> DAG_04
    DAG_04 --> DAG_05
    DAG_05 --> DAG_06
    DAG_06 --> DAG_08
    DAG_08 --> SILVER_LAYER

    %% Analytics Pipeline Flow - Data Promotion
    SILVER_LAYER --> GOLD_LAYER
    GOLD_LAYER --> DAG_10

    %% Data Warehouse Load Flow
    DAG_10 --> OLIST_STAGE_TABLE
    OLIST_STAGE_TABLE --> DAG_11
    DAG_11 --> DIMENSIONAL_MODEL

    %% Lifecycle Management
    DAG_09 --> BRONZE_LAYER
    DAG_09 --> SILVER_LAYER
    DAG_09 --> ARCHIVE_LAYER
    BRONZE_LAYER -.->|Archive Policy| ARCHIVE_LAYER

    %% ===========================================
    %% SECURITY INTEGRATION FLOWS
    %% ===========================================
    
    %% Credential Management
    SEC_VAULT -.->|API Keys| DAG_01
    SEC_VAULT -.->|PII Keys| SEC_PII
    SEC_VAULT -.->|Storage Creds| DAG_07
    SEC_VAULT -.->|Storage Creds| DAG_08
    SEC_VAULT -.->|Storage Creds| DAG_09
    SEC_VAULT -.->|Storage Creds| DAG_06
    SEC_VAULT -.->|DB Creds| DAG_10
    SEC_VAULT -.->|DB Creds| DAG_11

    %% PII Protection Integration
    SEC_PII --> DAG_04
    SEC_PII -.->|Masking Rules| SILVER_LAYER

    %% Secure Connections
    SEC_CONN -.->|TLS/mTLS Connections| DAG_07
    SEC_CONN -.->|TLS/mTLS Connections| DAG_08
    SEC_CONN -.->|TLS/mTLS Connections| DAG_10
    SEC_CONN -.->|TLS/mTLS Connections| DAG_11

    %% ===========================================
    %% AUDIT & COMPLIANCE FLOWS
    %% ===========================================
    
    %% Comprehensive Audit Trail
    DAG_01 --> SEC_AUDIT
    DAG_02 --> SEC_AUDIT
    DAG_03 --> SEC_AUDIT
    DAG_04 --> SEC_AUDIT
    DAG_05 --> SEC_AUDIT
    DAG_06 --> SEC_AUDIT
    DAG_10 --> SEC_AUDIT
    DAG_11 --> SEC_AUDIT
    SEC_VAULT --> SEC_AUDIT
    SEC_PII --> SEC_AUDIT
    SEC_CONN --> SEC_AUDIT

    %% Audit Outputs
    SEC_AUDIT --> AUDIT_LOGS_FILES
    SEC_AUDIT --> COMPLIANCE

    %% ===========================================
    %% QUALITY & MONITORING FLOWS
    %% ===========================================
    
    %% Quality Validation Integration
    GE_SUITE --> DAG_05
    GE_SUITE -.->|Validation Rules| SILVER_LAYER
    DAG_05 -.->|Quality Gate| GOLD_LAYER

    %% Monitoring Integration
    MONITORING -.->|Observability| DAG_01
    MONITORING -.->|Observability| DAG_06
    MONITORING -.->|Observability| DAG_10
    MONITORING --> AUDIT_LOGS_FILES

    %% ===========================================
    %% PROFESSIONAL STYLING
    %% ===========================================
    
    %% Color Palette - Enterprise Theme
    classDef sourceLayer fill:#1565C0,stroke:#0D47A1,stroke-width:3px,color:#ffffff,font-weight:bold
    classDef securityLayer fill:#7B1FA2,stroke:#4A148C,stroke-width:3px,color:#ffffff,font-weight:bold
    classDef orchestrationLayer fill:#2E7D32,stroke:#1B5E20,stroke-width:3px,color:#ffffff,font-weight:bold
    classDef storageLayer fill:#E65100,stroke:#BF360C,stroke-width:3px,color:#ffffff,font-weight:bold
    classDef governanceLayer fill:#D32F2F,stroke:#B71C1C,stroke-width:3px,color:#ffffff,font-weight:bold
    classDef auditLayer fill:#E91E63,stroke:#C2185B,stroke-width:3px,color:#ffffff,font-weight:bold

    %% Apply Styling
    class API_BC,API_WEATHER,DS_OLIST,STREAM_SALES sourceLayer
    class SEC_VAULT,SEC_AUDIT,SEC_PII,SEC_CONN securityLayer
    class DAG_01,DAG_02,DAG_03,DAG_04,DAG_05,DAG_06,DAG_07,DAG_08,DAG_09,DAG_10,DAG_11 orchestrationLayer
    class BRONZE_LAYER,SILVER_LAYER,GOLD_LAYER,ARCHIVE_LAYER,PG_WAREHOUSE,OLIST_STAGE_TABLE,DIMENSIONAL_MODEL storageLayer
    class GE_SUITE,MONITORING,COMPLIANCE governanceLayer
    class AUDIT_LOGS_FILES auditLayer
