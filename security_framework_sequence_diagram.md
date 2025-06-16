### Diagrama de Sequência: Acesso Seguro a Credenciais

**Cenário:** Uma DAG do Airflow precisa acessar a API do Banco Central para coletar dados de câmbio. O diagrama ilustra como o framework de segurança garante acesso controlado e auditado às credenciais.

```mermaid
sequenceDiagram
   autonumber
   participant DAG as Airflow DAG
   participant SM as SecurityManager
   participant V as Vault
   participant AL as AuditLog
   participant API as API Externa
   
   DAG->>SM: Solicita credencial para a API
   activate SM
   SM->>V: Pede segredo (ex: 'api_key')
   activate V
   V-->>SM: Descriptografa e retorna o segredo
   deactivate V
   SM->>AL: Registra evento de acesso ao segredo
   activate AL
   AL-->>SM: Confirma registro de auditoria
   deactivate AL
   SM-->>DAG: Entrega a credencial segura
   deactivate SM
   DAG->>API: Realiza chamada autenticada com a credencial
   API-->>DAG: Retorna dados solicitados
   
   Note over SM,V: Todas as credenciais são<br/>criptografadas com Fernet (AES-128)
   Note over AL: Logs incluem timestamp,<br/>DAG ID e tipo de credencial
   Note over DAG,API: Conexão segura estabelecida<br/>sem exposição de credenciais
