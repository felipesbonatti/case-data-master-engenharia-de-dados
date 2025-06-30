# Diagrama de Sequência: Acesso Seguro a Credenciais

## Cenário de Uso
**Situação:** Uma DAG do Airflow precisa acessar a API do Banco Central para coletar dados de câmbio. O diagrama ilustra como o framework de segurança garante acesso controlado e auditado às credenciais, demonstrando a implementação prática dos componentes de segurança em tempo de execução.

## Fluxo de Segurança
Este diagrama detalha o processo step-by-step de como as credenciais são solicitadas, validadas, entregues e auditadas, garantindo **zero-trust** e total rastreabilidade das operações.

```mermaid
sequenceDiagram
    autonumber
    participant DAG as 🔄 Airflow DAG
    participant SM as 🛡️ SecurityManager
    participant V as 🔐 Vault
    participant AL as 📝 AuditLog
    participant API as 🌐 API Externa
    
    Note over DAG,API: Processo de Acesso Seguro a Credenciais
    
    DAG->>+SM: 1. Solicita credencial para API Banco Central
    Note right of DAG: DAG identifica-se com<br/>task_id e dag_id
    
    SM->>SM: 2. Valida permissões da DAG
    Note right of SM: Verifica se a DAG tem<br/>autorização para acessar<br/>essa credencial específica
    
    SM->>+V: 3. Solicita segredo ('bcb_api_key')
    Note right of SM: Requisição autenticada<br/>com token JWT
    
    V->>V: 4. Descriptografa segredo
    Note right of V: Usa Fernet (AES-128)<br/>com chave rotacionada
    
    V-->>-SM: 5. Retorna credencial descriptografada
    Note left of V: Credencial temporária<br/>com TTL de 15 minutos
    
    SM->>+AL: 6. Registra evento de acesso
    Note right of SM: Log inclui: timestamp,<br/>dag_id, task_id, secret_name
    
    AL->>AL: 7. Persiste log de auditoria
    Note right of AL: Armazenamento imutável<br/>com hash de integridade
    
    AL-->>-SM: 8. Confirma registro
    
    SM-->>-DAG: 9. Entrega credencial segura
    Note left of SM: Credencial em memória<br/>nunca persistida em disco
    
    DAG->>+API: 10. Chamada autenticada
    Note right of DAG: HTTPS + API Key<br/>no header Authorization
    
    API-->>-DAG: 11. Retorna dados de câmbio
    Note left of API: Dados em formato JSON<br/>com timestamp de coleta
    
    DAG->>DAG: 12. Limpa credencial da memória
    Note right of DAG: Garbage collection<br/>força limpeza imediata
    
    rect rgb(255, 245, 238)
        Note over SM,V: 🔒 Segurança:<br/>Credenciais criptografadas com Fernet (AES-128)<br/>Rotação automática de chaves a cada 30 dias
    end
    
    rect rgb(240, 248, 255)
        Note over AL: 📊 Auditoria:<br/>Logs incluem timestamp, DAG ID, task ID<br/>e tipo de credencial acessada
    end
    
    rect rgb(245, 255, 245)
        Note over DAG,API: 🌐 Conexão:<br/>Estabelecida via HTTPS com certificado válido<br/>Sem exposição de credenciais em logs
    end
```

---

## Componentes e Responsabilidades

### 🛡️ **SecurityManager**
- **Validação de Permissões**: Verifica se a DAG tem autorização para acessar credenciais específicas
- **Intermediação Segura**: Atua como proxy entre DAGs e o Vault
- **Controle de TTL**: Gerencia tempo de vida das credenciais temporárias
- **Rate Limiting**: Controla frequência de acessos por DAG

### 🔐 **Vault (HashiCorp Vault)**
- **Armazenamento Seguro**: Credenciais criptografadas com Fernet (AES-128)
- **Rotação Automática**: Chaves rotacionadas automaticamente a cada 30 dias
- **Auditoria Nativa**: Logs detalhados de todos os acessos
- **Políticas Dinâmicas**: Controle granular de acesso baseado em políticas

### 📝 **AuditLog**
- **Registro Imutável**: Logs com hash de integridade para prevenção de adulteração
- **Rastreabilidade Completa**: Tracking de qual DAG acessou qual credencial e quando
- **Compliance**: Atendimento aos requisitos de auditoria e governança
- **Alertas Automáticos**: Notificações em caso de acessos suspeitos

---

## Aspectos Técnicos de Segurança

### 🔐 **Criptografia**
- **Algoritmo**: Fernet (AES-128 em modo CBC)
- **Gestão de Chaves**: Rotação automática a cada 30 dias
- **Derivação**: PBKDF2 com salt único por credencial

### ⏱️ **Controle Temporal**
- **TTL de Credenciais**: 15 minutos para credenciais temporárias
- **Timeout de Sessão**: 5 minutos de inatividade
- **Renovação Automática**: Credenciais renovadas antes da expiração

### 🛡️ **Validação e Autorização**
- **RBAC**: Role-Based Access Control por DAG
- **JWT Tokens**: Autenticação baseada em tokens com expiração
- **IP Whitelisting**: Controle de acesso por origem

---

## Benefícios de Segurança

### ✅ **Princípios de Segurança Aplicados**
- **Zero-Trust Architecture**: Nenhum componente tem acesso direto às credenciais
- **Princípio do Menor Privilégio**: DAGs só acessam credenciais necessárias
- **Defense in Depth**: Múltiplas camadas de proteção
- **Fail-Safe Defaults**: Negação por padrão, acesso apenas com permissão explícita

### 📊 **Compliance e Auditoria**
- **Trilha de Auditoria Completa**: Registro de todas as operações
- **Conformidade LGPD**: Proteção de dados pessoais
- **SOX Compliance**: Controles financeiros adequados
- **ISO 27001**: Gestão de segurança da informação

### 🚀 **Operacional**
- **Alta Disponibilidade**: Vault em cluster com failover automático
- **Performance**: Cache inteligente de credenciais válidas
- **Monitoramento**: Métricas em tempo real de acesso e performance
- **Escalabilidade**: Suporte a milhares de DAGs simultâneas

---

## Cenários de Falha e Recuperação

### 🚨 **Tratamento de Erros**
1. **Vault Indisponível**: Fallback para cache local temporário
2. **Credencial Expirada**: Renovação automática transparente
3. **Acesso Negado**: Log de segurança e notificação aos administradores
4. **Falha de Rede**: Retry automático com backoff exponencial

### 🔄 **Procedimentos de Recuperação**
- **Backup de Credenciais**: Backup criptografado em storage seguro
- **Disaster Recovery**: Procedimentos documentados para restauração
- **Business Continuity**: Plano de continuidade para operações críticas
