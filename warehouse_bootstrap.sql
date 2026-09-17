-- DC Vietnam warehouse baseline. All datasets must remain in asia-southeast1.
CREATE SCHEMA IF NOT EXISTS `PROJECT_ID.dwh_raw` OPTIONS(location="asia-southeast1", description="Immutable source payloads from Lark, Bluecore, marketplaces, ads and Pancake");
CREATE SCHEMA IF NOT EXISTS `PROJECT_ID.dwh_clean` OPTIONS(location="asia-southeast1", description="Validated and standardized business entities");
CREATE SCHEMA IF NOT EXISTS `PROJECT_ID.dwh_mart` OPTIONS(location="asia-southeast1", description="Portal and finance reporting marts");
CREATE SCHEMA IF NOT EXISTS `PROJECT_ID.dwh_audit` OPTIONS(location="asia-southeast1", description="Pipeline runs, lineage and data-quality results");
CREATE SCHEMA IF NOT EXISTS `PROJECT_ID.dwh_secure` OPTIONS(location="asia-southeast1", description="Restricted PII and sensitive financial identifiers");

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_raw.ingestion_events` (
  event_id STRING NOT NULL,
  warehouse_id STRING NOT NULL,
  source_system STRING NOT NULL,
  source_entity STRING NOT NULL,
  source_record_id STRING NOT NULL,
  event_type STRING,
  payload JSON NOT NULL,
  payload_hash STRING,
  source_updated_at TIMESTAMP,
  ingested_at TIMESTAMP NOT NULL,
  trace_id STRING
)
PARTITION BY DATE(ingested_at)
CLUSTER BY warehouse_id, source_system, source_entity, source_record_id
OPTIONS(description="Append-only raw events. Never edit source payloads.");

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_audit.ingestion_runs` (
  run_id STRING NOT NULL,
  warehouse_id STRING NOT NULL,
  source_system STRING NOT NULL,
  source_entity STRING NOT NULL,
  started_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP,
  status STRING NOT NULL,
  received_rows INT64,
  accepted_rows INT64,
  quarantined_rows INT64,
  error_message STRING,
  trace_id STRING
)
PARTITION BY DATE(started_at)
CLUSTER BY warehouse_id, source_system, source_entity, status;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_audit.warehouse_registry` (
  warehouse_id STRING NOT NULL,
  project_id STRING NOT NULL,
  location STRING NOT NULL,
  raw_dataset STRING NOT NULL,
  clean_dataset STRING NOT NULL,
  mart_dataset STRING NOT NULL,
  audit_dataset STRING NOT NULL,
  secure_dataset STRING NOT NULL,
  active BOOL NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
)
CLUSTER BY warehouse_id, project_id;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_audit.data_contract_rules` (
  rule_id STRING NOT NULL,
  source_system STRING NOT NULL,
  source_entity STRING NOT NULL,
  field_name STRING,
  rule_type STRING NOT NULL,
  rule_config JSON,
  severity STRING NOT NULL,
  active BOOL NOT NULL,
  rule_version STRING NOT NULL,
  updated_at TIMESTAMP NOT NULL
)
CLUSTER BY source_system, source_entity, rule_type, active;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_audit.quarantine_records` (
  quarantine_id STRING NOT NULL,
  run_id STRING,
  warehouse_id STRING NOT NULL,
  source_system STRING NOT NULL,
  source_entity STRING NOT NULL,
  source_record_id STRING,
  failure_code STRING NOT NULL,
  failure_message STRING NOT NULL,
  payload JSON,
  mapping_version STRING,
  status STRING NOT NULL,
  assigned_to STRING,
  resolved_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL
)
PARTITION BY DATE(created_at)
CLUSTER BY warehouse_id, source_system, source_entity, status;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_clean.channel_mapping` (
  source_system STRING NOT NULL,
  source_channel_code STRING NOT NULL,
  canonical_channel STRING NOT NULL,
  active BOOL NOT NULL,
  mapping_version STRING NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  updated_by STRING
)
CLUSTER BY source_system, source_channel_code;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_clean.status_mapping` (
  source_system STRING NOT NULL,
  source_status STRING NOT NULL,
  canonical_status STRING NOT NULL,
  active BOOL NOT NULL,
  mapping_version STRING NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  updated_by STRING
)
CLUSTER BY source_system, source_status;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_clean.sku_mapping` (
  source_system STRING NOT NULL,
  source_sku STRING NOT NULL,
  canonical_sku STRING NOT NULL,
  product_name STRING,
  active BOOL NOT NULL,
  mapping_version STRING NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  updated_by STRING
)
CLUSTER BY source_system, source_sku, canonical_sku;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_clean.orders` (
  canonical_order_id STRING NOT NULL,
  warehouse_id STRING NOT NULL,
  source_system STRING NOT NULL,
  source_order_id STRING NOT NULL,
  canonical_channel STRING,
  order_status STRING,
  order_created_at TIMESTAMP,
  paid_at TIMESTAMP,
  currency_code STRING NOT NULL,
  gross_amount NUMERIC,
  discount_amount NUMERIC,
  shipping_fee NUMERIC,
  platform_fee NUMERIC,
  refund_amount NUMERIC,
  net_amount NUMERIC,
  source_updated_at TIMESTAMP,
  processed_at TIMESTAMP NOT NULL,
  mapping_version STRING NOT NULL
)
PARTITION BY DATE(processed_at)
CLUSTER BY warehouse_id, source_system, source_order_id, canonical_channel;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_clean.payments` (
  payment_id STRING NOT NULL,
  warehouse_id STRING NOT NULL,
  source_system STRING NOT NULL,
  source_transaction_id STRING NOT NULL,
  source_order_id STRING,
  canonical_order_id STRING,
  payment_type STRING NOT NULL,
  payment_status STRING,
  currency_code STRING NOT NULL,
  gross_amount NUMERIC,
  fee_amount NUMERIC,
  net_amount NUMERIC,
  paid_at TIMESTAMP,
  source_updated_at TIMESTAMP,
  processed_at TIMESTAMP NOT NULL,
  mapping_version STRING NOT NULL
)
PARTITION BY DATE(processed_at)
CLUSTER BY warehouse_id, source_system, source_order_id, source_transaction_id;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_clean.ads_spend` (
  spend_id STRING NOT NULL,
  warehouse_id STRING NOT NULL,
  source_system STRING NOT NULL,
  canonical_channel STRING NOT NULL,
  account_id STRING,
  campaign_id STRING,
  adset_id STRING,
  ad_id STRING,
  metric_date DATE NOT NULL,
  currency_code STRING NOT NULL,
  spend_amount NUMERIC,
  impressions INT64,
  clicks INT64,
  conversions NUMERIC,
  source_updated_at TIMESTAMP,
  processed_at TIMESTAMP NOT NULL
)
PARTITION BY metric_date
CLUSTER BY warehouse_id, source_system, canonical_channel, campaign_id;

CREATE TABLE IF NOT EXISTS `PROJECT_ID.dwh_mart.reconciliation_breaks` (
  break_id STRING NOT NULL,
  warehouse_id STRING NOT NULL,
  reconciliation_type STRING NOT NULL,
  canonical_order_id STRING,
  payment_id STRING,
  expected_amount NUMERIC,
  actual_amount NUMERIC,
  difference_amount NUMERIC,
  currency_code STRING NOT NULL,
  break_reason STRING NOT NULL,
  break_status STRING NOT NULL,
  owner_email STRING,
  detected_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP,
  resolution_note STRING
)
PARTITION BY DATE(detected_at)
CLUSTER BY warehouse_id, reconciliation_type, break_status, break_reason;

CREATE OR REPLACE VIEW `PROJECT_ID.dwh_mart.v_reconciliation_summary` AS
SELECT
  warehouse_id,
  reconciliation_type,
  break_status,
  currency_code,
  COUNT(*) AS break_count,
  SUM(difference_amount) AS total_difference_amount,
  MIN(detected_at) AS oldest_break_at
FROM `PROJECT_ID.dwh_mart.reconciliation_breaks`
GROUP BY warehouse_id, reconciliation_type, break_status, currency_code;

MERGE `PROJECT_ID.dwh_audit.warehouse_registry` AS target
USING (
  SELECT 'core' AS warehouse_id, 'PROJECT_ID' AS project_id, 'asia-southeast1' AS location,
    'dwh_raw' AS raw_dataset, 'dwh_clean' AS clean_dataset, 'dwh_mart' AS mart_dataset,
    'dwh_audit' AS audit_dataset, 'dwh_secure' AS secure_dataset, TRUE AS active
) AS source
ON target.warehouse_id = source.warehouse_id
WHEN MATCHED THEN UPDATE SET
  project_id = source.project_id, location = source.location, raw_dataset = source.raw_dataset,
  clean_dataset = source.clean_dataset, mart_dataset = source.mart_dataset,
  audit_dataset = source.audit_dataset, secure_dataset = source.secure_dataset,
  active = source.active, updated_at = CURRENT_TIMESTAMP()
WHEN NOT MATCHED THEN INSERT (
  warehouse_id, project_id, location, raw_dataset, clean_dataset, mart_dataset,
  audit_dataset, secure_dataset, active, created_at, updated_at
) VALUES (
  source.warehouse_id, source.project_id, source.location, source.raw_dataset, source.clean_dataset,
  source.mart_dataset, source.audit_dataset, source.secure_dataset, source.active,
  CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()
);
