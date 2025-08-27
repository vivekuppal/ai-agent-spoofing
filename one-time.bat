SET %PROJECT_ID%=lappuai-prod

set RUNTIME_SA=%RUNTIME_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com

REM @echo off
setlocal EnableExtensions EnableDelayedExpansion
REM ===========================================================
REM  Create AI Agent Infra (Windows CMD)
REM  - Enables APIs
REM  - Creates SAs + IAM
REM  - Builds (Cloud Build) and deploys Cloud Run
REM  - Creates Pub/Sub topic, DLQ, filtered push subscription
REM  - Wires GCS bucket notifications -> Pub/Sub
REM ===========================================================

REM ========== CONFIG (EDIT ME) ==========
set PROJECT_ID=lappuai-prod
echo PROJECT_ID=%PROJECT_ID%
set REGION=us-east1

REM Ingest bucket (no gs://)
set BUCKET=lai-dmarc-aggregate-reports

REM Component / service name (deploy one per run)
set SERVICE=ai-agent-spoofing

REM Pub/Sub plumbing
set TOPIC=ai-agent-spoofing-topic
set SUB=ai-agent-spoofing-sub

REM GCS object prefix to trigger on (can be empty for all)
set OBJECT_PREFIX=reports/

REM Subscription filter:
REM Use doubled quotes inside the value to survive CMD parsing.
set FILTER=attributes.eventType=""OBJECT_FINALIZE"" AND hasPrefix(attributes.objectId,""%OBJECT_PREFIX%"")

REM Dead-letter topic name (defaults to dlq.<SUB> if left blank)
set DLQ_TOPIC=

REM Service accounts (names only)
set RUNTIME_SA_NAME=ai-agent-spoofing-sa
set PUSH_SA_NAME=pubsub-push-spoofing-sa

REM ===== Optional Cloud Run runtime envs for the app =====
set ENV_COMPONENT_NAME=%SERVICE%
set ENV_EXPECTED_EVENT_TYPE=OBJECT_FINALIZE
set ENV_OBJECT_PREFIX=%OBJECT_PREFIX%
set ENV_OUTPUT_PREFIX=outputs/%SERVICE%/
REM Set REQUIRE_JWT=true if you want the app to verify the OIDC token too.
set ENV_REQUIRE_JWT=true
REM PUBSUB_ALLOWED_AUDIENCE is set AFTER deploy since we need the service URL.

REM ========== DERIVED ==========
for /f %%P in ('call gcloud projects describe "%PROJECT_ID%" --format^=value^(projectNumber^) -q') do set "PROJECT_NUMBER=%%P"
REM All application specific privileges should be granted to the runtime service account.
set RUNTIME_SA=%RUNTIME_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com
set PUSH_SA=%PUSH_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com
set PUBSUB_SERVICE_AGENT=service-%PROJECT_NUMBER%@gcp-sa-pubsub.iam.gserviceaccount.com
set GCS_SERVICE_AGENT=service-%PROJECT_NUMBER%@gs-project-accounts.iam.gserviceaccount.com

:: Enable the IAM credentails API
gcloud services enable iamcredentials.googleapis.com --project %PROJECT_ID%

gcloud projects add-iam-policy-binding "%PROJECT_ID%" ^
  --member="serviceAccount:%RUNTIME_SA%" ^
  --role="roles/vpcaccess.user"

REM update the existing service (safe to re-run)
gcloud run services update "%SERVICE%" ^
  --region "%REGION%" --project "%PROJECT_ID%" ^
  --vpc-connector "lai-vpc-connector" ^
  --vpc-egress=private-ranges-only
