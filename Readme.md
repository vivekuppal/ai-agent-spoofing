# Purpose
Run AI-agents that will detect various suspicious activities in email metadata


# Deployment Steps from scratch
1. Create the necessary infrastructure using the `create-agent.bat` script
2. To tear down the complete infrastructure use `teardown.bat` script


# Deploy just the container
1. If only changes are in the source code, use `build-container.bat` script to create and deploy the container image <br/>
   Ensure that the env vars in script are the same as that in `create-agent.bat` script <br/>

# Smoke Testing the code in GCS
To ensure that container is active and is actually running good code, copy the file `smoke.xml` to the GCS storage bucket

# Testing the code locally

Run the app using the below command

```
C:\git\ai-agent-spoofing>uvicorn app.main:app --host 0.0.0.0 --port 8080
```
Ensure app is up and running `http://localhost:8080/health`<br/>

To process the file `smoke.xml` locally call the endpoint `http://localhost:8080/health`

---------------------------------------------------
Log of container would be in Cloud Run logs

get logs locally

``` powershell
gcloud logging read `
'resource.type="cloud_run_revision" AND resource.labels.service_name="ai-agent-spoofing" AND resource.labels.location="us-east1"' `
--project=lappuai-prod `
--freshness=2h `
--order=asc `
--format="csv(timestamp,textPayload)" `
--limit=2000 | Out-File ai-agent-logs.txt -Encoding utf8
```