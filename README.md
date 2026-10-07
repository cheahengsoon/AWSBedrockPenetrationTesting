# AWSBedrockPenetrationTesting
just focus Amazon Bedrock

# Test Case
1. Prompt Injection Testing
2. Guardrail Bypass Testing
3. Data Exfiltration via Knowledge Base

# Permission Required
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockLLMPentest",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:ListFoundationModels",
        "bedrock:ListGuardrails",
        "bedrock:GetGuardrail",
        "bedrock-agent-runtime:InvokeAgent",
        "bedrock-agent-runtime:Retrieve",
        "bedrock-agent:ListAgents",
        "bedrock-agent:ListKnowledgeBases"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["us-east-1", "ap-southeast-1"]
        }
      }
    }
  ]
}
```
# Usage — LLM Tests
```
# List all 27 test IDs
python3 bedrock_llm_pentest.py --list-tests

# Full run against a model (requires bedrock:InvokeModel)
python3 bedrock_llm_pentest.py \
  --model anthropic.claude-haiku-4-5-20251001-v1:0 \
  --region us-east-1

# Run specific categories only
python3 bedrock_llm_pentest.py \
  --categories system_prompt_extraction jailbreaking data_extraction

# Test with a guardrail deployed
python3 bedrock_llm_pentest.py \
  --model anthropic.claude-haiku-4-5-20251001-v1:0 \
  --guardrail <guardrail-id>

# Compare attack success WITH vs WITHOUT guardrail
python3 bedrock_llm_pentest.py \
  --compare-guardrail \
  --guardrail <guardrail-id>

# Use a specific AWS profile
python3 bedrock_llm_pentest.py --profile bedrock-dev-role
```

# Usage — Agent Tests
```
# Enumerate agents and knowledge bases (read-only)
python3 bedrock_agent_pentest.py \
  --region ap-southeast-1 \
  --enumerate-only

# Run full agent attack suite
python3 bedrock_agent_pentest.py \
  --agent-id <agent-id> \
  --alias-id <alias-id> \
  --region ap-southeast-1
```
