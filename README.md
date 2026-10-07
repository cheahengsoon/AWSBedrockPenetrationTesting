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
