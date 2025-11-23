# src/ai_assistant.py

import json
import os
from datetime import datetime
from openai import OpenAI


def generate_incident_report(alert: dict) -> str:
    """
    Use a generative AI model to create a human-readable security incident report.
    """
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""
You are a Tier-1 Security Operations Center (SOC) analyst.
Write a clear, professional incident report that another analyst could use
to continue the investigation.

Follow this EXACT structure and use short, direct sentences.

===
ALERT CONTEXT (INPUT)
{json.dumps(alert, indent=2)}
===

Now output the report with these sections:

1. Summary  
   - 2–3 sentences describing what was detected, when it happened, and from which IP/user.

2. Attack Type  
   - Clearly state the type (e.g., "Brute-force login", "Password spraying", "Credential stuffing").  
   - Briefly explain what that attack type means in 1–2 sentences.

3. Severity  
   - Choose one: Low, Medium, High, Critical.  
   - Give 1–2 sentences explaining WHY you chose that severity.

4. Technical Details  
   - Bullet points. Include IPs, usernames, timestamps, fail counts, time windows, and any relevant data.  
   - Keep it factual and concise.

5. Impact Assessment  
   - 2–3 sentences about what could happen if the attack succeeds  
     (e.g., account takeover, data exfiltration, lateral movement).

6. Recommended Remediation  
   - Bullet points with specific, actionable steps  
     (e.g., "Add temporary firewall block for IP X", "Enable MFA",  
     "Reset targeted user passwords", "Increase lockout thresholds").

7. SOC Follow-Up Actions  
   - Bullet list of tasks for the SOC team  
     (e.g., "Correlate with other alerts from same IP",  
     "Search SIEM logs for related activity in last 24h",  
     "Verify targeted accounts for unusual login patterns").

Rules:
- Do NOT invent data that is not in the alert.  
- If information is missing, write "Not available in alert".  
- Keep the tone professional, like a real SOC Jira/ServiceNow ticket.  
- Do NOT include any JSON in the final answer.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=400
    )

    return response.choices[0].message.content.strip()


def save_incident_report(report_text: str) -> str:
    os.makedirs("output/incident_reports", exist_ok=True)
    filename = f"incident_reports_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    path = os.path.join("output/incident_reports", filename)

    with open(path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[AI] Incident report saved: {path}")
    return path