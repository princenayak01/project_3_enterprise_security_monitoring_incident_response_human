import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "10mb" }));

// Lazy init Gemini AI
let aiClient: GoogleGenAI | null = null;
function getAIClient(): GoogleGenAI | null {
  if (!apiKey) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
        },
      },
    });
  }
  return aiClient;
}

// Health check endpoint
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// 1. AI Deep Log Analysis & Threat Intelligence
app.post("/api/gemini/analyze-log", async (req, res) => {
  try {
    const { rawLog, context, logType } = req.body;
    if (!rawLog) {
      return res.status(400).json({ error: "rawLog is required" });
    }

    const ai = getAIClient();
    if (!ai) {
      return res.json({
        analysis: "### Simulated AI Security Log Analysis (API Key not provided)\n\n" +
          "**Threat Assessment**: High Severity Anomaly Detected\n" +
          "**MITRE ATT&CK Mapping**: T1110 (Brute Force) & T1078 (Valid Accounts)\n" +
          "**Root Cause**: Multiple consecutive authentication failures followed by a high-privilege token issuance from an unmanaged IP.\n" +
          "**Recommended Action**: Immediately isolate affected endpoint, revoke user Kerberos/OAuth session tokens, and block source CIDR on perimeter edge firewall."
      });
    }

    const prompt = `You are a Senior Tier 3 Enterprise Cybersecurity SOC Incident Responder & Threat Hunter.
Analyze the following security log (${logType || 'General SIEM / IDS'}):

RAW LOG:
\`\`\`
${rawLog}
\`\`\`

CONTEXT: ${context || 'Enterprise Network Security Monitoring'}

Please provide a structured, professional SOC analysis including:
1. **Threat Summary & Classification** (Severity: Critical/High/Medium/Low, Category)
2. **MITRE ATT&CK Technique & Tactic** (e.g. T1059 Command and Scripting Interpreter, T1078 Valid Accounts)
3. **Indicator of Compromise (IOC) Extraction** (IPs, Hashes, Domains, Processes, User Accounts)
4. **Attack Narrative & Root Cause** (How the adversary executed the step)
5. **Immediate Containment Steps** (Actionable steps for L1/L2 analyst)
6. **Suggested SIEM Correlation / Sigma Rule** (Brief syntax or logic)
`;

    const response = await ai.models.generateContent({
      model: "gemini-3.7-flash",
      contents: prompt,
    });

    res.json({ analysis: response.text || "No analysis returned." });
  } catch (error: any) {
    console.error("Error analyzing log with Gemini:", error);
    res.status(500).json({ error: error.message || "Failed to analyze log" });
  }
});

// 2. AI SOC Incident Copilot Chat
app.post("/api/gemini/incident-copilot", async (req, res) => {
  try {
    const { messages, incidentContext } = req.body;
    const ai = getAIClient();

    if (!ai) {
      const lastMsg = messages?.[messages.length - 1]?.content || "Help with incident";
      return res.json({
        reply: `**SOC Copilot Advisor**: Based on current incident context, proceed with containment playbook PB-101. Isolate the affected host, snapshot volatile memory with LiME/FTK Imager, and query firewall logs for egress C2 traffic to the suspect domain.`
      });
    }

    const conversationPrompt = `You are "Sentinel-AI", an elite Cyber Incident Response Copilot embedded inside an Enterprise Security Operations Center (SOC).
Current Active Incident Context:
${JSON.stringify(incidentContext || {}, null, 2)}

User/Analyst Inquiry:
${messages?.[messages.length - 1]?.content || 'Provide incident response guidance'}

Answer concisely, using standard SOC terminology (NIST SP 800-61, MITRE ATT&CK, RFC 2828). Provide actionable PowerShell/Bash/Splunk queries or firewall commands when applicable.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.7-flash",
      contents: conversationPrompt,
    });

    res.json({ reply: response.text || "No reply generated." });
  } catch (error: any) {
    console.error("Error in incident copilot:", error);
    res.status(500).json({ error: error.message || "Failed to process chat" });
  }
});

// 3. AI SOAR Playbook Generator
app.post("/api/gemini/generate-playbook", async (req, res) => {
  try {
    const { threatScenario, targetEnvironment } = req.body;
    const ai = getAIClient();

    if (!ai) {
      return res.json({
        playbook: {
          title: `Automated Playbook: ${threatScenario || "Threat Containment"}`,
          trigger: "Correlation Alert Severity >= High",
          estimatedMTTR: "12 mins",
          phases: [
            { name: "Triage & Validation", steps: ["Verify alert fidelity via Zeek flow logs", "Check VirusTotal for IP reputation"] },
            { name: "Containment", steps: ["Isolate host via EDR API", "Block source IP on Palo Alto NGFW", "Revoke Entra ID user session"] },
            { name: "Eradication", steps: ["Kill malicious PID", "Remove persistence registry keys / crontab", "Run full AV deep scan"] },
            { name: "Recovery & Lessons", steps: ["Un-isolate host to staging VLAN", "Verify service integrity", "Publish post-mortem report"] }
          ]
        }
      });
    }

    const prompt = `Generate an Enterprise Automated Incident Response SOAR Playbook for scenario: "${threatScenario}".
Target Environment: "${targetEnvironment || 'Hybrid Enterprise (AWS + Active Directory + Linux/Windows Servers)'}".

Return valid JSON with:
{
  "title": string,
  "trigger": string,
  "estimatedMTTR": string,
  "mitreTactic": string,
  "phases": [
    {
      "name": "Phase Name (e.g. Triage, Containment, Eradication, Recovery)",
      "steps": ["Step 1", "Step 2", "Step 3"]
    }
  ]
}`;

    const response = await ai.models.generateContent({
      model: "gemini-3.7-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      },
    });

    let playbookData;
    try {
      playbookData = JSON.parse(response.text || "{}");
    } catch {
      playbookData = { error: "Failed to parse json", raw: response.text };
    }

    res.json({ playbook: playbookData });
  } catch (error: any) {
    console.error("Error generating playbook:", error);
    res.status(500).json({ error: error.message || "Failed to generate playbook" });
  }
});

// 4. AI Post-Incident Executive & Technical Report Generator
app.post("/api/gemini/generate-report", async (req, res) => {
  try {
    const { incidentData } = req.body;
    const ai = getAIClient();

    if (!ai) {
      return res.json({
        reportMarkdown: `## NIST SP 800-61 Incident Post-Mortem Report\n\n` +
          `**Incident Title**: ${incidentData?.title || 'INC-2026-088: Ransomware Containment'}\n` +
          `**Severity**: ${incidentData?.severity || 'CRITICAL'} | **Status**: RESOLVED\n\n` +
          `### 1. Executive Summary\n` +
          `On ${new Date().toLocaleDateString()}, the SOC detected unauthorized lateral movement and staging of encrypted payloads. Automated SOAR containment rules isolated 2 endpoint hosts within 4 minutes, preventing data exfiltration and database encryption.\n\n` +
          `### 2. Timeline of Events\n` +
          `- **T00:00**: Initial phishing payload delivered.\n` +
          `- **T00:04**: PowerShell Cobalt Strike beacon detected by Wazuh EDR.\n` +
          `- **T00:06**: Automated SOAR Playbook PB-101 executed (host isolated, firewall blocked).\n` +
          `- **T00:25**: Root cause identified as CVE-2024-38077 and remediated.\n\n` +
          `### 3. Indicators of Compromise (IOCs)\n` +
          `- Malicious IP: \`194.26.29.114\` (C2 server)\n` +
          `- Hash SHA256: \`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\`\n\n` +
          `### 4. Corrective Actions & Hardening\n` +
          `- Applied emergency Windows Remote Desktop gateway security update.\n` +
          `- Enforced FIDO2 MFA on all privileged administrative accounts.`
      });
    }

    const prompt = `You are a Lead Cybersecurity Forensic Investigator.
Write a formal, comprehensive NIST SP 800-61 Rev. 2 Post-Incident Report in Markdown format for the following incident:
${JSON.stringify(incidentData, null, 2)}

Include sections:
1. Executive Summary
2. Incident Timeline & Chronology
3. Attack Vector & Root Cause Analysis (MITRE ATT&CK Mapping)
4. Forensic Evidence & Indicators of Compromise (IOCs table)
5. Containment, Eradication & Recovery Actions
6. Business Impact Assessment
7. Preventive Hardening Recommendations & Action Items`;

    const response = await ai.models.generateContent({
      model: "gemini-3.7-flash",
      contents: prompt,
    });

    res.json({ reportMarkdown: response.text || "Report generation failed." });
  } catch (error: any) {
    console.error("Error generating report:", error);
    res.status(500).json({ error: error.message || "Failed to generate report" });
  }
});

// Vite middleware & Static serving
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Enterprise Security Monitoring Server running on port ${PORT}`);
  });
}

startServer();
