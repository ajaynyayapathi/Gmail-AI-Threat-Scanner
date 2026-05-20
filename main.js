function analyzeOpenedEmail(e) {
  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  
  // Extract essential components for the AI context
  const emailData = {
    from: message.getFrom(),
    subject: message.getSubject(),
    body: message.getPlainBody().substring(0, 4000) // Keep within reasonable token limits
  };

  // Analyze via Gemini
  const analysis = callGeminiScanner(emailData);
  
  return buildSecurityCard(analysis, emailData.from);
}

/**
 * Sends email metadata to Gemini API to check for phishing, social engineering, or anomalies.
 */
function callGeminiScanner(emailData) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  
  if (!apiKey) return { status: "SUSPICIOUS", riskScore: 50, verdict: "API Key missing.", redFlags: ["Configure GEMINI_API_KEY"] };

  // FIX: Using gemini-3.1-flash-lite or gemini-3.5-flash for maximum speed
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=${apiKey}`;
  
  const systemPrompt = "You are an expert cybersecurity mail filter. Analyze the following email for signs of phishing, business email compromise (BEC), suspicious credential links, artificial urgency, or layout anomalies. You must return your analysis strictly in valid JSON format with keys: 'status' (either 'SAFE', 'SUSPICIOUS', or 'MALICIOUS'), 'riskScore' (0 to 100), 'verdict' (one sentence summary), and 'redFlags' (an array of strings listing specific reasons). Do not wrap the JSON response in markdown blocks.";
  
  const safeSubject = emailData.subject || "(No Subject)";
  const safeBody = emailData.body ? emailData.body.trim() : "(Empty Email Body)";
  const userContent = `Sender: ${emailData.from}\nSubject: ${safeSubject}\nBody:\n${safeBody}`;
  
  const payload = {
    "contents": [{
      "parts": [
        { "text": systemPrompt },
        { "text": userContent }
      ]
    }],
    "generationConfig": {
      "responseMimeType": "application/json",
      "temperature": 0.1,
      "thinkingConfig": { "thinkingBudget": 0 } // FIX: Forces the model to bypass thinking steps for ultra-low latency
    }
  };
  
  const options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };
  
  try {
    const response = UrlFetchApp.fetch(url, options);
    const responseCode = response.getResponseCode();
    const responseText = response.getContentText();
    const json = JSON.parse(responseText);
    
    // Check for explicit API error structures (e.g., bad key, blocked content)
    if (json.error) {
      return {
        status: "SUSPICIOUS",
        riskScore: 50,
        verdict: `Gemini API returned an explicit error (HTTP ${responseCode}).`,
        redFlags: [json.error.message || "Unknown API error"]
      };
    }
    
    // Validate that the candidates property exists before reading it
    if (!json.candidates || json.candidates.length === 0 || !json.candidates[0].content) {
      return {
        status: "SUSPICIOUS",
        riskScore: 50,
        verdict: "API response structure did not contain generated text content.",
        redFlags: ["Empty generation candidate array. Check for safety block filtering."]
      };
    }
    
    const rawText = json.candidates[0].content.parts[0].text;
    return JSON.parse(rawText);
    
  } catch (err) {
    return {
      status: "SUSPICIOUS",
      riskScore: 50,
      verdict: "Failed to automatically process email body safely.",
      redFlags: ["Analysis pipeline error: " + err.toString()]
    };
  }
}

/**
 * Constructs the contextual Card UI inside Gmail using CardService.
 */
function buildSecurityCard(analysis, sender) {
  const card = CardService.newCardBuilder();
  const header = CardService.newCardHeader();
  
  if (analysis.status === "MALICIOUS") {
    header.setTitle("🚨 HIGH RISK DETECTED").setSubtitle("Extreme caution advised.");
  } else if (analysis.status === "SUSPICIOUS") {
    header.setTitle("⚠️ SUSPICIOUS ACTIVITY").setSubtitle("Review anomalies below.");
  } else {
    header.setTitle("✅ EMAIL CLEAR").setSubtitle("No obvious threats found.");
  }
  card.setHeader(header);
  
  const section = CardService.newCardSection().setHeader("AI Security Assessment");
  
  section.addWidget(CardService.newKeyValue()
    .setTopLabel("Risk Score")
    .setContent(`<b>${analysis.riskScore} / 100</b>`)
    .setBottomLabel(`Classification: ${analysis.status}`));
    
  section.addWidget(CardService.newKeyValue()
    .setTopLabel("Verdict")
    .setContent(analysis.verdict)
    .setMultiline(true));
    
  if (analysis.redFlags && analysis.redFlags.length > 0) {
    let flagsText = analysis.redFlags.map(flag => `• ${flag}`).join("<br/>");
    section.addWidget(CardService.newTextParagraph().setText(`<b>Anomalies Found:</b><br/>${flagsText}`));
  } else {
    section.addWidget(CardService.newTextParagraph().setText("No operational red flags noted in body text pattern matching."));
  }
  
  // ADD INTERACTION: Show False Positive button if the email wasn't classified as completely clean
  if (analysis.status !== "SAFE") {
    const buttonSet = CardService.newButtonSet();
    
    // Create an explicit callback action linked to a function execution handler
    const falsePositiveAction = CardService.newAction()
      .setFunctionName("handleFalsePositive");
      
    const falsePositiveButton = CardService.newTextButton()
      .setText("Mark as False Positive")
      .setOnClickAction(falsePositiveAction);
      
    buttonSet.addButton(falsePositiveButton);
    section.addWidget(buttonSet);
  }
  
  card.addSection(section);
  return card.build();
}
/**
 * Automatically scans unread inbox messages, analyzes them via Gemini,
 * and applies security labels dynamically in the background.
 */
function autoScanInbox() {
  // Ensure your custom security labels exist in your Gmail account
  const safeLabel = getOrCreateLabel("AI-Safe");
  const suspiciousLabel = getOrCreateLabel("AI-Suspicious");
  const maliciousLabel = getOrCreateLabel("AI-Malicious");
  
  // Find up to 10 unread emails that haven't been scanned yet
  const threads = GmailApp.search("is:unread -label:AI-Safe -label:AI-Suspicious -label:AI-Malicious", 0, 10);
  
  for (const thread of threads) {
    const messages = thread.getMessages();
    const lastMessage = messages[messages.length - 1]; // Scan the latest incoming message
    
    const emailData = {
      from: lastMessage.getFrom(),
      subject: lastMessage.getSubject(),
      body: lastMessage.getPlainBody().substring(0, 4000)
    };
    
    // Use your existing Gemini API function
    const analysis = callGeminiScanner(emailData);
    
    // Apply appropriate label based on the AI verdict
    if (analysis.status === "MALICIOUS") {
      thread.addLabel(maliciousLabel);
      thread.markImportant(); // Ensure it stands out
    } else if (analysis.status === "SUSPICIOUS") {
      thread.addLabel(suspiciousLabel);
    } else {
      thread.addLabel(safeLabel);
    }
  }
}

/**
 * Helper function to find or create Gmail labels safely.
 */
function getOrCreateLabel(name) {
  let label = GmailApp.getUserLabelByName(name);
  if (!label) {
    label = GmailApp.createLabel(name);
  }
  return label;
}
/**
 * Action Callback: Fixes misclassifications by cleaning tags manually.
 */
function handleFalsePositive(e) {
  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  const thread = message.getThread();
  
  // Fetch existing label definitions securely
  const safeLabel = getOrCreateLabel("AI-Safe");
  const suspiciousLabel = getOrCreateLabel("AI-Suspicious");
  const maliciousLabel = getOrCreateLabel("AI-Malicious");
  
  // Rectify the organizational states
  thread.removeLabel(suspiciousLabel);
  thread.removeLabel(maliciousLabel);
  thread.addLabel(safeLabel);
  
  // Return an official action response back to the Workspace UI to build an alert notification
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification()
      .setText("Thread successfully re-classified as Safe. Labels updated."))
    .build();
}
