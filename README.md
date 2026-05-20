**Gmail AI Threat Scanner**

A lightweight, zero-infra Gmail security extension built using Google Apps Script. It monitors incoming emails, extracts metadata, and runs real-time anomaly analysis using low-latency AI models via API.

It operates in two modes simultaneously:
  1. Automated Background Scan: A time-driven trigger runs every minute to evaluate new unread emails and apply color-coded labels (AI-Safe, AI-Suspicious, AI-Malicious).
  2. Interactive Sidebar Add-on: A contextual sidebar panel that opens when reading an email to show detailed risk scores, verdicts, specific red flags, and an interactive "Mark as False Positive" button to manually fix misclassifications.

**Installation & Setup**
  1. Initialize the Script Project
  2. Go to Google Apps Script
  3. Click New Project and rename it to Gmail AI Security Scanner.

**Configure the Manifest (appsscript.json)**

To allow the script to make outbound API calls, modify mailbox labels, and fetch local time zones, you must declare explicit OAuth scopes.
  1. Click on Project Settings (the gear icon on the left menu).
  2. Check the box for Show "appsscript.json" manifest file in editor.
  3. Return to the editor tab, open appsscript.json, and replace its contents with "appscript.json" file contents.

**Add Your Engine Code (Main.gs)**
  1. Rename the default Code.gs file to Main.gs and paste the following complete script.

**Store Your API Credentials**
  1. Go to Project Settings (gear icon) in the Apps Script console.
  2. Scroll down to Script Properties and click Add script property.
  3. Set Property to GEMINI_API_KEY (or your chosen model's key identifier).
  4. Set Value to your secret string from your API dashboard, then save.

**Automate Background Execution**

To make the analysis function look for incoming emails automatically without needing to open the add-on UI manually:
  1. Click the Triggers icon on the left menu bar (the alarm clock).
  2. Click Add Trigger in the lower-right corner.
  3. Set the function to run to autoScanInbox.
  4. Set the deployment to Head.
  5. Set the event source to Time-driven.
  6. Set the type of time-based trigger to Minutes timer and set the interval to Every minute.
  7. Click Save and accept the background security authorization requests.

**Deployment & Verification**
  1. Inside the Apps Script editor panel, click Deploy > Test deployments.
  2. Click Install next to the Gmail application add-on entry, and select Done.
  3. Navigate to Gmail in your browser and refresh the page (Ctrl + F5 or Cmd + Shift + R to clear cached layout hooks).
  4. New incoming emails will dynamically receive text labels within their row views.
  5. Opening any individual email thread exposes the AI Threat Scanner badge in the right-hand action drawer sidebar. Clicking it renders full metrics parsing instantly.
