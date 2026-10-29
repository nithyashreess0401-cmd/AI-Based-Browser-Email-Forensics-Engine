const startInput = document.getElementById("startDate");
const endInput = document.getElementById("endDate");
const tokenInput = document.getElementById("sessionToken");
const status = document.getElementById("status");
const button = document.getElementById("analyse");
const API_URL = "https://forensic-engine-connector.onrender.com";

button.addEventListener("click", async () => {
  const startDate = startInput.value, endDate = endInput.value, token = tokenInput.value.trim();
  if (!startDate || !endDate || !token) { status.textContent = "Enter both dates and the session token."; return; }
  if (startDate > endDate) { status.textContent = "End date must be on or after start date."; return; }
  button.disabled = true; status.textContent = "Retrieving Chrome history...";
  try {
    const response = await chrome.runtime.sendMessage({type:"GET_FORENSIC_HISTORY",startDate,endDate});
    if (!response?.success) throw new Error(response?.error || "History retrieval failed.");
    const upload = await fetch(API_URL + "/v1/evidence", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({token,start_date:startDate,end_date:endDate,records:response.records || []})
    });
    const result = await upload.json();
    if (!upload.ok) throw new Error(result.detail || "Could not send evidence to Forensic Engine.");
    status.textContent = "Sent " + result.count + " history entries to the connector. Return to Streamlit and click Run Browser Analysis.";
  } catch(error) {
    status.textContent = "Error: " + error.message + "\nCheck the dates, token, and that the extension is reloaded.";
  } finally { button.disabled = false; }
});
