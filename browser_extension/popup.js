const startInput = document.getElementById("startDate");
const endInput = document.getElementById("endDate");
const status = document.getElementById("status");
const button = document.getElementById("analyse");

button.addEventListener("click", async () => {
  const startDate = startInput.value;
  const endDate = endInput.value;

  if (!startDate || !endDate) {
    status.textContent = "Select both dates.";
    return;
  }

  if (startDate > endDate) {
    status.textContent = "End date must be on or after start date.";
    return;
  }

  button.disabled = true;
  status.textContent = "Retrieving Chrome history...";

  try {
    // Keep the message contract consistent with background.js.
    const response = await chrome.runtime.sendMessage({
      type: "GET_FORENSIC_HISTORY",
      startDate,
      endDate
    });

    if (!response?.success) {
      throw new Error(response?.error || "History retrieval failed.");
    }

    const blob = new Blob(
      [JSON.stringify(response.records || [], null, 2)],
      { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "browser_history_evidence.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    status.textContent =
      `Retrieved ${response.count ?? (response.records || []).length} history entries.\n` +
      "Evidence JSON downloaded. Keep this file with your investigation records.";
  } catch (error) {
    status.textContent = `Error: ${error.message}\nCheck that the extension is enabled and reload it in chrome://extensions.`;
  } finally {
    button.disabled = false;
  }
});
