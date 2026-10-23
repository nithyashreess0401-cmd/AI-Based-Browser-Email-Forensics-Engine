
const startInput = document.getElementById("startDate");
const endInput = document.getElementById("endDate");
const status = document.getElementById("status");
const button = document.getElementById("analyse");

button.addEventListener("click", async () => {
  const start = startInput.value;
  const end = endInput.value;

  if (!start || !end) {
    status.textContent = "Select both dates.";
    return;
  }

  // Use local calendar dates, including the whole end date.
  const startTime = new Date(`${start}T00:00:00`).getTime();
  const endTime = new Date(`${end}T00:00:00`).getTime()
    + 24 * 60 * 60 * 1000;

  if (startTime >= endTime) {
    status.textContent = "End date must be on or after start date.";
    return;
  }

  button.disabled = true;
  status.textContent = "Retrieving Chrome history...";

  try {
    const response = await chrome.runtime.sendMessage({
      type: "GET_HISTORY",
      startTime,
      endTime
    });

    if (!response?.ok) {
      throw new Error(response?.error || "History retrieval failed.");
    }

    // Keep results locally for now.
    const blob = new Blob(
      [JSON.stringify(response.records, null, 2)],
      { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "browser_history_evidence.json";
    link.click();
    URL.revokeObjectURL(url);

    status.textContent =
      `Retrieved ${response.records.length} visits.\n` +
      "A local evidence JSON file was downloaded.";
  } catch (error) {
    status.textContent = `Error: ${error.message}`;
  } finally {
    button.disabled = false;
  }
});
