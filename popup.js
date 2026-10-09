document.getElementById("collect").addEventListener("click", async () => {
  const startValue = document.getElementById("startDate").value;
  const endValue = document.getElementById("endDate").value;
  const status = document.getElementById("status");

  if (!startValue || !endValue) {
    status.textContent = "Select both dates.";
    return;
  }

  const start = new Date(startValue + "T00:00:00").getTime();
  const end = new Date(endValue + "T23:59:59.999").getTime();

  if (start > end) {
    status.textContent = "Start date must be before end date.";
    return;
  }

  status.textContent = "Reading permitted browser history...";

  try {
    const records = await chrome.history.search({
      text: "",
      startTime: start,
      endTime: end,
      maxResults: 10000
    });

    const history = records.map(item => ({
      url: item.url,
      title: item.title || "",
      lastVisitTime: item.lastVisitTime || null,
      visitCount: item.visitCount || 0
    }));

    // Local test only: display the number of records collected.
    status.textContent =
      `Collected ${history.length} history records.`;

    console.log("Collected browser history:", history);
  } catch (error) {
    status.textContent = "Could not read browser history.";
    console.error(error);
  }
});
