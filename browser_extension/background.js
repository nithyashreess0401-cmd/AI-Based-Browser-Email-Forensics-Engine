
const APP_ORIGIN =
  "https://ai-based-browser-email-forensics-engine-fudazumawynmgunkx3xxqd.streamlit.app";

function getHistory(startDate, endDate) {
  return new Promise((resolve, reject) => {
    const start = new Date(`${startDate}T00:00:00`).getTime();
    const end = new Date(`${endDate}T23:59:59.999`).getTime();

    if (
      Number.isNaN(start) ||
      Number.isNaN(end) ||
      start > end
    ) {
      reject(new Error("Invalid investigation date range."));
      return;
    }

    chrome.history.search(
      {
        text: "",
        startTime: start,
        endTime: end,
        maxResults: 0
      },
      (items) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        const records = (items || []).map((item) => ({
          URL: item.url || "",
          Title: item.title || "",
          "Visit Time": item.lastVisitTime
            ? new Date(item.lastVisitTime).toISOString()
            : "",
          "Visit Count": item.visitCount || 0,
          "Typed Count": item.typedCount || 0,
          Browser: "Chrome"
        }));

        resolve(records);
      }
    );
  });
}

chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    if (message?.type !== "GET_FORENSIC_HISTORY") {
      return false;
    }

    getHistory(message.startDate, message.endDate)
      .then((records) => {
        sendResponse({
          success: true,
          count: records.length,
          records
        });
      })
      .catch((error) => {
        sendResponse({
          success: false,
          error: error.message
        });
      });

    return true;
  }
);

chrome.runtime.onMessageExternal.addListener(
  (message, sender, sendResponse) => {
    if (sender.origin !== APP_ORIGIN) {
      sendResponse({
        success: false,
        error: "Untrusted website origin."
      });
      return false;
    }

    if (message?.type !== "GET_FORENSIC_HISTORY") {
      return false;
    }

    getHistory(message.startDate, message.endDate)
      .then((records) => {
        sendResponse({
          success: true,
          count: records.length,
          records
        });
      })
      .catch((error) => {
        sendResponse({
          success: false,
          error: error.message
        });
      });

    return true;
  }
);
