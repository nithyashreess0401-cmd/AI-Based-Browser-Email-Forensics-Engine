
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "GET_HISTORY") return;

  (async () => {
    try {
      const startTime = Number(message.startTime);
      const endTime = Number(message.endTime);

      if (
        !Number.isFinite(startTime) ||
        !Number.isFinite(endTime) ||
        startTime >= endTime
      ) {
        throw new Error("Invalid investigation date range.");
      }

      // Search known URLs, then retrieve individual visits so an
      // earlier visit is not missed just because the URL was revisited later.
      const items = await chrome.history.search({
        text: "",
        startTime: 0,
        endTime: Date.now(),
        maxResults: 100000
      });

      const records = [];

      for (const item of items) {
        if (!item.url || !/^https?:\/\//i.test(item.url)) continue;

        const visits = await chrome.history.getVisits({
          url: item.url
        });

        for (const visit of visits) {
          if (
            visit.visitTime >= startTime &&
            visit.visitTime < endTime
          ) {
            records.push({
              url: item.url,
              title: item.title || "",
              visitTime: new Date(visit.visitTime).toISOString(),
              transition: visit.transition || ""
            });
          }
        }
      }

      records.sort(
        (a, b) => new Date(a.visitTime) - new Date(b.visitTime)
      );

      sendResponse({ ok: true, records });
    } catch (error) {
      sendResponse({
        ok: false,
        error: error?.message || "Unknown history retrieval error."
      });
    }
  })();

  return true;
});

// Continue observing new main-frame navigation events.
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!/^https?:\/\//i.test(details.url)) return;

  console.log(
    "Forensic Engine observed URL:",
    details.url,
    new Date().toISOString()
  );
});
