
chrome.webNavigation.onCompleted.addListener((details) => {
  // Ignore embedded frames; process the main tab only.
  if (details.frameId !== 0) return;

  const url = details.url;

  // Ignore browser-internal pages.
  if (!url.startsWith("http://") &&
      !url.startsWith("https://")) {
    return;
  }

  console.log("Forensic Engine observed URL:", url);
  console.log("Navigation time:", new Date().toISOString());
});
