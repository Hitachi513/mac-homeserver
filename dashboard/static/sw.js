// Service worker for the home-screen app: shows Web Push notifications and opens the right page when tapped.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("push", e => {
  let d = {};
  try { d = e.data.json(); } catch { d = { title: "家用控制台", body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(d.title || "家用控制台", {
    body: d.body || "", icon: "/static/icon-180.png", badge: "/static/icon-180.png",
    tag: d.kind || "general", renotify: true, data: { url: d.url || "/" },
  }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL(e.notification.data.url || "/", self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(ws => {
    for (const w of ws) { w.navigate(url); return w.focus(); }
    return self.clients.openWindow(url);
  }));
});
