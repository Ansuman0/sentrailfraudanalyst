/** Names and one-line descriptions for the plan features (the API only returns ids). Unknown ids fall back to the id. */
export const FEATURES: { id: string; name: string; text: string }[] = [
  { id: "screening", name: "Transfer screening", text: "Real-time screening of crypto transfers through the API." },
  { id: "alerts", name: "Alert queue", text: "Held and flagged transfers for analysts to work." },
  { id: "ai", name: "AI investigation", text: "AI-assisted case summaries and STR drafts." },
  { id: "trace", name: "Wallet trace", text: "Follow funds through connected wallets." },
  { id: "statements", name: "Statement upload", text: "Upload customer statements for review." },
  { id: "export", name: "Case export", text: "Export case data." },
];

export const featureInfo = (id: string) => FEATURES.find((f) => f.id === id) ?? { id, name: id, text: "" };
