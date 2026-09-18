export function audit(event, details = {}) {
  const safe = Object.fromEntries(Object.entries(details).filter(([key]) => !/(password|secret|token|authorization|uri)/i.test(key)));
  console.info(JSON.stringify({ event, timestamp: new Date().toISOString(), ...safe }));
}
