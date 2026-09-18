import api from "./api";

export async function updateAlertWorkflow(alertId, action, body = {}) {
  const response = await api.post(`/alerts/${alertId}/${action}`, body, { timeout: 30000 });
  return response.data.alert;
}
