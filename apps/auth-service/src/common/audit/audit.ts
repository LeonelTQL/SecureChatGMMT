export function audit(event: string, data: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), service: 'AUTH', event, ...data }));
}
