export const API_VERSION = '0.1.0';

export interface AppConfig {
  nodeEnv: string;
  port: number;
  serviceName: string;
  apiVersion: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PORT: ${env.PORT}`);
  }
  return {
    nodeEnv: env.NODE_ENV ?? 'development',
    port,
    serviceName: 'enclave-api',
    apiVersion: API_VERSION,
  };
}
