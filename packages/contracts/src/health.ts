import type { WIRE_VERSION } from './version';

export interface HealthStatus {
  service: string;
  apiVersion: string;
  wireVersion: typeof WIRE_VERSION;
  time: string;
}
