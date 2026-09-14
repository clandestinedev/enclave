export interface ApiError {
  code: string;
  message: string;
}

export interface ApiEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: ApiError;
}
