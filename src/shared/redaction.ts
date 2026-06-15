const SECRET_KEY_PATTERN =
  /(api[_-]?key|token|secret|password|passwd|credential|private[_-]?key|auth|bearer|session|cookie)/i;

const SECRET_VALUE_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\b[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

const REDACTED = '[REDACTED]';

export function isSecretKey(key: string): boolean {
  return SECRET_KEY_PATTERN.test(key);
}

export function redactString(value: string, keyHint = ''): string {
  if (isSecretKey(keyHint)) {
    return REDACTED;
  }

  let redacted = value;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    redacted = redacted.replace(pattern, REDACTED);
  }

  return redacted;
}

export function redactDeep<T>(value: T, keyHint = ''): T {
  if (typeof value === 'string') {
    return redactString(value, keyHint) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactDeep(item, keyHint)) as T;
  }

  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      output[key] = isSecretKey(key) ? REDACTED : redactDeep(child, key);
    }
    return output as T;
  }

  return value;
}

export function hasSecretMaterial(value: unknown): boolean {
  if (typeof value === 'string') {
    return SECRET_VALUE_PATTERNS.some((pattern) => {
      pattern.lastIndex = 0;
      return pattern.test(value);
    });
  }

  if (Array.isArray(value)) {
    return value.some((item) => hasSecretMaterial(item));
  }

  if (value && typeof value === 'object') {
    return Object.entries(value).some(([key, child]) => isSecretKey(key) || hasSecretMaterial(child));
  }

  return false;
}

export function safeJson(value: unknown): string {
  return JSON.stringify(redactDeep(value), null, 2);
}
