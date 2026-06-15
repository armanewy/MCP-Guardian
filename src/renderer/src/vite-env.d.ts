/// <reference types="vite/client" />

import type { GuardianApi } from '../../preload';

declare global {
  interface Window {
    guardian: GuardianApi;
  }
}
