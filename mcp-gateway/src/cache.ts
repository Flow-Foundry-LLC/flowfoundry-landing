export class TTLCache<T> {
  private store = new Map<string, { value: T; expiresAt: number }>();

  constructor() {
    // Sweep expired entries every 60s
    setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store) {
        if (entry.expiresAt <= now) this.store.delete(key);
      }
    }, 60_000).unref();
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T, ttlMs: number): void {
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}
