/**
 * Activity Cache Port
 * Domain layer interface for caching user activity data
 * Following Clean Architecture: application layer depends on domain abstractions
 */
export interface ActivityCachePort {
  /**
   * Store a key-value pair with TTL
   */
  set(key: string, value: string, ttlSeconds: number): Promise<void>;

  /**
   * Get value by key
   */
  get(key: string): Promise<string | null>;

  /**
   * Delete a key
   */
  delete(key: string): Promise<void>;

  /**
   * Get all keys matching a pattern
   */
  keys(pattern: string): Promise<string[]>;
}
