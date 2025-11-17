export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNextPage: boolean;
}

export interface CursorPaginationMeta {
  cursor?: string;
  limit: number;
  hasNextPage: boolean;
}

export interface PaginatedResponse<T> {
  data: T[];
  meta: PaginationMeta;
}

export interface CursorPaginatedResponse<T> {
  data: T[];
  meta: CursorPaginationMeta;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
}

export interface PaginationConfig {
  defaultPage?: number;
  defaultLimit?: number;
  /** Max number of records allowed per page to protect DB/load. */
  maxLimit?: number;
  /** Minimum allowed limit (defaults to 1 to avoid zero/negative limits). */
  minLimit?: number;
}

export interface NormalizedPaginationParams {
  page: number;
  limit: number;
  offset: number;
}

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_LIMIT = 1;
const DEFAULT_MAX_LIMIT = 100;

export class PaginationHelper {
  /**
   * Normalize user-provided pagination params into safe numbers.
   * Ensures:
   * - page defaults to >= 1
   * - limit stays within configured min/max bounds
   * - offset is derived from normalized values
   */
  static normalizeParams(params: PaginationParams = {}, config: PaginationConfig = {}): NormalizedPaginationParams {
    const defaultPage = config.defaultPage ?? DEFAULT_PAGE;
    const defaultLimit = config.defaultLimit ?? DEFAULT_LIMIT;
    const minLimit = Math.max(config.minLimit ?? DEFAULT_MIN_LIMIT, DEFAULT_MIN_LIMIT);
    const maxLimit = Math.max(config.maxLimit ?? DEFAULT_MAX_LIMIT, minLimit);

    const parsedPage = Number(params.page);
    const page = Number.isFinite(parsedPage) && parsedPage > 0 ? Math.floor(parsedPage) : defaultPage;

    const parsedLimit = Number(params.limit);
    const limitCandidate = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.floor(parsedLimit) : defaultLimit;
    const limit = Math.min(Math.max(limitCandidate, minLimit), maxLimit);

    return {
      page,
      limit,
      offset: this.calculateOffset(page, limit)
    };
  }

  static calculateOffset(page: number, limit: number): number {
    return Math.max(page - 1, 0) * limit;
  }

  static calculateTotalPages(total: number, limit: number): number {
    if (limit <= 0) {
      return 0;
    }
    return Math.max(Math.ceil(total / limit), 0);
  }

  static hasNextPage(total: number, page: number, limit: number): boolean {
    if (limit <= 0) {
      return false;
    }
    return page * limit < total;
  }

  static createMeta(page: number, limit: number, total: number): PaginationMeta {
    return {
      page,
      limit,
      total,
      totalPages: this.calculateTotalPages(total, limit),
      hasNextPage: this.hasNextPage(total, page, limit)
    };
  }

  static buildResponse<T>(data: T[], total: number, params: PaginationParams = {}, config: PaginationConfig = {}): PaginatedResponse<T> {
    const normalized = this.normalizeParams(params, config);
    return {
      data,
      meta: this.createMeta(normalized.page, normalized.limit, total)
    };
  }

  static createCursorMeta(cursor: string | undefined, limit: number, hasNextPage: boolean): CursorPaginationMeta {
    return {
      cursor,
      limit,
      hasNextPage
    };
  }

  static buildCursorResponse<T>(data: T[], meta: {cursor?: string; hasNextPage: boolean}, limit: number): CursorPaginatedResponse<T> {
    return {
      data,
      meta: this.createCursorMeta(meta.cursor, limit, meta.hasNextPage)
    };
  }
}
