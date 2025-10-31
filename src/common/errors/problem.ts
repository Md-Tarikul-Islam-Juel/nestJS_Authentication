export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  code?: string;
  errors?: Record<string, string[]>;
}

export class Problem {
  static create(status: number, title: string, detail: string, code?: string, errors?: Record<string, string[]>): ProblemDetails {
    return {
      type: `https://httpstatus.es/${status}`,
      title,
      status,
      detail,
      code,
      errors
    };
  }

  static badRequest(detail: string, code?: string, errors?: Record<string, string[]>): ProblemDetails {
    return this.create(400, 'Bad Request', detail, code, errors);
  }

  static unauthorized(detail: string, code?: string): ProblemDetails {
    return this.create(401, 'Unauthorized', detail, code);
  }

  static forbidden(detail: string, code?: string): ProblemDetails {
    return this.create(403, 'Forbidden', detail, code);
  }

  static notFound(detail: string, code?: string): ProblemDetails {
    return this.create(404, 'Not Found', detail, code);
  }

  static conflict(detail: string, code?: string): ProblemDetails {
    return this.create(409, 'Conflict', detail, code);
  }

  static internalServerError(detail: string, code?: string): ProblemDetails {
    return this.create(500, 'Internal Server Error', detail, code);
  }
}
