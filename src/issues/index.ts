import { CancellableEvent } from "../core/events.js";

export type PathSegment = { readonly key: PropertyKey } | { readonly index: number };

export interface Issue {
  readonly message: string;
  readonly path?: ReadonlyArray<PropertyKey | PathSegment>;
}

export type IssueFactory<TSchema extends object> = {
  [K in Extract<keyof TSchema, string>]-?: (message: string) => Issue;
} & {
  $path: (path: ReadonlyArray<PropertyKey | PathSegment>, message: string) => Issue;
  $root: (message: string) => Issue;
};

export function createIssue(message: string, path?: ReadonlyArray<PropertyKey | PathSegment>): Issue {
  if (!path || path.length === 0) {
    return { message };
  }

  return {
    message,
    path: [...path],
  };
}

export function createIssueFactory<TSchema extends object>(
  fields: readonly Extract<keyof TSchema, string>[],
): IssueFactory<TSchema> {
  const factory: Record<string, unknown> & {
    $path: (path: ReadonlyArray<PropertyKey | PathSegment>, message: string) => Issue;
    $root: (message: string) => Issue;
  } = {
    $path: (path, message) => createIssue(message, path),
    $root: (message) => createIssue(message),
  };

  for (const field of fields) {
    factory[field] = (message: string) => createIssue(message, [field]);
  }

  return factory as IssueFactory<TSchema>;
}

export abstract class AuthIssueEvent<TSchema extends object> extends CancellableEvent {
  private readonly _issues: Issue[] = [];
  private readonly _issue: IssueFactory<TSchema>;

  protected constructor(fields: readonly Extract<keyof TSchema, string>[]) {
    super();
    this._issue = createIssueFactory<TSchema>(fields);
    this.cancel = this.cancel.bind(this);
  }

  public get issues(): ReadonlyArray<Issue> {
    return this._issues;
  }

  public get issue(): IssueFactory<TSchema> {
    return this._issue;
  }

  public addIssues(...issues: Array<Issue | undefined>): void {
    for (const issue of issues) {
      if (!issue) {
        continue;
      }

      this._issues.push(issue);
    }
  }

  public override cancel(reason?: string): void;
  public override cancel(...issues: Issue[]): void;
  public override cancel(reason: string, ...issues: Issue[]): void;
  public override cancel(reasonOrIssue?: string | Issue, ...issues: Issue[]): void {
    let reason = "";

    if (typeof reasonOrIssue === "string") {
      reason = reasonOrIssue;
      this.addIssues(...issues);
    } else if (reasonOrIssue === undefined) {
      this.addIssues(...issues);
    } else {
      this.addIssues(reasonOrIssue, ...issues);
      reason = reasonOrIssue.message;
    }

    super.cancel(reason);
  }
}
