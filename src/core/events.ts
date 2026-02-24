export enum EventPriority {
  HIGHEST = 1,
  HIGH = 2,
  NORMAL = 3,
  LOW = 4,
}

export class Event {}

export class CancellableEvent extends Event {
  public canceled = false;
  public reason = "";

  public cancel(reason = ""): void {
    this.canceled = true;
    this.reason = reason;
  }
}

type EventHandler<TEvent extends Event = Event> = (event: TEvent) => void | Promise<void>;

type RegisteredHandler = {
  priority: EventPriority;
  run: EventHandler;
};

export class EventManager {
  private readonly handlers = new Map<string, RegisteredHandler[]>();

  public on<TEvent extends Event>(
    eventName: string,
    handler: EventHandler<TEvent>,
    priority: EventPriority = EventPriority.NORMAL,
  ): void {
    const next = this.handlers.get(eventName) ?? [];
    next.push({ priority, run: handler as EventHandler });
    next.sort((a, b) => a.priority - b.priority);
    this.handlers.set(eventName, next);
  }

  public async emit<TEvent extends Event>(
    eventName: string,
    event: TEvent,
    options: { awaitHandlers?: boolean } = {},
  ): Promise<void> {
    const list = this.handlers.get(eventName);
    if (!list || list.length === 0) {
      return;
    }

    if (options.awaitHandlers === false) {
      for (const handler of list) {
        void handler.run(event);
      }
      return;
    }

    for (const handler of list) {
      await handler.run(event);
      if (event instanceof CancellableEvent && event.canceled) {
        break;
      }
    }
  }
}
