import fs from "fs";

export class Logger {
  private logFilePath: string | null = null;
  private static instances: Map<string, Logger> = new Map();

  constructor(private requestId: string) {}

  static create(requestId: string): Logger {
    const logger = new Logger(requestId);
    this.instances.set(requestId, logger);
    return logger;
  }

  static getInstance(requestId: string): Logger | undefined {
    return this.instances.get(requestId);
  }

  enableFileOutput(logFilePath: string) {
    this.logFilePath = logFilePath;
  }

  log(message: string) {
    console.log(message);
    if (this.logFilePath) {
      fs.appendFileSync(this.logFilePath, message + "\n");
    }
  }

  logSeparator() {
    this.log("-----------------------------------------");
  }

  static removeInstance(requestId: string) {
    this.instances.delete(requestId);
  }
}
