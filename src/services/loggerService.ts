import { Logger } from "./tcpdumpProcessor/printer/logger";
import { getLogFilePath } from "./fileService";

export const initializeLogger = (requestId: string): Logger => {
  const logFilePath = getLogFilePath(requestId);
  const logger = Logger.create(requestId);
  logger.enableFileOutput(logFilePath);
  return logger;
};
