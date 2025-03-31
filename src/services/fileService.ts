import fs from "fs";
import path from "path";

const LOG_DIR = path.join(__dirname, "../logs");
const UPLOAD_DIR = path.join(__dirname, "../../uploads");

export const ensureDirectoriesExist = () => {
  [LOG_DIR, UPLOAD_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};

export const readFileContent = (filePath: string): string => {
  return fs.readFileSync(filePath, "utf-8");
};

export const deleteFile = (filePath: string) => {
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
};

export const scheduleFileDeletion = (filePath: string, delayMs: number = 5000) => {
  setTimeout(() => deleteFile(filePath), delayMs);
};

export const getLogFilePath = (requestId: string): string => {
  return path.join(LOG_DIR, `tcpdump_analysis_${requestId}.log`);
};
