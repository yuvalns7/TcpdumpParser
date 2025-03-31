import express, { Request, Response } from "express";
import multer from "multer";
import crypto from "crypto";
import {
  ensureDirectoriesExist,
  readFileContent,
  deleteFile,
  scheduleFileDeletion,
  getLogFilePath,
} from "../services/fileService";
import { initializeLogger } from "../services/loggerService";
import { processTcpdumpContent } from "../services/tcpdumpProcessor/tcpdumpProcessorService";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/parseTcpdumpFile", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded." });

    const filePath = req.file.path;
    const fileContent = readFileContent(filePath);

    const requestId = crypto.randomUUID();
    const logger = initializeLogger(requestId);
    processTcpdumpContent(fileContent, logger);
    const logFilePath = getLogFilePath(requestId)

    deleteFile(filePath);
    scheduleFileDeletion(logFilePath);

    res.download(logFilePath, `tcpdump_analysis_${requestId}.log`, (err) => {
      if (err) res.status(500).json({ error: "Error downloading the file." });
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
