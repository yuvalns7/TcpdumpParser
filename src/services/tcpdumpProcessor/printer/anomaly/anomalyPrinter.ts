import { Anomaly, AnomalyType } from "../../anomalyDetector/anomalyDetector.type";
import {
  AnomalyMessagesMap,
  AnomalyTypeOrder,
  AnomalyTypeToLabels,
} from "./printer.config";
import { Logger } from "../logger";

export const printAnomalies = (anomalies: Anomaly[], logger: Logger) => {
  if (anomalies.length === 0) {
    logger.log("✅ No anomalies detected.");
    return;
  }

  logger.logSeparator();
  logger.log("📢 Output of Anomaly Detection:");
  logger.logSeparator();

  const groupedAnomalies: Record<AnomalyType, Anomaly[]> | {} =
    anomalies.reduce((grouped, anomaly) => {
      if (!grouped[anomaly.type]) {
        grouped[anomaly.type] = [];
      }
      grouped[anomaly.type].push(anomaly);
      return grouped;
    }, {});

  AnomalyTypeOrder.forEach((type) => {
    if (groupedAnomalies[type]) {
      logger.log(`🚨 ${AnomalyTypeToLabels[type]}:`);

      groupedAnomalies[type]
        .sort(({ lineIndex: a }, { lineIndex: b }) => a - b)
        .forEach((anomaly: Anomaly) => {
          printAnomaly(anomaly, logger);
        });

      logger.logSeparator();
    }
  });
};

const printAnomaly = ({ keyLabel, lineIndex, type, explanation }: Anomaly, logger: Logger) => {
  const message =
    AnomalyMessagesMap[type]?.(lineIndex, keyLabel) ??
    `Line ${lineIndex + 1}: Anomaly detected.`;

  logger.log(explanation ? `${message} (${explanation})` : message);
};
