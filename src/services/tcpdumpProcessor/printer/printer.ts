import { Anomaly } from "../anomalyDetector/anomalyDetector.type";
import { PacketResult } from "../tcpdumpProcessor.type";
import { TcpdumpReport } from "../reportGenerator/reportGenerator.type";
import { printAnomalies } from "./anomaly/anomalyPrinter";
import { printPackets } from "./packet/packetPrinter";
import { printReport } from "./report/reportPrinter";
import { Logger } from "./logger";

export const logTcpdumpAnalysis = (packets: PacketResult[], anomalies: Anomaly[], reportData: TcpdumpReport,   logger: Logger
) => {
  printPackets(packets, logger);
  printAnomalies(anomalies, logger);
  printReport(reportData, logger)
}