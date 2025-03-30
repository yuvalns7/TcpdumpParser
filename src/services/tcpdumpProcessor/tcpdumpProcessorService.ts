import {
  detectPacketAnomalies,
  detectStructuralAnomalies,
} from "./anomalyDetector/anomalyDetector"
import { Anomaly } from "./anomalyDetector/anomalyDetector.type"
import {
  parsePartialPacket,
  parseTcpdumpPacket,
} from "./packetParser/packetParser"
import { Packet } from "./packetParser/packetParser.type"
import { parseTimestamp } from "./packetParser/packetParser.util"
import { Logger } from "./printer/logger"
import { logTcpdumpAnalysis } from "./printer/printer"
import { generateTcpdumpReport } from "./reportGenerator/reportGenerator"
import { PacketResult } from "./tcpdumpProcessor.type"

export const processTcpdumpContent = (fileContent: string, logger: Logger) => {
  const tcpdumpLines = fileContent.split("\n").map((line) => line.trim())

  const malformedPackets: Partial<Packet>[] = []
  const validPackets: Packet[] = []
  const anomalies: Anomaly[] = []

  tcpdumpLines.forEach((line, index) => {
    if (line.length > 0) {
      processPacketLine(line, index, validPackets, malformedPackets, anomalies)
    }
  })

  generateReport(validPackets, malformedPackets, anomalies, logger)
}

const processPacketLine = (
  line: string,
  index: number,
  validPackets: Packet[],
  malformedPackets: Partial<Packet>[],
  anomalies: Anomaly[]
) => {
  const parsedPacket = parseTcpdumpPacket(line)

  if (parsedPacket) {
    const packetAnomalies = detectPacketAnomalies(parsedPacket, index)
    if (packetAnomalies.length > 0) {
      anomalies.push(...packetAnomalies)
      malformedPackets.push(parsedPacket)
    } else {
      validPackets.push(parsedPacket)
    }
  } else {
    const partialPacket = parsePartialPacket(line)
    malformedPackets.push(partialPacket)
    anomalies.push(...detectStructuralAnomalies(line, index))
    anomalies.push(...detectPacketAnomalies(partialPacket, index))
  }
}

const generateReport = (
  validPackets: Packet[],
  malformedPackets: Partial<Packet>[],
  anomalies: Anomaly[],
  logger: Logger
) => {
  const totalPackets: PacketResult[] = [
    ...malformedPackets.map((p) => ({ ...p, isMalformed: true })),
    ...validPackets.map((p) => ({ ...p, isMalformed: false })),
  ]
  totalPackets.sort(
    (a, b) => parseTimestamp(a.timestamp) - parseTimestamp(b.timestamp)
  )

  const reportData = generateTcpdumpReport(
    validPackets,
    malformedPackets,
    totalPackets
  )

  logTcpdumpAnalysis(totalPackets, anomalies, reportData, logger)
}
