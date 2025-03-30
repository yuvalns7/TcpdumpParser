import {
  PortUsageMap,
  TcpdumpReport,
} from "../../reportGenerator/reportGenerator.type"
import {
  ConnectionKey,
  HandshakeStatus,
} from "../../reportGenerator/tcpTracker/tcpTracker.type"
import { Logger } from "../logger"

export const printReport = (reportData: TcpdumpReport, logger: Logger) => {
  logger.logSeparator()
  logger.log("📢 TCPdump Analysis Report")
  logger.logSeparator()

  printPacketSummary(reportData.packetCount, logger)
  printProtocolBreakdown(reportData.protocolCounts, logger)
  printApplicationProtocolBreakdown(
    reportData.applicationProtocolCounts,
    logger
  )
  printNonStandardPorts(reportData.nonStandardPorts, logger)
  printPortUsage(reportData.portUsage, logger)
  printIpStatistics(reportData.ipCounts, logger)
  printTcpTraffic(reportData.handshakeTracker, logger)
  printPacketSize(reportData.packetSize, logger)
  printSynPacketStatusBreakdown(reportData.synPacketStatus, logger)
}

const printPacketSummary = (
  {
    total,
    malformed,
    validated,
  }: {
    total: number
    validated: number
    malformed: number
  },
  logger: Logger
) => {
  logger.log(`Total Packets: ${total}`)
  logger.log(`Valid Packets: ${validated} (${percentage(validated, total)}%)`)
  logger.log(
    `Malformed Packets: ${malformed} (${percentage(malformed, total)}%)`
  )
}

const printProtocolBreakdown = (
  protocolCounts: {
    UDP: number
    TCP: number
    ICMP: number
  },
  logger: Logger
) => {
  logger.logSeparator()
  logger.log("Protocol Breakdown:")
  logger.log(`UDP Packets: ${protocolCounts.UDP}`)
  logger.log(`TCP Packets: ${protocolCounts.TCP}`)
  logger.log(`ICMP Packets: ${protocolCounts.ICMP}`)
}

const printApplicationProtocolBreakdown = (
  {
    DNS,
    HTTP,
    TLS,
  }: {
    HTTP: number
    DNS: number
    TLS: number
  },
  logger: Logger
) => {
  logger.logSeparator()
  logger.log("Application Protocol Breakdown:")
  logger.log(`TLS Packets: ${TLS}`)
  logger.log(`HTTP Packets: ${HTTP}`)
  logger.log(`DNS Packets: ${DNS}`)
}

const printNonStandardPorts = (
  nonStandardPorts: Set<number>,
  logger: Logger
) => {
  logger.logSeparator()
  if (nonStandardPorts.size === 0) {
    logger.log("All ports used are standard.")
  } else {
    logger.log("Non-standard ports detected:")
    Array.from(nonStandardPorts)
      .sort((a, b) => a - b)
      .forEach((port) => logger.log(`  * Port ${port}`))
  }
}

const printPortUsage = (
  portUsage: {
    src: PortUsageMap
    dst: PortUsageMap
  },
  logger: Logger
) => {
  logger.logSeparator()
  logger.log("Source Port Usage:")
  printPortMap(portUsage.src, logger)
  logger.logSeparator()
  logger.log("Destination Port Usage:")
  printPortMap(portUsage.dst, logger)
}

const printPortMap = (portMap: PortUsageMap, logger: Logger) => {
  Object.entries(portMap)
    .sort(([, a], [, b]) => b - a)
    .forEach(([port, count]) => {
      logger.log(` * Port ${port.padStart(5, " ")} used ${count} time(s)`)
    })
}

const printIpStatistics = (ipCounts: Map<string, number>, logger: Logger) => {
  logger.logSeparator()
  logger.log("Unique IP Addresses & Appearance Counts:")
  ipCounts.forEach((count, ip) =>
    logger.log(`IP ${ip} appeared ${count} times`)
  )
}

const printTcpTraffic = (
  handshakeTracker: Map<ConnectionKey, HandshakeStatus>,
  logger: Logger
) => {
  logger.logSeparator()
  logger.log("TCP Handshake Analysis:")
  logger.logSeparator()
  printHandshakes(handshakeTracker, logger)
}

const percentage = (part: number, total: number): string =>
  ((100 * part) / total).toFixed(2)

export const printHandshakes = (
  handshakeTracker: Map<ConnectionKey, HandshakeStatus>,
  logger: Logger
) => {
  const handshakeLog: string[] = []

  handshakeTracker.forEach((status, key) => {
    if (status.hasSyn && !status.hasSynAck) {
      handshakeLog.push(
        `🚨 Incomplete handshake: SYN sent but no SYN-ACK received for ${key}`
      )
    } else if (status.hasSynAck && !status.hasAck) {
      handshakeLog.push(
        `🚨 Incomplete handshake: SYN-ACK received but no ACK sent for ${key}`
      )
    } else {
      handshakeLog.push(`✅ Completed handshake: ${key}`)
    }
  })

  handshakeLog.forEach((anomaly) => logger.log(anomaly))
}

const printPacketSize = (
  {
    avgPacketSize,
    maxPacketSize,
    minPacketSize,
  }: {
    minPacketSize: number
    maxPacketSize: number
    avgPacketSize: number
  },
  logger: Logger
) => {
  logger.logSeparator()
  logger.log("Packet Size Analysis:")
  logger.logSeparator()
  logger.log(`Min packet size - ${minPacketSize}`)
  logger.log(`Max packet size - ${maxPacketSize}`)
  logger.log(`Avg packet size - ${avgPacketSize}`)
}

const printSynPacketStatusBreakdown = (
  {
    synAckPackets,
    synFloodPossible,
    synPackets,
  }: {
    synPackets: number
    synAckPackets: number
    synFloodPossible: boolean
  },
  logger: Logger
) => {
  logger.logSeparator()
  logger.log("Syn Flood Analysis:")
  logger.log(`Number Of Syn Packets: ${synPackets}`)
  logger.log(`Number Of Syn Ack Packets: ${synAckPackets}`)
  logger.log(
    `Is Syn Flood Attack Possible: ${synFloodPossible ? `yes` : `false`}`
  )
}
