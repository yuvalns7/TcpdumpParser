import { Packet } from "../packetParser/packetParser.type"
import { PacketResult } from "../tcpdumpProcessor.type"
import { STANDARD_PORTS } from "./reportGenerator.const"
import { PortUsageMap, TcpdumpReport } from "./reportGenerator.type"
import { analyzeTcpHandshake } from "./tcpTracker/tcpTracker"
import { ConnectionKey, HandshakeStatus } from "./tcpTracker/tcpTracker.type"

export const generateTcpdumpReport = (
  validPackets: Packet[],
  malformedPackets: Partial<Packet>[],
  totalPackets: PacketResult[]
): TcpdumpReport => {
  const protocolCounts = { UDP: 0, TCP: 0, ICMP: 0 }
  const applicationProtocolCounts = { HTTP: 0, DNS: 0, TLS: 0 }
  const portUsage: { src: PortUsageMap; dst: PortUsageMap } = {
    src: {},
    dst: {},
  }
  const nonStandardPorts = new Set<number>()
  const ipCounts = new Map<string, number>()
  const handshakeTracker = new Map<ConnectionKey, HandshakeStatus>()
  const packetSize = {
    totalPacketSize: 0,
    minPacketSize: Number.MAX_SAFE_INTEGER,
    maxPacketSize: 0,
    avgPacketSize: 0,
  }
  const synPacketStatus = {
    synPackets: 0,
    synAckPackets: 0,
  }

  for (const packet of totalPackets) {
    if (packet.protocol) protocolCounts[packet.protocol]++
    if (packet.applicationProtocol)
      applicationProtocolCounts[packet.applicationProtocol]++

    if (packet.protocol === "TCP") analyzeTcpHandshake(packet, handshakeTracker)
    updateSynStatus(packet.flags, synPacketStatus)

    updatePortUsage(packet.srcPort, portUsage.src, nonStandardPorts)
    updatePortUsage(packet.dstPort, portUsage.dst, nonStandardPorts)

    updateIpCount(packet.srcIP, ipCounts)
    updateIpCount(packet.dstIP, ipCounts)

    analtyzePacketSize(packet, packetSize)
  }

  return {
    protocolCounts,
    applicationProtocolCounts,
    portUsage,
    nonStandardPorts,
    ipCounts,
    handshakeTracker,
    packetCount: {
      total: totalPackets.length,
      malformed: malformedPackets.length,
      validated: validPackets.length,
    },
    packetSize: {
      ...packetSize,
      avgPacketSize:
        totalPackets.length > 0
          ? packetSize.totalPacketSize / totalPackets.length
          : 0,
    },
    synPacketStatus: {
      ...synPacketStatus,
      synFloodPossible:
        synPacketStatus.synPackets > synPacketStatus.synAckPackets * 3,
    },
  }
}

const updateSynStatus = (
  flags: string,
  synPacketStatus: {
    synPackets: number
    synAckPackets: number
  }
) => {
  if (flags === "[S]") synPacketStatus.synPackets++
  if (flags === "[S.]") synPacketStatus.synAckPackets++
}

const updatePortUsage = (
  port: number | undefined,
  portMap: PortUsageMap,
  nonStandardPorts: Set<number>
) => {
  if (port !== undefined) {
    portMap[port] = (portMap[port] || 0) + 1
    if (!STANDARD_PORTS.has(port)) nonStandardPorts.add(port)
  }
}

const updateIpCount = (ip: string | undefined, ipMap: Map<string, number>) => {
  if (ip) ipMap.set(ip, (ipMap.get(ip) || 0) + 1)
}

const analtyzePacketSize = (
  packet: PacketResult,
  packetSizes: {
    totalPacketSize: number
    minPacketSize: number
    maxPacketSize: number
  }
) => {
  if (packet.length !== undefined) {
    packetSizes.totalPacketSize += packet.length
    packetSizes.minPacketSize = Math.min(
      packetSizes.minPacketSize,
      packet.length
    )
    packetSizes.maxPacketSize = Math.max(
      packetSizes.maxPacketSize,
      packet.length
    )
  }
}
