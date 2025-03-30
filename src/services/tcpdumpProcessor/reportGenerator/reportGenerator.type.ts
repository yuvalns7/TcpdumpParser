import { ConnectionKey, HandshakeStatus } from "./tcpTracker/tcpTracker.type"

export type PortUsageMap = Record<number, number>

export type TcpdumpReport = {
  packetCount: {
    total: number
    validated: number
    malformed: number
  }
  protocolCounts: {
    UDP: number
    TCP: number
    ICMP: number
  }
  applicationProtocolCounts: {
    HTTP: number
    DNS: number
    TLS: number
  }
  portUsage: { src: PortUsageMap; dst: PortUsageMap }
  nonStandardPorts: Set<number>
  ipCounts: Map<string, number>
  handshakeTracker: Map<ConnectionKey, HandshakeStatus>
  packetSize: {
    totalPacketSize: number
    minPacketSize: number
    maxPacketSize: number
    avgPacketSize: number
  }
  synPacketStatus: {
    synPackets: number
    synAckPackets: number, 
    synFloodPossible: boolean
  }
}
