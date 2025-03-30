import { Packet } from "../../packetParser/packetParser.type"
import {
  ConnectionKey,
  FlagsChecks,
  FlagTypes,
  HandshakeStatus,
} from "./tcpTracker.type"

export const analyzeTcpHandshake = (
  { srcIP, srcPort, dstIP, dstPort, flags, protocol }: Partial<Packet>,
  handshakeTracker: Map<ConnectionKey, HandshakeStatus>
) => {
  if (protocol !== "TCP" || !flags) return

  const key = createConnectionKey(srcIP, srcPort, dstIP, dstPort)
  const reverseKey = createConnectionKey(dstIP, dstPort, srcIP, srcPort)

  if (isFlagPacket("syn", flags)) {
    handshakeTracker.set(key, { hasSyn: true, hasSynAck: false, hasAck: false })
    return
  }

  if (isFlagPacket("synAck", flags)) {
    updateHandshakeStatus(handshakeTracker, reverseKey, "hasSynAck")
    return
  }

  if (isFlagPacket("ack", flags)) {
    updateHandshakeStatus(handshakeTracker, reverseKey, "hasAck")
  }
}


const createConnectionKey = (
  srcIP?: string,
  srcPort?: number,
  dstIP?: string,
  dstPort?: number
) =>
  `${srcIP ?? "unknown"}:${srcPort ?? "unknown"} -> ${dstIP ?? "unknown"}:${
    dstPort ?? "unknown"
  }`

const isFlagPacket = (flagType: FlagTypes, flags: string) => {
  const flagsChecks = FlagsChecks[flagType]
  return flagsChecks.every(({ key, isIncluded }) => 
    flags.includes(key) === isIncluded
  )
}

const updateHandshakeStatus = (
  tracker: Map<ConnectionKey, HandshakeStatus>,
  key: ConnectionKey,
  statusField: keyof HandshakeStatus
) => {
  if (!tracker.has(key)) return
  tracker.get(key)![statusField] = true
}
