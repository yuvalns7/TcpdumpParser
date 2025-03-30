import {
  PacketMetadataFields,
  ICMPDetailsFields,
  CommonPacketFields,
  TCPDetailsFields,
} from "./packetParser.config"
import { Packet, RegexField } from "./packetParser.type"
import {
  convertToNumber,
  inferApplicationProtocol,
  setPacketKey,
} from "./packetParser.util"
import { IP_REGEX, TCPDUMP_HEADER_REGEX } from "./regex.const"

export const parseTcpdumpPacket = (str: string, lineIndex: number) => {
  const match = str.match(TCPDUMP_HEADER_REGEX)

  if (match && match.groups) {
    const { timestamp, srcIP, srcPort, dstIP, dstPort, protocol, rest } =
      match.groups

    const parsedPacket: Packet = {
      timestamp,
      srcIP,
      dstIP,
      protocol: protocol === "Flags" ? "TCP" : (protocol as Packet["protocol"]),
      srcPort: convertToNumber(srcPort),
      dstPort: convertToNumber(dstPort),
      line: lineIndex + 1
    }

    extractPacketDetails(parsedPacket, rest)
    return parsedPacket
  }
  return null //str does not match packet starcture
}

export const parsePartialPacket = (line: string, lineIndex: number) => {
  let packet: Partial<Packet> = {}
  extractFieldsFromRegex(PacketMetadataFields, line, packet)

  const ipMatch = line.match(IP_REGEX)
  if (ipMatch?.groups) {
    const { srcIP, srcPort, dstIP, dstPort } = ipMatch.groups
    const { protocol } = packet
    packet = {
      ...packet,
      srcIP,
      dstIP,
      srcPort: convertToNumber(srcPort),
      dstPort: convertToNumber(dstPort),
      protocol: protocol === "Flags" ? "TCP" : protocol,
      line: lineIndex + 1
    }
  }

  extractPacketDetails(packet, line)
  return packet
}

const extractPacketDetails = (
  packet: Partial<Packet>,
  details: string
) => {
  const regexFields = [...CommonPacketFields]
  if (packet.protocol === "TCP") regexFields.push(...TCPDetailsFields)
  else if (packet.protocol === "ICMP") regexFields.push(...ICMPDetailsFields)

  extractFieldsFromRegex(regexFields, details, packet)

  setPacketKey("applicationProtocol",inferApplicationProtocol(packet),packet ) 
}

const extractFieldsFromRegex = (
  regexFields: RegexField[],
  str: string,
  packet: Partial<Packet>
) =>
  regexFields.forEach(({ key, isNumeric, regex }) => {
    const value = str?.match(regex)?.[1]
    if (value) {
      setPacketKey(key, value, packet, isNumeric)
    }
  })
