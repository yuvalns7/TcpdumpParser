import { Packet } from "../packetParser/packetParser.type"
import { PACKET_TIMESTAMP_REGEX } from "../packetParser/regex.const"
import { AnomalyRule } from "./anomalyDetector.type"
import {
  isIPValid,
  isLengthValid,
  isPortValid,
  isPositiveNumber,
  isPositiveOrZeroNumber,
  isUnexpectedField,
  isValidHttpPorts,
} from "./anomalyDetector.util"

export const StracturePacketFields: {
  index: number
  regex: RegExp
  label: string
}[] = [
  { index: 0, regex: PACKET_TIMESTAMP_REGEX, label: "Timestamp" },
  {
    index: 1,
    regex: /^IP$/,
    label: "Layer 3 Protocol",
  },
  {
    index: 2,
    regex: /^(?:\d{1,3}(?:\.\d{1,3}){3})(?:\.\d+)?$/,
    label: "Source IP",
  },
  {
    index: 3,
    regex: />/,
    label: "> sign",
  },
  {
    index: 4,
    regex: /^(?:\d{1,3}(?:\.\d{1,3}){3})(?:\.\d+)?:$/,
    label: "Destination IP",
  },
  {
    index: 5,
    regex: /UDP|ICMP|Flags/,
    label: "Protocol",
  },
]

export const BaseAnomalyRules: AnomalyRule[] = [
  {
    key: "srcIP",
    label: "source Ip",
    type: "IncorrectFormat",
    isValid: isIPValid,
    explanation:
      "ip should have four octets and that each octet is in the range 0–255",
  },
  {
    key: "dstIP",
    label: "destination Ip",
    type: "IncorrectFormat",
    isValid: isIPValid,
    explanation:
      "ip should have four octets and that each octet is in the range 0–255",
  },
  {
    key: "srcPort",
    label: "source port",
    isValid: isPortValid,
    type: "IncorrectFormat",
    explanation: "port needs to be in range of 0-65535",
  },
  {
    key: "dstPort",
    label: "destination port",
    isValid: isPortValid,
    type: "IncorrectFormat",
    explanation: "port needs to be in range of 0-65535",
  },
  {
    key: "length",
    label: "length",
    type: "IncorrectFormat",
    isValid: isPositiveOrZeroNumber,
    explanation: "length cant be negative number",
  },
  {
    key: "sequenceStart",
    label: "sequence start",
    type: "IncorrectFormat",
    isValid: isPositiveOrZeroNumber,
    explanation: "seq should be positive number",
  },
  {
    key: "win",
    label: "window size",
    type: "IncorrectFormat",
    isValid: isPositiveOrZeroNumber,
    explanation: "window size should be positive number",
  },
  {
    key: "length",
    label: "length",
    type: "IncorrectFormat",
    explanation:
      "length should be consistent with the difference in sequence numbers if a range is provided",
    isValid: isLengthValid,
  },
  {
    key: "id",
    label: "id",
    type: "IncorrectFormat",
    isValid: isPositiveOrZeroNumber,
    explanation: "id should be positive number",
  },
]

export const TCPAnomaliesRules: AnomalyRule[] = [
  {
    key: "srcPort",
    label: "source port",
    type: "TCPrequiredField",
    explanation: "source port is required for TCP protocol packet",
  },
  {
    key: "dstPort",
    label: "destination port",
    type: "TCPrequiredField",
    explanation: "destination port is required for TCP protocol packet",
  },
  {
    key: "flags",
    label: "flags",
    type: "TCPrequiredField",
    explanation: "flags are required for TCP protocol packet",
  },
]

export const SynFlagRules: AnomalyRule[] = [
  {
    key: "sequenceStart",
    label: "sequence start",
    type: "TCPrequiredField",
    explanation: "seq is required for TCP protocol packet with SYN flag",
  },
  {
    key: "ack",
    label: "ack",
    type: "IncorrectKey",
    isValid: isUnexpectedField,
    explanation: "ack should not appear in TCP protocol packet with SYN flag",
  },
  {
    key: "sequenceEnd",
    label: "sequence End",
    type: "IncorrectKey",
    isValid: isUnexpectedField,
    explanation:
      "sequence range should not appear in TCP protocol packet with SYN flag",
  },
]

export const SynAckFlagsRules: AnomalyRule[] = [
  {
    key: "sequenceStart",
    label: "sequence start",
    type: "TCPrequiredField",
    explanation: "seq is required for TCP protocol packet with SYN ACK flags",
  },
  {
    key: "length",
    label: "length",
    type: "TCPrequiredField",
    explanation:
      "length is required for TCP protocol packet with SYN ACK flags",
  },
  {
    key: "win",
    label: "window size",
    type: "TCPrequiredField",
    explanation: "win is required for TCP protocol packet with SYN ACK flags",
  },
  {
    key: "ack",
    label: "ack",
    type: "TCPrequiredField",
    explanation: "ack is required for TCP protocol packet with SYN ACK flags",
  },
]

export const AckFlagsRules: AnomalyRule[] = [
  {
    key: "ack",
    label: "ack",
    type: "TCPrequiredField",
    explanation: "ack is required for TCP protocol packet with ACK flags",
  },
  {
    key: "win",
    label: "window size",
    type: "TCPrequiredField",
    explanation: "win is required for TCP protocol packet with ACK flags",
  },
]

export const DataFlagRules: AnomalyRule[] = [
  {
    key: "ack",
    label: "ack",
    type: "TCPrequiredField",
    explanation: "ack is required for TCP protocol packet with Data flags",
  },
  {
    key: "sequenceStart",
    label: "sequence start",
    type: "TCPrequiredField",
    explanation: "seq is required for TCP protocol packet with Data flags",
  },
  {
    key: "length",
    label: "length",
    type: "TCPrequiredField",
    explanation: "length is required for TCP protocol packet with Data flags",
  },
  {
    key: "length",
    label: "length",
    type: "IncorrectFormat",
    isValid: isPositiveNumber,
    explanation: "length should be above 0 in data packet",
  },
  {
    key: "win",
    label: "window size",
    type: "TCPrequiredField",
    explanation: "win is required for TCP protocol packet with Data flags",
  },
]

export const UDPRules: AnomalyRule[] = [
  {
    key: "srcPort",
    label: "source port",
    type: "UDPrequiredField",
    explanation: "source port is required for UDP protocol packet",
  },
  {
    key: "dstPort",
    label: "destination port",
    type: "UDPrequiredField",
    explanation: "destination port is required for UDP protocol packet",
  },
  {
    key: "length",
    label: "length",
    type: "UDPrequiredField",
    explanation: "length is required for UDP protocol packet",
  },
]

export const ICMPRules: AnomalyRule[] = [
  {
    key: "sequenceStart",
    label: "sequence start",
    type: "ICMPrequiredField",
    explanation: "seq is required for ICMP protocol packet",
  },
  {
    key: "id",
    label: "id",
    type: "ICMPrequiredField",
    explanation: "id is required for ICMP protocol packet",
  },
  {
    key: "length",
    label: "length",
    type: "ICMPrequiredField",
    explanation: "length is required for ICMP protocol packet",
  },
]

export const HTTPRules: AnomalyRule[] = [
  {
    key: "http",
    label: "HTTP data",
    type: "IncorrectFormat",
    explanation: "HTTP data should only appear on valid HTTP ports (80, 443)",
    isValid: isValidHttpPorts,
  },
]

export const DNSRules: AnomalyRule[] = [
  {
    key: "length",
    label: "DNS packet length",
    type: "IncorrectFormat",
    explanation: "DNS packets should have a minimum length of 12 bytes",
    isValid: (packet: Partial<Packet>) => {
      return packet.length !== undefined && packet.length >= 12
    },
  },
  {
    key: "srcPort",
    label: "Source Port",
    type: "IncorrectFormat",
    explanation:
      "DNS requests are usually from high-numbered ports (>1024) and sent to port 53",
    isValid: (packet: Partial<Packet>) => {
      return packet.srcPort === undefined || packet.srcPort > 1024
    },
  },
  {
    key: "protocol",
    label: "Protocol",
    type: "IncorrectFormat",
    explanation: "DNS is typically UDP, but can also be TCP in some cases",
    isValid: (packet: Partial<Packet>) => {
      return packet.protocol === "UDP" || packet.protocol === "TCP"
    },
  },
]

export const ProtocolAnomalies: Record<string, AnomalyRule[]> = {
  TCP: [...TCPAnomaliesRules],
  UDP: [...UDPRules],
  ICMP: [...ICMPRules],
}

export const FlagAnomalies: Record<string, AnomalyRule[]> = {
  "[S]": SynFlagRules,
  "[S.]": SynAckFlagsRules,
  "[.]": AckFlagsRules,
  "[P.]": DataFlagRules,
  // TODO: add more flags combinations
}
