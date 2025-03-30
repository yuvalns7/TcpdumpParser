import { Packet } from "../packetParser/packetParser.type"

export const isIPValid = (packet: Partial<Packet>, key: keyof Packet) => {
  const IP_REGEX =
    /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/
  const ip = packet[key] as string
  return !ip || ip.match(IP_REGEX)?.[1] !== undefined
}
export const isPortValid = (packet: Partial<Packet>, key: keyof Packet) => {
  const port = packet[key] as number
  return port === undefined || (port >= 0 && port <= 65535)
}

export const isPositiveOrZeroNumber = (packet: Partial<Packet>, key: keyof Packet) => {
  const port = packet[key] as number
  return port === undefined || (port >= 0)
}
export const isPositiveNumber = (packet: Partial<Packet>, key: keyof Packet) => {
  const port = packet[key] as number
  return port === undefined || (port > 0)
}

export const isRequiredField = (packet: Partial<Packet>, key: keyof Packet) =>
  packet[key] !== undefined

export const isUnexpectedField = (packet: Partial<Packet>, key: keyof Packet) =>
  packet[key] === undefined

export const isLengthValid = (packet: Partial<Packet>, key: keyof Packet) => {
  const length = packet[key] as number
  if (packet?.sequenceEnd && packet?.sequenceStart) {
    return length === packet.sequenceEnd - packet.sequenceStart
  }
  return true
}
export const isValidHttpPorts = (packet: Partial<Packet>) => {
  const httpPorts = new Set([80, 443]);
  return httpPorts.has(packet.dstPort ?? 0) || httpPorts.has(packet.srcPort ?? 0);
}