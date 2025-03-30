import { DNS_PORT, TLS_PORT } from "../tcpdumpProcessor.const";
import { Packet } from "./packetParser.type"

export const convertToNumber = (str: string) =>
  str ? parseInt(str, 10) : undefined

export const parseTimestamp = (timestamp: string): number => {
  const match = timestamp.match(/^(\d{2}):(\d{2}):(\d{2})\.(\d{6})$/);
  if (!match) return 0; 

  const [, hours, minutes, seconds, microseconds] = match.map(Number);

  return (
    hours * 3_600_000_000 + 
    minutes * 60_000_000 + 
    seconds * 1_000_000 + 
    microseconds 
  );
};

export const setPacketKey = <K extends keyof Packet>(
  key: K,
  value: string,
  parsedPacket: Partial<Packet>,
  isNumeric: boolean = false
) => {
  parsedPacket[key] = isNumeric
    ? (convertToNumber(value) as Packet[K])
    : (value as Packet[K])
}

export const inferApplicationProtocol = (packet: Partial<Packet>): Packet["applicationProtocol"] => {
  if (packet?.http) return "HTTP"
  if (packet?.srcPort === DNS_PORT || packet?.dstPort === DNS_PORT) return "DNS"
  if (packet?.srcPort === TLS_PORT || packet?.dstPort === TLS_PORT) return "TLS"
  return undefined
}