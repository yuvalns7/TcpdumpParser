export const TCPDUMP_HEADER_REGEX = /^(?<timestamp>\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(?<srcIP>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?<srcPort>\d+))?\s*>\s*(?<dstIP>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?<dstPort>\d+))?:\s*(?:"?(?<protocol>Flags|UDP|ICMP)"?)(?<rest>.*)$/
export const PACKET_TIMESTAMP_REGEX = /(\d{2}:\d{2}:\d{2}\.\d{6})/
export const IP_REGEX = /(?<srcIP>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?<srcPort>\d+))?\s*>\s*(?<dstIP>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?<dstPort>\d+))?/
