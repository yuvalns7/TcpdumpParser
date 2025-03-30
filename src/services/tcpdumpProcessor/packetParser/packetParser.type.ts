export type Packet = {
  line: number
  timestamp: string
  srcIP: string
  dstIP: string
  protocol: "UDP" | "ICMP" | "TCP" | "Flags"

  srcPort?: number
  dstPort?: number
  length?: number;
  sequenceStart?: number
  sequenceEnd?: number
  id?: number;
  flags?: string;  
  win?: number;
  ack?: number;
  options?: string;
  http?: string;
  applicationProtocol?: "HTTP" | "DNS" | "TLS"
}

export type RegexField = {
  key: keyof Packet
  regex: RegExp
  isNumeric: boolean
}

