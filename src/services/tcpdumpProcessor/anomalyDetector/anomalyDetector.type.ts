import { Packet } from "../packetParser/packetParser.type"

export type AnomalyType =
  | "MissingField"
  | "IncorrectPlace"
  | "TCPrequiredField"
  | "ICMPrequiredField"
  | "UDPrequiredField"
  | "IncorrectFormat"
  | "IncorrectKey"

export type Anomaly = {
  lineIndex: number
  type: AnomalyType
  keyLabel: string
  explanation?: string
}

export type AnomalyRule = {
  key: keyof Packet
  label: string
  isValid?: (packet: Partial<Packet>, key: keyof Packet) => boolean
  type: AnomalyType
  explanation?: string
}
