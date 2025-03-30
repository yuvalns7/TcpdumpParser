export type ConnectionKey = string
export type HandshakeStatus = {
  hasSyn: boolean
  hasSynAck: boolean
  hasAck: boolean
}

export type FlagTypes = "syn" | "synAck" | "ack"
type FlagCheck = { key: string; isIncluded: boolean }

export const FlagsChecks: Record<FlagTypes, FlagCheck[]> = {
  ["syn"]: [
    {
      key: "S",
      isIncluded: true,
    },
    {
      key: ".",
      isIncluded: false,
    },
  ],
  ["synAck"]: [
    {
      key: "S",
      isIncluded: true,
    },
    {
      key: ".",
      isIncluded: true,
    },
  ],
  ["ack"]: [
    {
      key: "S",
      isIncluded: false,
    },
    {
      key: ".",
      isIncluded: true,
    },
  ],
}
