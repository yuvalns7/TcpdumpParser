import { PacketResult } from "../../tcpdumpProcessor.type";

export const ExtraFieldsToPrint: { key: keyof PacketResult; label: string }[] = [
  { key: "length", label: "Packet Length" },
  { key: "sequenceStart", label: "Sequence Start" },
  { key: "sequenceEnd", label: "Sequence End" },
  { key: "ack", label: "Acknowledgment Number" },
  { key: "win", label: "Window Size" },
  { key: "id", label: "Packet ID" },
  { key: "options", label: "Options" },
  { key: "http", label: "HTTP Data" },
  { key: "applicationProtocol", label: "Application Protocol" },
];
