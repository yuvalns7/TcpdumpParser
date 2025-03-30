import { RegexField } from "./packetParser.type";
import {  PACKET_TIMESTAMP_REGEX } from "./regex.const";

  export const PacketMetadataFields: RegexField[] = [
    {
      key: "timestamp",
      isNumeric: false,
      regex: PACKET_TIMESTAMP_REGEX,
     
    },
    { key: "flags", isNumeric: false, regex: /Flags\s*\[([^\]]+)\]/ },
    { key: "protocol", isNumeric: false, regex: /\b(UDP|ICMP|Flags)\b/}
  ]
  
export const CommonPacketFields: RegexField[] = [
    {
      key: "length",
      regex: /\blength\s+(-?\d+)/,
      isNumeric: true,
    },
    {
      key: "sequenceStart",
      regex: /\bseq\s+(-?\d+)/,
      isNumeric: true,
    },
    {
      key: "sequenceEnd",
      regex: /\bseq\s+\d+:(-?\d+)/,
      isNumeric: true,
    },
  ]
  
  export const TCPDetailsFields: RegexField[] = [
    {
      key: "flags",
      regex: /\s*(\[[^\]]+\])/,
      isNumeric: false,
    },
    {
      key: "win",
      regex: /\bwin\s+(-?\d+)/,
      isNumeric: true,
    },
    {
      key: "options",
      regex: /\boptions\s*\[([^\]]+)\]/,
      isNumeric: false,
    },
    {
      key: "ack",
      regex: /\back\s+(\d+)/,
      isNumeric: false,
    },
    {
      key: "http",
      regex: /:HTTP:\s*(.+)$/,
      isNumeric: false,
    },
  ]
  
  export const ICMPDetailsFields: RegexField[] = [
    {
      key: "id",
      regex: /\bid\s+(-?\d+)/,
      isNumeric: true,
    },
  ]
  