import { PacketResult } from "../../tcpdumpProcessor.type";
import { formatValue } from "../printer.util";
import { Logger } from "../logger";

const printPacket = (packet: PacketResult, logger: Logger) => {
  if (packet.isMalformed) logger.log(`-------Packet is Malformed-------`);
  
  logger.log(`Timestamp: ${formatValue(packet.timestamp)}`);
  logger.log(
    `Source IP: ${formatValue(packet.srcIP)}${
      packet.srcPort ? `, Source Port: ${packet.srcPort}` : ""
    }`
  );
  logger.log(
    `Destination IP: ${formatValue(packet.dstIP)}${
      packet.dstPort ? `, Destination Port: ${packet.dstPort}` : ""
    }`
  );
  logger.log(
    `Protocol: ${formatValue(packet.protocol)}${
      packet.flags ? ` (Flags: ${packet.flags})` : ""
    }`
  );
  if (packet?.applicationProtocol)
    logger.log(
      `Application Protocol: ${formatValue(packet.applicationProtocol)}`
    );
  logger.log("");
};

export const printPackets = (packets: PacketResult[], logger: Logger) => {
  logger.logSeparator();
  logger.log("📢 Output of Parsed tcpdump Data:");
  logger.logSeparator();
  packets.forEach((p) => printPacket(p, logger));
};
