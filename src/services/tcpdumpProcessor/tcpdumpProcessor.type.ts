import { Packet } from "./packetParser/packetParser.type";

export type PacketResult = Partial<Packet> & { isMalformed: boolean }