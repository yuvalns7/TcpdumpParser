import { Packet } from "../packetParser/packetParser.type"
import {
  BaseAnomalyRules,
  DNSRules,
  FlagAnomalies,
  HTTPRules,
  ProtocolAnomalies,
  StracturePacketFields,
} from "./anomalyDetector.config"
import { Anomaly, AnomalyRule } from "./anomalyDetector.type"
import { isRequiredField } from "./anomalyDetector.util"

export const detectStructuralAnomalies = (
  line: string,
  lineIndex: number
): Anomaly[] => {
  const anomalies: Anomaly[] = []
  const words = line.split(/\s+/)

  StracturePacketFields.forEach(({ index, regex, label }) => {
    const expectedWord = words[index]

    if (!regex) return

    if (!expectedWord) {
      anomalies.push({
        lineIndex,
        type: "IncorrectFormat",
        keyLabel: label,
      })
      return
    }

    if (!expectedWord?.match(regex)) {
      const isMisplaced = words.some((word) => regex.test(word))

      anomalies.push({
        lineIndex,
        type: isMisplaced ? "IncorrectPlace" : "MissingField",
        keyLabel: label,
      })

      return
    }
  })

  return anomalies
}

const applyAnomalyRuleChecks = (
  packet: Partial<Packet>,
  anomalies: Anomaly[],
  lineIndex: number,
  anomalyFieldChecks: AnomalyRule[]
) =>
  anomalyFieldChecks.forEach(
    ({ key, label, isValid = isRequiredField, type, explanation }) => {
      if (!isValid(packet, key)) {
        return anomalies.push({
          keyLabel: label,
          lineIndex,
          type,
          explanation,
        })
      }
    }
  )

export const detectPacketAnomalies = (
  packet: Partial<Packet>,
  lineIndex: number
) => {
  const anomalies: Anomaly[] = []
  const anomalyChecks = [...BaseAnomalyRules]

  if (packet.protocol && ProtocolAnomalies[packet.protocol])
    anomalyChecks.push(...ProtocolAnomalies[packet.protocol])

  if (packet.protocol === "TCP" && packet.flags && FlagAnomalies[packet.flags])
    anomalyChecks.push(...FlagAnomalies[packet.flags])

  if (packet.http) 
    anomalyChecks.push(...HTTPRules)

  if (packet.dstPort === 53) 
    anomalyChecks.push(...DNSRules)
  
  applyAnomalyRuleChecks(packet, anomalies, lineIndex, anomalyChecks)
  return anomalies
}
