import { Anomaly, AnomalyType } from "../../anomalyDetector/anomalyDetector.type";

export const AnomalyMessagesMap: Record<Anomaly["type"], (lineIndex: number, keyLabel: string) => string> = {
  MissingField: (line, key) => `Line ${line + 1} is missing ${key}.`,
  IncorrectPlace: (line, key) => `Line ${line + 1}: ${key} is not found where expected.`,
  TCPrequiredField: (line, key) => `Line ${line + 1} (TCP) is missing required field: ${key}.`,
  UDPrequiredField: (line, key) => `Line ${line + 1} (UDP) is missing required field: ${key}.`,
  ICMPrequiredField: (line, key) => `Line ${line + 1} (ICMP) is missing required field: ${key}.`,
  IncorrectFormat: (line, key) => `Line ${line + 1}: ${key} is incorrectly formatted.`,
  IncorrectKey: (line, key) => `Line ${line + 1}: ${key} should not be present.`,
};

export const AnomalyTypeOrder: AnomalyType[] = [
  "MissingField",
  "TCPrequiredField",
  "UDPrequiredField",
  "ICMPrequiredField",
  "IncorrectFormat",
  "IncorrectPlace",
  "IncorrectKey",
];

export const AnomalyTypeToLabels: Record<AnomalyType, string> = {
  MissingField: "Missing Fields",
  TCPrequiredField: "TCP Required Fields Missing",
  UDPrequiredField: "UDP Required Fields Missing",
  ICMPrequiredField: "ICMP Required Fields Missing",
  IncorrectFormat: "Incorrect Format",
  IncorrectPlace: "Fields in Incorrect Place",
  IncorrectKey: "Unexpected Fields",
};