import Foundation

func runnerCallback(_ url: URL?) -> String? {
  guard let url,
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
        let callback = components.queryItems?.first(where: { $0.name == "callback" })?.value,
        !callback.isEmpty else { return nil }
  return callback
}

@discardableResult
func runnerFinish(_ identifier: String,
                  _ name: String,
                  _ version: String,
                  _ outcome: String,
                  _ rounds: [[String: Any]],
                  _ timing: [String: Any]?,
                  _ callback: String) -> Bool {
  var report: [String: Any] = [
    "schemaVersion": 1,
    "sdk": ["id": identifier, "name": name, "version": version],
    "outcome": outcome,
    "generatedAt": ISO8601DateFormatter().string(from: Date()),
    "rounds": rounds
  ]
  if let timing { report["timing"] = timing }
  guard let data = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]),
        let json = String(data: data, encoding: .utf8) else { return false }
  return json.withCString { reportPointer in
    callback.withCString { callbackPointer in
      SHDWRunnerSendJSON(reportPointer, callbackPointer) != 0
    }
  }
}
