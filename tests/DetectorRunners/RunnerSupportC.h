// Keep the Swift bridge C-only. Importing Foundation from a Swift bridging
// header conflicts with the Linux Theos SDK's host Dispatch module.
int SHDWRunnerSendJSON(const char *reportJSON, const char *callbackURL);
const char *SHDWFreeRASPGenericProbeJSON(void);
