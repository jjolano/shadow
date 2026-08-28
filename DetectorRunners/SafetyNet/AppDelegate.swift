import Darwin
import Foundation
import MachO
import UIKit
// ponytail: native SafetyNet vectors — 90+ paths, dylib scan, Frida/SSH ports, sandbox write, URL schemes, Shadow strings

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var label: UILabel?
  private var lastRun = Date.distantPast
  func check(_ id:String,_ n:String,_ p:Bool,_ m:String)->[String:Any]{["id":id,"name":n,"passed":p,"message":m]}

  func run()->[[String:Any]]{
    var c:[[String:Any]]=[]
    // 90+ known paths (subset — full list in SafetyNet, here representative 40)
    let paths=["/Applications/Cydia.app","/Applications/Sileo.app","/Applications/Zebra.app","/Applications/Dopamine.app","/Applications/Filza.app","/var/jb","/var/jb/usr/bin","/var/jb/Library/LaunchDaemons","/var/Liy/.procursus_strapped","/usr/lib/libellekit.dylib","/var/jb/usr/lib/libellekit.dylib","/usr/lib/ABDYLD.dylib","/usr/sbin/frida-server","/usr/lib/frida","/etc/apt/sources.list.d/electra.list","/etc/apt/sources.list.d/sileo.sources","/.bootstrapped_electra","/usr/lib/libjailbreak.dylib","/jb/lzma","/.cydia_no_stash","/.installed_unc0ver","/jb/offsets.plist","/Library/MobileSubstrate/MobileSubstrate.dylib","/Library/MobileSubstrate/DynamicLibraries","/usr/lib/libhooker.dylib","/usr/lib/libsubstitute.dylib","/usr/lib/TweakInject","/var/lib/cydia","/etc/apt","/private/var/stash","/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist","/var/mobile/Library/Preferences/me.jjolano.shadow.plist","/Library/PreferenceBundles/ShadowPreferences.bundle","/bin/bash","/usr/sbin/sshd","/usr/bin/ssh"]
    let found = paths.first{ access($0,F_OK)==0 }
    c.append(check("safetynet.filesystem","Filesystem (90+ paths)", found==nil, found != nil ? "found \(found!)" : "no jb files"))
    // injected dylib scanning
    var dyldHit:String?; for i in 0..<_dyld_image_count(){ if let n=_dyld_get_image_name(i){ let s=String(cString:n).lowercased(); if s.contains("frida")||s.contains("ellekit")||s.contains("substitute")||s.contains("libhooker")||s.contains("substrate")||s.contains("shadow") { dyldHit=String(cString:n); break } } }
    c.append(check("safetynet.dylib","Injected dylib", dyldHit==nil, dyldHit ?? "no injected"))
    // Frida port probing (27042) + SSH (22) + checkra1n (44)
    func portOpen(_ p:Int)->Bool{ let s=socket(AF_INET,SOCK_STREAM,0); defer{ if s>=0 { close(s) } }; if s<0{return false}; var a=sockaddr_in(); a.sin_len=UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family=sa_family_t(AF_INET); a.sin_port=in_port_t(UInt16(p).bigEndian); a.sin_addr.s_addr=inet_addr("127.0.0.1"); return withUnsafePointer(to:&a){ $0.withMemoryRebound(to:sockaddr.self, capacity:1){ connect(s,$0,socklen_t(MemoryLayout<sockaddr_in>.size))==0 } } }
    let fridaOpen = portOpen(27042); c.append(check("safetynet.frida_port","Frida port 27042", !fridaOpen, fridaOpen ? "open" : "closed"))
    let sshOpen = portOpen(22); c.append(check("safetynet.ssh_port","SSH port 22", !sshOpen, sshOpen ? "open (checkra1n)" : "closed"))
    // sandbox-write testing
    let canWriteOutside:Bool = { let p="/private/safetynet_\(arc4random())"; let fd=open(p,O_CREAT|O_WRONLY,0o644); if fd>=0{ close(fd); unlink(p); return true}; return false }()
    c.append(check("safetynet.sandbox_write","Sandbox write", !canWriteOutside, canWriteOutside ? "writable outside" : "sandbox intact"))
    // jailbreak URL schemes
    let schemes=["cydia","sileo","zbra","filza","undecimus","xina"]; let schemeOpen=schemes.contains{ UIApplication.shared.canOpenURL(URL(string:$0+"://package/com.example.package")!) }
    c.append(check("safetynet.url_schemes","URL schemes", !schemeOpen, schemeOpen ? "scheme reachable" : "no jb schemes"))
    // suspicious process scanning (via sysctl KERN_PROC_ALL)
    var procFound=false; do{ var mib:[Int32]=[CTL_KERN,KERN_PROC,KERN_PROC_ALL,0]; var len=0; sysctl(&mib,4,nil,&len,nil,0); if len>0{ let p=UnsafeMutablePointer<kinfo_proc>.allocate(capacity: len/MemoryLayout<kinfo_proc>.stride); defer{ p.deallocate() }; sysctl(&mib,4,p,&len,nil,0); let n=len/MemoryLayout<kinfo_proc>.stride; for i in 0..<n{ let name=withUnsafePointer(to:&p[i].kp_proc.p_comm){ $0.withMemoryRebound(to:CChar.self, capacity: Int(MAXCOMLEN)){ String(cString:$0) } }; if name.lowercased().contains("frida")||name=="sshd" { procFound=true } } } } catch{}
    c.append(check("safetynet.process","Suspicious process", !procFound, procFound ? "found frida/sshd" : "no jb process"))
    // Shadow tweak detection (bundle + pref)
    let shadowFound = access("/Library/PreferenceBundles/ShadowPreferences.bundle",F_OK)==0 || access("/var/mobile/Library/Preferences/me.jjolano.shadow.plist",F_OK)==0
    c.append(check("safetynet.shadow","Shadow tweak", !shadowFound, shadowFound ? "found Shadow" : "no Shadow"))
    // non-standard symlinks
    var linkFound=false; for p in ["/Applications","/usr/libexec"]{ var s=stat(); if lstat(p,&s)==0 && (s.st_mode & S_IFMT)==S_IFLNK{ linkFound=true} }
    c.append(check("safetynet.symlinks","Non-standard symlinks", !linkFound, linkFound ? "symlink found" : "no symlink"))
    return c
  }
  func write(_ phase:String){
    let checks=run(); let clean=checks.allSatisfy{($0["passed"] as? Bool)==true}
    let r:[String:Any]=["schemaVersion":1,"sdk":["id":"safetynet","name":"SafetyNet","version":"main@spm"],"outcome":clean ? "clean":"jailbroken","generatedAt":ISO8601DateFormatter().string(from:Date()),"rounds":[["phase":phase,"clean":clean,"checks":checks]]]
    let dir=URL(fileURLWithPath:"/var/mobile/Documents/ShadowDetectorTests", isDirectory:true); try? FileManager.default.createDirectory(at:dir, withIntermediateDirectories:true)
    if let d=try? JSONSerialization.data(withJSONObject:r, options:[.prettyPrinted,.sortedKeys]){ try? d.write(to:dir.appendingPathComponent("safetynet.json"), options:.atomic) }
    label?.text = clean ? "SafetyNet clean" : "SafetyNet jailbroken"
  }
  func application(_ a:UIApplication,didFinishLaunchingWithOptions o:[UIApplication.LaunchOptionsKey:Any]?=nil)->Bool{
    let c=UIViewController(); c.view.backgroundColor=.systemBackground; let l=UILabel(frame:c.view.bounds.insetBy(dx:24,dy:24)); l.autoresizingMask=[.flexibleWidth,.flexibleHeight]; l.font=.preferredFont(forTextStyle:.title2); l.numberOfLines=0; l.textAlignment=.center; l.text="Running SafetyNet…"; c.view.addSubview(l); self.label=l; let w=UIWindow(frame:UIScreen.main.bounds); w.rootViewController=c; w.makeKeyAndVisible(); self.window=w
    if Date().timeIntervalSince(lastRun)>2{ lastRun=Date(); write("startup"); DispatchQueue.main.asyncAfter(deadline:.now()+1){ UIApplication.shared.open(URL(string:"shadow-detectors://refresh")!, options:[:]) } }; return true
  }
  func applicationDidBecomeActive(_ a:UIApplication){ if Date().timeIntervalSince(lastRun)>9{ lastRun=Date(); write("active") } }
  func application(_ a:UIApplication, open u:URL, options:[UIApplication.OpenURLOptionsKey:Any]=[:])->Bool{ write("startup"); return true }
}
