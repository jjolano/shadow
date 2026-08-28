import Darwin
import Foundation
import MachO
import ObjectiveC
import UIKit
// ponytail: filtered DSK — jailbreak/hook/swizzling/dyld/frida only, 14.0 buildable, gated at runtime if iOS <15

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  private var label: UILabel?
  private var lastRun = Date.distantPast

  func check(_ id:String,_ n:String,_ p:Bool,_ m:String)->[String:Any]{["id":id,"name":n,"passed":p,"message":m]}

  // ARM64 hook prologue inspection — check first instructions for suspicious trampoline
  func hasHookPrologue(_ sym: String)->Bool {
    guard let p = dlsym(UnsafeMutableRawPointer(bitPattern: -2), sym) else { return false }
    let ptr = unsafeBitCast(p, to: UnsafePointer<UInt32>.self)
    let first = ptr.pointee
    // hook trampolines often start with ldr/b : 0x58000000, 0x14000000, 0xd61f, 0x58000051 etc
    // ponytail: naive first-word heuristic, upgrade to full ARM64 decode if throughput matters
    return first == 0x58000051 || (first & 0xFC000000) == 0x14000000
  }

  func isSwizzled(_ cls: AnyClass, _ sel: Selector)->Bool {
    guard let m = class_getInstanceMethod(cls, sel) else { return false }
    var info = Dl_info()
    guard dladdr(unsafeBitCast(method_getImplementation(m), to: UnsafeRawPointer.self), &info)==1, let f=info.dli_fname else { return false }
    let img=String(cString:f).lowercased(); let bin=String(cString:_dyld_get_image_name(0)).lowercased()
    return !(img.contains("/system/library/") || img.contains(bin))
  }

  func run()->[[String:Any]]{
    var c:[[String:Any]]=[]
    // gating: if iOS <15, report gated (harness also hides Run)
    if #available(iOS 15, *) {} else {
      c.append(check("dsk.gated","iOS version", false, "Requires iOS 15"))
      return c
    }
    // jailbreak subset
    let jbFiles=["/var/jb","/Applications/Cydia.app","/Library/MobileSubstrate/MobileSubstrate.dylib","/usr/lib/libhooker.dylib","/usr/lib/libellekit.dylib"]
    let found = jbFiles.first{ access($0,F_OK)==0 }
    c.append(check("dsk.jailbreak.files","Jailbreak files", found==nil, found != nil ? "found \(found!)" : "clean"))
    c.append(check("dsk.jailbreak.schemes","Jailbreak schemes", !UIApplication.shared.canOpenURL(URL(string:"cydia://package/com.example.package")!), UIApplication.shared.canOpenURL(URL(string:"cydia://package/com.example.package")!) ? "cydia reachable" : "no schemes"))
    // dyld
    var dyldHit:String?; for i in 0..<_dyld_image_count(){ if let n=_dyld_get_image_name(i){ let s=String(cString:n).lowercased(); if s.contains("frida")||s.contains("ellekit")||s.contains("substitute")||s.contains("libhooker") { dyldHit=String(cString:n); break } } }
    c.append(check("dsk.jailbreak.dyld","Dyld images", dyldHit==nil, dyldHit ?? "no jb dyld"))
    // frida multi-port
    func portOpen(_ p:Int)->Bool{ let s=socket(AF_INET,SOCK_STREAM,0); defer{if s>=0{close(s)}}; if s<0{return false}; var a=sockaddr_in(); a.sin_len=UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family=sa_family_t(AF_INET); a.sin_port=in_port_t(UInt16(p).bigEndian); a.sin_addr.s_addr=inet_addr("127.0.0.1"); return withUnsafePointer(to:&a){ $0.withMemoryRebound(to:sockaddr.self, capacity:1){ connect(s,$0,socklen_t(MemoryLayout<sockaddr_in>.size))==0 } } }
    let frida = portOpen(27042)||portOpen(27043); c.append(check("dsk.frida.ports","Frida ports", !frida, frida ? "frida port open" : "closed"))
    // hook detection via prologue
    let hookSymbols=["stat","access","fork","open","readlink"]; var hookFound=false; var hookSym=""
    for s in hookSymbols{ if hasHookPrologue(s){ hookFound=true; hookSym=s; break } }
    c.append(check("dsk.hook.prologue","Hook prologue (ARM64)", !hookFound, hookFound ? "hook on \(hookSym)" : "no prologue hook"))
    // swizzling — FileManager fileExists, UIApplication canOpenURL, LAContext evaluatePolicy (if LA)
    c.append(check("dsk.swizzling.filemanager","Swizzling FileManager", !isSwizzled(FileManager.self, #selector(FileManager.fileExists(atPath:))), isSwizzled(FileManager.self, #selector(FileManager.fileExists(atPath:))) ? "swizzled" : "not swizzled"))
    c.append(check("dsk.swizzling.uiapplication","Swizzling UIApplication", !isSwizzled(UIApplication.self, #selector(UIApplication.canOpenURL(_:))), isSwizzled(UIApplication.self, #selector(UIApplication.canOpenURL(_:))) ? "swizzled" : "not swizzled"))
    // substrate/hooker libs loaded
    if let dylibs = _dyld_image_count() as UInt32? {
      // already covered, add explicit allowlist check
      c.append(check("dsk.reverse","Reverse engineering", dyldHit==nil, dyldHit==nil ? "no inject" : "injected \(dyldHit!)"))
    }
    return c
  }

  func write(_ phase:String){
    let checks=run(); let gated = checks.contains{ ($0["id"] as? String)=="dsk.gated" }
    let clean = !gated && checks.allSatisfy{($0["passed"] as? Bool)==true}
    let outcome = gated ? "notRun" : (clean ? "clean" : "jailbroken")
    let r:[String:Any]=["schemaVersion":1,"sdk":["id":"devicesecuritykit","name":"DeviceSecurityKit","version":"0.40.0-filtered"],"outcome":outcome,"generatedAt":ISO8601DateFormatter().string(from:Date()),"rounds":[["phase":phase,"clean":clean,"checks":checks]]]
    let dir=URL(fileURLWithPath:"/var/mobile/Documents/ShadowDetectorTests", isDirectory:true); try? FileManager.default.createDirectory(at:dir, withIntermediateDirectories:true)
    if let d=try? JSONSerialization.data(withJSONObject:r, options:[.prettyPrinted,.sortedKeys]){ try? d.write(to:dir.appendingPathComponent("devicesecuritykit.json"), options:.atomic) }
    label?.text = gated ? "Requires iOS 15" : (clean ? "DSK clean" : "DSK jailbroken")
  }

  func application(_ a:UIApplication,didFinishLaunchingWithOptions o:[UIApplication.LaunchOptionsKey:Any]?=nil)->Bool{
    let c=UIViewController(); c.view.backgroundColor=.systemBackground; let l=UILabel(frame:c.view.bounds.insetBy(dx:24,dy:24)); l.autoresizingMask=[.flexibleWidth,.flexibleHeight]; l.font=.preferredFont(forTextStyle:.title2); l.numberOfLines=0; l.textAlignment=.center; l.text="Running DSK…"; c.view.addSubview(l); self.label=l; let w=UIWindow(frame:UIScreen.main.bounds); w.rootViewController=c; w.makeKeyAndVisible(); self.window=w
    if Date().timeIntervalSince(lastRun)>2{ lastRun=Date(); write("startup"); DispatchQueue.main.asyncAfter(deadline:.now()+1){ UIApplication.shared.open(URL(string:"shadow-detectors://refresh")!, options:[:]) } }; return true
  }
  func applicationDidBecomeActive(_ a:UIApplication){ if Date().timeIntervalSince(lastRun)>9{ lastRun=Date(); write("active") } }
  func application(_ a:UIApplication, open u:URL, options:[UIApplication.OpenURLOptionsKey:Any]=[:])->Bool{ write("startup"); return true }
}
