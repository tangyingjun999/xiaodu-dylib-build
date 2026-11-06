//
//  XDProbe.m — 最小探针 dylib
//
//  只做三件事，不做任何 hook：
//    1. constructor 里立刻写一行日志（证明 dylib 被 dyld 加载并执行了）
//    2. 主队列异步再写一次（证明 Objective-C runtime / UIKit 可用）
//    3. 打印关键类是否存在（证明我们的目标类名没猜错）
//
//  为什么需要它：
//    在未越狱设备上 NSLog 走的是 syslog，你在手机上根本看不到。
//    所以把日志写进 App 沙盒的 Documents/xd_probe.log，用 Filza 就能看。
//    如果这个文件根本没生成 -> dylib 没被加载（注入/签名/依赖问题）
//    如果生成了但没有第二段   -> 卡在 constructor 之后（主队列没跑起来）
//    如果全部生成             -> 加载链路 OK，可以上完整版
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>

static NSString *XDDocsPath(NSString *name) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    NSString *doc = dirs.count ? dirs.firstObject : NSTemporaryDirectory();
    if (!doc) doc = @"/tmp";
    return [doc stringByAppendingPathComponent:name];
}

static void XDWrite(NSString *name, NSString *msg) {
    NSString *path = XDDocsPath(name);
    NSString *line = [NSString stringWithFormat:@"[%.3f] %@\n",
                      [NSDate date].timeIntervalSince1970, msg];
    NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        [fm createFileAtPath:path contents:d attributes:nil];
        return;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForUpdatingAtPath:path];
    if (!fh) return;
    @try {
        [fh seekToEndOfFile];
        [fh writeData:d];
    } @catch (NSException *e) { }
    [fh closeFile];
}

__attribute__((constructor)) static void XDProbeEntry(void) {
    // 第一行：能写出来就说明 constructor 执行了，这是最硬的证据。
    XDWrite(@"xd_probe.log", @"=== constructor fired ===");
    XDWrite(@"xd_probe.log", [NSString stringWithFormat:@"home = %@", NSHomeDirectory()]);
    XDWrite(@"xd_probe.log", [NSString stringWithFormat:@"bundle = %@",
                              [NSBundle mainBundle].bundleIdentifier]);
    XDWrite(@"xd_probe.log", [NSString stringWithFormat:@"os = %@",
                              [UIDevice currentDevice].systemVersion]);

    // 第二段：主队列可用性 + 目标类探测。
    dispatch_async(dispatch_get_main_queue(), ^{
        XDWrite(@"xd_probe.log", @"=== main queue reached ===");

        NSArray<NSString *> *classes = @[
            @"MSRewardVideoAd", @"MSRewardVideoAdTimer", @"MSRewardReporter",
            @"MSRewardVideoView", @"MSRewardVideoAdTaskView", @"MSRewardH5ViewController",
            @"MSRewardVideoAdLoaderManager", @"BBAJSBindingRewardedVideoAd",
            @"BBAJSBindingRewardedVideoAdInner", @"ATMSRewardedVideoDelegate",
            @"ATMSRewardedVideoAdapter", @"ATMSRewardedVideoCustomEvent"
        ];
        for (NSString *cn in classes) {
            Class c = NSClassFromString(cn);
            NSUInteger count = 0;
            if (c) {
                unsigned int n = 0;
                Method *list = class_copyMethodList(c, &n);
                count = n;
                if (list) free(list);
                // 把方法名也记下来，避免后面 Hook 猜错 selector
                NSMutableArray *names = [NSMutableArray array];
                unsigned int m = 0;
                Method *ml = class_copyMethodList(c, &m);
                for (unsigned int i = 0; i < m; i++) {
                    [names addObject:NSStringFromSelector(method_getName(ml[i]))];
                }
                if (ml) free(ml);
                XDWrite(@"xd_probe.log",
                        [NSString stringWithFormat:@"class %@ : %lu methods\n    %@",
                         cn, (unsigned long)count,
                         [names componentsJoinedByString:@", "]]);
            } else {
                XDWrite(@"xd_probe.log",
                        [NSString stringWithFormat:@"class %@ : NOT FOUND", cn]);
            }
        }
        XDWrite(@"xd_probe.log", @"=== probe done ===");
    });
}
