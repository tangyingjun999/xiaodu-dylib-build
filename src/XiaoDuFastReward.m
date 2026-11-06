//
//  XiaoDuFastReward.m — 完整版注入 dylib（小度 6.0.0 / Watson / com.baidu.superduer）
//
//  与 Frida Gadget 方案的区别（这是关键）：
//    本 dylib 不做任何代码页修改。全部 Hook 都是 ObjC runtime 的数据层操作：
//      method_setImplementation / class_copyMethodList / class_getInstanceMethod
//    这些只改 runtime 的方法表与 IMP 指针，属于数据写入，
//      不需要 Interceptor，不需要 JIT，不需要 CS_DEBUGGED。
//    所以它在未越狱（仅 TrollStore）的设备上依然可用 —— 这正是 Frida Gadget 做不到的。
//
//  策略：保留真实广告请求（show_custom_ext / third_trans_id 是服务端 S2S 核销凭证），
//        只短路客户端的「播放时长 / 校验闸门 / 完成通知」，并掐断京东跳转。
//        实测协议重放 collect / ON_REWARD（含真实票据）curAdCount 3->3，
//        所以必须让 SDK 自己走完成回调。
//
//  日志：所有输出同时写到 App 沙盒 Documents/xd_hook.log（NSLog 在真机上看不到）。
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <string.h>

static NSString * const kTag = @"[XDFastReward] ";
static NSString * const kLogName = @"xd_hook.log";

#pragma mark - file logging

static void XDWrite(NSString *msg) {
    NSString *line = [NSString stringWithFormat:@"[%.3f] %@\n",
                      [NSDate date].timeIntervalSince1970, msg];
    NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSString *path = nil;
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                       NSUserDomainMask, YES);
    if (dirs.count) path = [dirs.firstObject stringByAppendingPathComponent:kLogName];
    if (!path) path = [NSTemporaryDirectory() stringByAppendingPathComponent:kLogName];

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

#define XDLog(fmt, ...) do { \
    NSString *__s = [NSString stringWithFormat:fmt, ##__VA_ARGS__]; \
    NSLog(@"%@%@", kTag, __s); \
    XDWrite([kTag stringByAppendingString:__s]); \
} while (0)

// ---- 精确类名（砸壳二进制确认） ------------------------------------------
static NSArray<NSString *> *XDRewardClasses(void) {
    return @[@"MSRewardVideoAd", @"MSRewardVideoAdTimer", @"MSRewardReporter",
             @"MSRewardVideoView", @"MSRewardVideoAdTaskView", @"MSRewardH5ViewController",
             @"MSRewardVideoAdLoaderManager", @"BBAJSBindingRewardedVideoAd",
             @"BBAJSBindingRewardedVideoAdInner", @"ATMSRewardedVideoDelegate",
             @"ATMSRewardedVideoAdapter", @"ATMSRewardedVideoCustomEvent"];
}
static NSArray<NSString *> *XDTriggerViews(void) {
    return @[@"MSRewardVideoAdTaskView", @"MSRewardVideoView",
             @"MSRewardH5View", @"MSRewardAdWebView"];
}

// 完成/通知类 selector（抓包事件 + 二进制符号）
static NSArray<NSString *> *XDRewardSelectors(void) {
    return @[@"msRewardVideoReward", @"msRewardVideoFinish", @"msRewardVideoClosed",
             @"msRewardVideoClickSkip", @"skipAdToShowEndCover", @"notifyH5SkipCountDown",
             @"webBridgeH5NotifyRewarded", @"notifyRewarded", @"msVideoCompletion",
             @"serverVerifyReward", @"onReward"];
}

static BOOL gFired = NO;
static NSInteger gFireCount = 0;
static NSInteger gBlocked = 0;
static NSInteger gGateCount = 0;
static IMP gOrigOpenURL = NULL;
static IMP gOrigOpenURLWithOptions = NULL;

#pragma mark - helpers

static BOOL XDIsAdJump(NSString *s) {
    if (!s.length) return NO;
    NSArray *bad = @[@"jd.com", @"360buy", @"openapp.jdmobile", @"item.m.jd",
                     @"pangolin", @"gdt.qq.com", @"jdcloud"];
    NSString *low = s.lowercaseString;
    for (NSString *b in bad) if ([low containsString:b]) return YES;
    return NO;
}

// Only invoke selectors that genuinely take no explicit arguments; calling a
// method with (id, NSDictionary*) using objc_msgSend(self, sel) would read
// garbage registers and crash.
static void XDSend(id obj, NSString *selName) {
    if (!obj || !selName.length) return;
    SEL sel = NSSelectorFromString(selName);
    if (!sel || ![obj respondsToSelector:sel]) return;
    Class c = object_getClass(obj);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (method_getNumberOfArguments(m) != 2) return;
    @try {
        ((void (*)(id, SEL))objc_msgSend)(obj, sel);
        XDLog(@"sent -[%@ %@]", NSStringFromClass([obj class]), selName);
    } @catch (NSException *e) { XDLog(@"send fail %@: %@", selName, e.reason); }
}

static void XDSendClass(NSString *clsName, NSString *selName) {
    Class c = NSClassFromString(clsName);
    if (!c) return;
    SEL sel = NSSelectorFromString(selName);
    Method m = class_getClassMethod(c, sel);
    if (!m || method_getNumberOfArguments(m) != 2) return;
    @try {
        ((void (*)(id, SEL))objc_msgSend)((id)c, sel);
        XDLog(@"sent +[%@ %@]", clsName, selName);
    } @catch (NSException *e) { XDLog(@"send class fail %@: %@", selName, e.reason); }
}

static UIView *XDFindView(UIView *root, int depth) {
    if (!root || depth > 40) return nil;
    NSString *cn = NSStringFromClass([root class]);
    for (NSString *t in XDTriggerViews()) if ([cn isEqualToString:t]) return root;
    for (UIView *sub in root.subviews) {
        UIView *hit = XDFindView(sub, depth + 1);
        if (hit) return hit;
    }
    return nil;
}

static NSArray<UIWindow *> *XDWindows(void) {
    NSMutableArray *out = [NSMutableArray array];
    if (@available(iOS 15.0, *)) {
        UIApplication *app = [UIApplication sharedApplication];
        for (UIWindow *w in app.windows) if (!w.hidden) [out addObject:w];
    } else {
        UIWindow *w = [UIApplication sharedApplication].keyWindow;
        if (w) [out addObject:w];
    }
    return out;
}

#pragma mark - forced completion

static void XDForceReward(UIView *anchor) {
    gFireCount++;
    XDLog(@"forceReward #%ld anchor=%@", (long)gFireCount,
          anchor ? NSStringFromClass([anchor class]) : @"nil");

    NSMutableArray *targets = [NSMutableArray array];
    if (anchor) [targets addObject:anchor];
    for (NSString *key in @[@"delegate", @"rewardAd", @"reporter", @"manager", @"viewController"]) {
        @try {
            id v = [anchor valueForKey:key];
            if (v && v != anchor) [targets addObject:v];
        } @catch (NSException *e) { }
    }
    UIResponder *r = anchor;
    while ((r = [r nextResponder])) {
        if ([r isKindOfClass:[UIViewController class]]) { [targets addObject:r]; break; }
    }

    for (id t in targets)
        for (NSString *sel in XDRewardSelectors())
            XDSend(t, sel);

    for (NSString *cn in @[@"BBAJSBindingRewardedVideoAd", @"BBAJSBindingRewardedVideoAdInner"])
        for (NSString *sel in @[@"webBridgeH5NotifyRewarded", @"notifyH5SkipCountDown", @"notifyRewarded"])
            XDSendClass(cn, sel);

    XDLog(@"forceReward done, targets=%lu", (unsigned long)targets.count);
}

static void XDTick(void) {
    UIView *anchor = nil;
    for (UIWindow *w in XDWindows()) {
        anchor = XDFindView(w, 0);
        if (anchor) break;
    }
    if (!anchor) { gFired = NO; return; }
    if (gFired) return;
    gFired = YES;
    XDLog(@"detected rewarded-ad view %@", NSStringFromClass([anchor class]));
    // Let the SDK finish loading/bidding first so it has a valid trans_id.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ XDForceReward(anchor); });
}

#pragma mark - timer / verify getters -> 0 / 1

static unichar XDReturnChar(Method m) {
    const char *enc = method_getTypeEncoding(m);
    if (!enc) return 0;
    while (*enc && strchr("rnNoORV", *enc)) enc++;   // skip qualifiers
    return (unichar)*enc;
}

static BOOL XDIsIntegerReturn(unichar c) {
    return strchr("cCiIsSlLqQB", (char)c) != NULL;
}

static void XDSwizzleGates(void) {
    NSRegularExpression *timeRe = [NSRegularExpression
        regularExpressionWithPattern:@"(rewardtime|countdown|remainingtime|reductionsecond|playedduration|currentplaytime)"
                             options:NSRegularExpressionCaseInsensitive error:nil];
    NSRegularExpression *verifyRe = [NSRegularExpression
        regularExpressionWithPattern:@"(serververify|verifyreward|checkcountdownreward|checktwostagereward|canreward|isrewardfinish)"
                             options:NSRegularExpressionCaseInsensitive error:nil];

    for (NSString *cn in XDRewardClasses()) {
        Class c = NSClassFromString(cn);
        if (!c) { XDLog(@"class missing: %@", cn); continue; }
        unsigned int n = 0;
        Method *list = class_copyMethodList(c, &n);
        for (unsigned int i = 0; i < n; i++) @autoreleasepool {
            Method m = list[i];
            SEL sel = method_getName(m);
            NSString *sn = NSStringFromSelector(sel);
            NSRange r = NSMakeRange(0, sn.length);
            BOOL isTime = [timeRe firstMatchInString:sn options:0 range:r] != nil;
            BOOL isVerify = [verifyRe firstMatchInString:sn options:0 range:r] != nil;
            if (!isTime && !isVerify) continue;
            if (method_getNumberOfArguments(m) != 2) continue;   // getter only
            if (!XDIsIntegerReturn(XDReturnChar(m))) continue;    // skip double / id
            long long fixed = isTime ? 0 : 1;
            IMP rep = imp_implementationWithBlock(^long long(id selfObj) { return fixed; });
            IMP old = method_setImplementation(m, rep);
            if (old != rep) {
                gGateCount++;
                XDLog(@"gate -[%@ %@] -> %lld", cn, sn, fixed);
            }
        }
        if (list) free(list);
    }
    XDLog(@"gates patched: %ld", (long)gGateCount);
}

#pragma mark - jump blocker

static BOOL XDOpenURLIMP(id selfObj, SEL _cmd, NSURL *url) {
    NSString *s = [url absoluteString] ?: @"";
    if (XDIsAdJump(s)) {
        gBlocked++;
        XDLog(@"blocked jump #%ld: %@", (long)gBlocked,
              [s substringToIndex:MIN((NSUInteger)120, s.length)]);
        return NO;
    }
    if (gOrigOpenURL) return ((BOOL (*)(id, SEL, NSURL *))gOrigOpenURL)(selfObj, _cmd, url);
    return NO;
}

static void XDOpenURLOptionsIMP(id selfObj, SEL _cmd, NSURL *url,
                                NSDictionary *options, void (^completion)(BOOL)) {
    NSString *s = [url absoluteString] ?: @"";
    if (XDIsAdJump(s)) {
        gBlocked++;
        XDLog(@"blocked jump(options) #%ld: %@", (long)gBlocked,
              [s substringToIndex:MIN((NSUInteger)120, s.length)]);
        if (completion) completion(NO);
        return;
    }
    if (gOrigOpenURLWithOptions) {
        ((void (*)(id, SEL, NSURL *, NSDictionary *, void (^)(BOOL)))gOrigOpenURLWithOptions)
            (selfObj, _cmd, url, options, completion);
    } else if (completion) {
        completion(NO);
    }
}

static void XDHookOpenURL(void) {
    Class app = NSClassFromString(@"UIApplication");
    if (!app) return;
    Method m1 = class_getInstanceMethod(app, @selector(openURL:));
    if (m1) {
        IMP old = method_setImplementation(m1, (IMP)XDOpenURLIMP);
        if (old != (IMP)XDOpenURLIMP) { gOrigOpenURL = old; XDLog(@"hooked -openURL:"); }
    }
    Method m2 = class_getInstanceMethod(app,
                NSSelectorFromString(@"openURL:options:completionHandler:"));
    if (m2) {
        IMP old = method_setImplementation(m2, (IMP)XDOpenURLOptionsIMP);
        if (old != (IMP)XDOpenURLOptionsIMP) {
            gOrigOpenURLWithOptions = old;
            XDLog(@"hooked -openURL:options:completionHandler:");
        }
    }
}

#pragma mark - entry

__attribute__((constructor)) static void XDEntry(void) {
    // 第一行就写盘：能写出来说明 dylib 已被 dyld 加载且 constructor 执行。
    XDLog(@"=== loaded (com.baidu.superduer) ===");
    XDLog(@"home=%@ os=%@", NSHomeDirectory(), [UIDevice currentDevice].systemVersion);

    dispatch_async(dispatch_get_main_queue(), ^{
        XDLog(@"=== main queue reached, installing hooks ===");
        XDSwizzleGates();
        XDHookOpenURL();

        // 每 5 秒轮询一次是否有激励视频视图出现；同时每 60 秒打一次心跳。
        __block NSInteger beats = 0;
        NSTimer *t = [NSTimer scheduledTimerWithTimeInterval:5.0 repeats:YES block:^(NSTimer *timer) {
            XDTick();
            beats++;
            if (beats % 12 == 0) {
                XDLog(@"heartbeat gates=%ld blocked=%ld fires=%ld",
                      (long)gGateCount, (long)gBlocked, (long)gFireCount);
            }
        }];
        [[NSRunLoop mainRunLoop] addTimer:t forMode:NSRunLoopCommonModes];
        XDLog(@"=== ready: timer gates + jump blocker + auto-completion armed ===");
    });
}
