//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <Security/Security.h>
#include <string.h>
#include "desktop_darwin.h"

extern void gatewayOpenConfig(void);

@interface GatewayMenuDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, retain) NSStatusItem *statusItem;
@property(nonatomic) BOOL showInitially;
@end

static void gatewayStopOnMainThread(void) {
    [NSApp stop:nil];
    // stop 不会唤醒正在等待事件的 run 循环，补发一个空事件完成退出。
    [NSApp postEvent:[NSEvent otherEventWithType:NSEventTypeApplicationDefined
        location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0
        context:nil subtype:0 data1:0 data2:0] atStart:YES];
}

@implementation GatewayMenuDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    NSImage *image = [NSImage imageWithSystemSymbolName:@"shield.lefthalf.filled" accessibilityDescription:@"安全网关"];
    image.template = YES;
    self.statusItem.button.image = image;
    if (!image) self.statusItem.button.title = @"网关";
    self.statusItem.button.toolTip = @"Codex 安全网关";

    NSMenu *menu = [[[NSMenu alloc] initWithTitle:@"安全网关"] autorelease];
    NSMenuItem *open = [menu addItemWithTitle:@"打开管理界面" action:@selector(openConfig:) keyEquivalent:@""];
    open.target = self;
    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quit = [menu addItemWithTitle:@"退出" action:@selector(quit:) keyEquivalent:@"q"];
    quit.target = self;
    self.statusItem.menu = menu;
    if (self.showInitially) gatewayOpenConfig();
}
- (void)openConfig:(id)sender { gatewayOpenConfig(); }
- (void)quit:(id)sender { gatewayStopOnMainThread(); }
- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)visible {
    gatewayOpenConfig();
    return NO;
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    // 先返回 Go 回收代理、审计库和单实例锁，再由主函数退出。
    gatewayStopOnMainThread();
    return NSTerminateCancel;
}
- (void)dealloc {
    if (_statusItem) [[NSStatusBar systemStatusBar] removeStatusItem:_statusItem];
    [_statusItem release];
    [super dealloc];
}
@end

int gateway_tray_run(int showInitially) {
    if (![NSThread isMainThread]) return 1;
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        GatewayMenuDelegate *delegate = [[GatewayMenuDelegate alloc] init];
        delegate.showInitially = showInitially != 0;
        [NSApp setDelegate:delegate];
        [NSApp run];
        [NSApp setDelegate:nil];
        [delegate release];
    }
    return 0;
}

void gateway_tray_stop(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ gatewayStopOnMainThread(); });
}

void gateway_desktop_error(const char *message) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        NSAlert *alert = [[[NSAlert alloc] init] autorelease];
        alert.messageText = @"Codex 安全网关";
        alert.informativeText = [NSString stringWithUTF8String:message];
        alert.alertStyle = NSAlertStyleCritical;
        [alert addButtonWithTitle:@"确定"];
        [alert runModal];
    }
}

int gateway_keychain_key(const char *service, int create, unsigned char *output) {
    @autoreleasepool {
        NSDictionary *identity = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: [NSString stringWithUTF8String:service],
            (id)kSecAttrAccount: @"desktop-settings-key-v1"
        };
        NSMutableDictionary *query = [[identity mutableCopy] autorelease];
        query[(id)kSecReturnData] = @YES;
        query[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
        if (status == errSecItemNotFound && create) {
            unsigned char key[32];
            status = SecRandomCopyBytes(kSecRandomDefault, sizeof(key), key);
            if (status != errSecSuccess) return status;
            NSMutableDictionary *attributes = [[identity mutableCopy] autorelease];
            attributes[(id)kSecValueData] = [NSData dataWithBytes:key length:sizeof(key)];
            attributes[(id)kSecAttrLabel] = @"Codex 安全网关设置加密密钥";
            attributes[(id)kSecAttrAccessible] = (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
            status = SecItemAdd((CFDictionaryRef)attributes, NULL);
            // 使用 volatile 写入，避免编译器删除临时密钥清零操作。
            volatile unsigned char *clearKey = key;
            for (size_t index = 0; index < sizeof(key); index++) clearKey[index] = 0;
            // 并发首次保存只允许创建一个密钥，随后读取已经提交的值。
            if (status != errSecSuccess && status != errSecDuplicateItem) return status;
            status = SecItemCopyMatching((CFDictionaryRef)query, &result);
        }
        if (status != errSecSuccess) return status;
        if (!result || CFGetTypeID(result) != CFDataGetTypeID() || CFDataGetLength(result) != 32) {
            if (result) CFRelease(result);
            return errSecDecode;
        }
        memcpy(output, CFDataGetBytePtr(result), 32);
        CFRelease(result);
        return errSecSuccess;
    }
}
