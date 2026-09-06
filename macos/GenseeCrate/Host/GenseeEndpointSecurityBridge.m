#import "GenseeEndpointSecurityBridge.h"
#import <sys/sysctl.h>
#import <errno.h>
#import <os/log.h>

NSArray<NSNumber *> *GenseeDescendantProcessIdentifiers(pid_t rootPID)
{
    if (rootPID <= 0) return @[];
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t byteCount = 0;
    struct kinfo_proc *processes = NULL;
    // The process table may grow between probe and fetch. Bound both memory
    // and retries, reserve slack, and report failure instead of hiding a gap.
    const size_t maximumBytes = 64 * 1024 * 1024;
    for (NSUInteger attempt = 0; attempt < 3; attempt++) {
        if (sysctl(mib, 4, NULL, &byteCount, NULL, 0) != 0) {
            os_log_error(OS_LOG_DEFAULT, "Gensee Cowork process snapshot probe failed: errno=%d", errno);
            return @[];
        }
        if (byteCount > maximumBytes / 2) break;
        size_t capacity = byteCount + byteCount / 4 + 32 * sizeof(struct kinfo_proc);
        processes = malloc(capacity);
        if (processes == NULL) break;
        byteCount = capacity;
        if (sysctl(mib, 4, processes, &byteCount, NULL, 0) == 0) break;
        int snapshotError = errno;
        free(processes);
        processes = NULL;
        if (snapshotError != ENOMEM) {
            os_log_error(OS_LOG_DEFAULT, "Gensee Cowork process snapshot failed: errno=%d", snapshotError);
            return @[];
        }
    }
    if (processes == NULL) {
        os_log_error(OS_LOG_DEFAULT, "Gensee Cowork descendant adoption incomplete: process snapshot exceeded retry/resource limit");
        return @[];
    }

    NSUInteger processCount = byteCount / sizeof(struct kinfo_proc);
    NSMutableDictionary<NSNumber *, NSMutableArray<NSNumber *> *> *childrenByParent =
        [NSMutableDictionary dictionary];
    for (NSUInteger index = 0; index < processCount; index++) {
        pid_t pid = processes[index].kp_proc.p_pid;
        pid_t parentPID = processes[index].kp_eproc.e_ppid;
        if (pid <= 0 || parentPID <= 0) continue;
        NSNumber *parent = @(parentPID);
        NSMutableArray<NSNumber *> *children = childrenByParent[parent];
        if (children == nil) {
            children = [NSMutableArray array];
            childrenByParent[parent] = children;
        }
        [children addObject:@(pid)];
    }
    free(processes);

    NSMutableArray<NSNumber *> *queue = [NSMutableArray arrayWithObject:@(rootPID)];
    NSMutableArray<NSNumber *> *descendants = [NSMutableArray array];
    NSMutableSet<NSNumber *> *seen = [NSMutableSet setWithObject:@(rootPID)];
    for (NSUInteger index = 0; index < queue.count; index++) {
        for (NSNumber *child in childrenByParent[queue[index]] ?: @[]) {
            if ([seen containsObject:child]) continue;
            [seen addObject:child];
            [queue addObject:child];
            [descendants addObject:child];
        }
    }
    return descendants;
}

@protocol GenseeEndpointSecurityRemote
- (void)fetchEventsAfterCursor:(uint64_t)cursor
                         limit:(NSUInteger)limit
                     withReply:(void (^)(NSArray<NSDictionary *> *events,
                                         uint64_t nextCursor,
                                         NSDictionary *health))reply;
- (void)healthWithReply:(void (^)(NSDictionary *health))reply;
- (void)updateConfiguration:(NSDictionary *)configuration
                   withReply:(void (^)(BOOL accepted, NSString *_Nullable message))reply;
@end

@interface GenseeEndpointSecurityBridge ()
@property(nonatomic) NSXPCConnection *connection;
@end

@implementation GenseeEndpointSecurityBridge

- (instancetype)initWithMachServiceName:(NSString *)serviceName
                  codeSigningRequirement:(NSString *)requirement
{
    self = [super init];
    if (self) {
        _connection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName
                                                               options:NSXPCConnectionPrivileged];
        _connection.remoteObjectInterface =
            [NSXPCInterface interfaceWithProtocol:@protocol(GenseeEndpointSecurityRemote)];
        if (@available(macOS 13.0, *)) {
            [_connection setCodeSigningRequirement:requirement];
        }
        __weak typeof(self) weakSelf = self;
        _connection.interruptionHandler = ^{
            dispatch_block_t handler = weakSelf.interruptionHandler;
            if (handler != nil) handler();
        };
        _connection.invalidationHandler = ^{
            dispatch_block_t handler = weakSelf.invalidationHandler;
            if (handler != nil) handler();
        };
    }
    return self;
}

- (void)activate
{
    [self.connection activate];
}

- (void)invalidate
{
    [self.connection invalidate];
}

- (id<GenseeEndpointSecurityRemote>)proxyWithFailure:(GenseeEndpointSecurityFailure)failure
{
    return [self.connection remoteObjectProxyWithErrorHandler:failure];
}

- (void)fetchEventsAfterCursor:(uint64_t)cursor
                         limit:(NSUInteger)limit
                         reply:(GenseeEndpointSecurityEventsReply)reply
                       failure:(GenseeEndpointSecurityFailure)failure
{
    [[self proxyWithFailure:failure] fetchEventsAfterCursor:cursor limit:limit withReply:reply];
}

- (void)updateConfiguration:(NSDictionary *)configuration
                       reply:(GenseeEndpointSecurityConfigurationReply)reply
                     failure:(GenseeEndpointSecurityFailure)failure
{
    [[self proxyWithFailure:failure] updateConfiguration:configuration withReply:reply];
}

@end
