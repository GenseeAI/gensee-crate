#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <bsm/libbsm.h>
#import <fcntl.h>
#import <mach/mach_time.h>
#import <math.h>
#import <os/log.h>
#import <sys/sysctl.h>

#import "GenseeEndpointSecurityXPC.h"

static NSString *const GenseeHostRequirement =
    @"anchor apple generic and certificate leaf[subject.OU] = \"3KWVB4M63F\" and identifier \"ai.gensee.crate\"";
static const NSUInteger GenseeRingCapacity = 20000;

static os_log_t GenseeLog(void)
{
    static os_log_t log;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        log = os_log_create("ai.gensee.crate.endpoint-security", "sensor");
    });
    return log;
}

static NSString *GenseeStringFromToken(es_string_token_t token)
{
    if (token.data == NULL || token.length == 0) {
        return @"";
    }
    NSString *value = [[NSString alloc] initWithBytes:token.data
                                               length:token.length
                                             encoding:NSUTF8StringEncoding];
    return value ?: @"<invalid-utf8>";
}

static NSString *GenseeBootID(void)
{
    static NSString *bootID;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        char value[128] = {0};
        size_t length = sizeof(value);
        if (sysctlbyname("kern.bootsessionuuid", value, &length, NULL, 0) == 0 && value[0] != '\0') {
            bootID = [NSString stringWithUTF8String:value];
        }
        if (bootID.length == 0) {
            bootID = @"unknown-boot";
        }
    });
    return bootID;
}

static NSString *GenseeEventName(es_event_type_t type)
{
    switch (type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
        case ES_EVENT_TYPE_NOTIFY_EXEC: return @"exec";
        case ES_EVENT_TYPE_NOTIFY_FORK: return @"fork";
        case ES_EVENT_TYPE_NOTIFY_EXIT: return @"exit";
        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN: return @"open";
        case ES_EVENT_TYPE_NOTIFY_CLOSE: return @"close";
        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_NOTIFY_CREATE: return @"create";
        case ES_EVENT_TYPE_NOTIFY_WRITE: return @"write";
        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_NOTIFY_RENAME: return @"rename";
        case ES_EVENT_TYPE_AUTH_UNLINK:
        case ES_EVENT_TYPE_NOTIFY_UNLINK: return @"unlink";
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE: return @"truncate";
        case ES_EVENT_TYPE_AUTH_READDIR:
        case ES_EVENT_TYPE_NOTIFY_READDIR: return @"readdir";
        case ES_EVENT_TYPE_NOTIFY_MMAP: return @"mmap";
        default: return @"unknown";
    }
}

static NSDictionary *GenseeFileDictionary(const es_file_t *file)
{
    if (file == NULL) {
        return @{};
    }
    return @{
        @"path": GenseeStringFromToken(file->path),
        @"path_truncated": @(file->path_truncated),
        @"device": @((uint64_t)file->stat.st_dev),
        @"inode": @((uint64_t)file->stat.st_ino),
        @"mode": @((uint32_t)file->stat.st_mode),
    };
}

static NSDictionary *GenseeProcessDictionary(const es_process_t *process, uint32_t messageVersion)
{
    if (process == NULL) {
        return @{};
    }
    NSMutableDictionary *result = [@{
        @"pid": @(audit_token_to_pid(process->audit_token)),
        @"pidversion": @((uint32_t)audit_token_to_pidversion(process->audit_token)),
        @"ppid": @(process->ppid),
        @"executable_path": process->executable != NULL
            ? GenseeStringFromToken(process->executable->path)
            : @"<unknown>",
        @"signing_id": GenseeStringFromToken(process->signing_id),
        @"team_id": GenseeStringFromToken(process->team_id),
        @"platform_binary": @(process->is_platform_binary),
        @"is_es_client": @(process->is_es_client),
        @"codesigning_flags": @(process->codesigning_flags),
    } mutableCopy];
    if (messageVersion >= 3) {
        uint64_t start = (uint64_t)process->start_time.tv_sec * 1000ULL;
        start += (uint64_t)process->start_time.tv_usec / 1000ULL;
        result[@"start_time_ms"] = @(start);
    }
    if (messageVersion >= 4) {
        result[@"parent_pidversion"] = @((uint32_t)audit_token_to_pidversion(process->parent_audit_token));
        result[@"responsible_pid"] = @(audit_token_to_pid(process->responsible_audit_token));
        result[@"responsible_pidversion"] = @((uint32_t)audit_token_to_pidversion(process->responsible_audit_token));
    }
    return result;
}

static BOOL GenseeIsOwnProcess(const es_process_t *process)
{
    if (process == NULL || process->is_es_client) return YES;
    NSString *path = process->executable != NULL
        ? GenseeStringFromToken(process->executable->path)
        : @"";
    NSString *signingID = GenseeStringFromToken(process->signing_id);
    NSString *teamID = GenseeStringFromToken(process->team_id);
    if ([teamID isEqualToString:@"3KWVB4M63F"] &&
        ([signingID isEqualToString:@"ai.gensee.crate"] ||
         [signingID isEqualToString:@"ai.gensee.crate.endpoint-security"] ||
         [signingID isEqualToString:@"ai.gensee.crate.cli"])) {
        return YES;
    }
    return [path containsString:@"/Gensee Crate.app/Contents/"];
}

static NSString *GenseeDestinationPath(const es_file_t *directory, es_string_token_t filename)
{
    NSString *name = GenseeStringFromToken(filename);
    if (directory == NULL) return name.length > 0 ? name : @"<unknown>";
    NSString *directoryPath = GenseeStringFromToken(directory->path);
    if (directoryPath.length == 0) return name.length > 0 ? name : @"<unknown>";
    if (name.length == 0) return directoryPath;
    return [directoryPath stringByAppendingPathComponent:name] ?: directoryPath;
}

static NSDictionary *GenseeNewPathFile(const es_file_t *directory, es_string_token_t filename, mode_t mode)
{
    NSMutableDictionary *result = [@{
        @"path": GenseeDestinationPath(directory, filename) ?: @"<unknown>",
        @"mode": @((uint32_t)mode),
    } mutableCopy];
    if (directory != NULL) {
        result[@"path_truncated"] = @(directory->path_truncated);
        result[@"device"] = @((uint64_t)directory->stat.st_dev);
    }
    return result;
}

static NSString *_Nullable GenseeAuthorizationPath(const es_message_t *message)
{
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
            return GenseeStringFromToken(message->event.exec.target->executable->path);
        case ES_EVENT_TYPE_AUTH_OPEN:
            return GenseeStringFromToken(message->event.open.file->path);
        case ES_EVENT_TYPE_AUTH_CREATE:
            if (message->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                return GenseeStringFromToken(message->event.create.destination.existing_file->path);
            }
            return GenseeDestinationPath(message->event.create.destination.new_path.dir,
                                         message->event.create.destination.new_path.filename);
        case ES_EVENT_TYPE_AUTH_RENAME:
            return GenseeStringFromToken(message->event.rename.source->path);
        case ES_EVENT_TYPE_AUTH_UNLINK:
            return GenseeStringFromToken(message->event.unlink.target->path);
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return GenseeStringFromToken(message->event.truncate.target->path);
        case ES_EVENT_TYPE_AUTH_READDIR:
            return GenseeStringFromToken(message->event.readdir.target->path);
        default:
            return nil;
    }
}

static NSString *_Nullable GenseeSecondaryAuthorizationPath(const es_message_t *message)
{
    if (message->event_type != ES_EVENT_TYPE_AUTH_RENAME) {
        return nil;
    }
    if (message->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        return GenseeStringFromToken(message->event.rename.destination.existing_file->path);
    }
    return GenseeDestinationPath(message->event.rename.destination.new_path.dir,
                                 message->event.rename.destination.new_path.filename);
}

static BOOL GenseeIsAbsoluteStringArray(id value)
{
    if (value == nil) return YES;
    if (![value isKindOfClass:NSArray.class]) return NO;
    for (id item in (NSArray *)value) {
        if (![item isKindOfClass:NSString.class] ||
            [(NSString *)item length] == 0 ||
            ![(NSString *)item hasPrefix:@"/"]) {
            return NO;
        }
    }
    return YES;
}

static uint64_t GenseeElapsedMicroseconds(uint64_t start)
{
    static mach_timebase_info_data_t timebase;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ mach_timebase_info(&timebase); });
    uint64_t elapsed = mach_absolute_time() - start;
    __uint128_t nanos = (__uint128_t)elapsed * timebase.numer / timebase.denom;
    return (uint64_t)(nanos / 1000ULL);
}

static NSDictionary *GenseeSerializeMessage(const es_message_t *message,
                                             NSString *mode,
                                             NSString *result,
                                             NSString *_Nullable ruleID,
                                             NSString *_Nullable reason,
                                             uint64_t latencyMicroseconds)
{
    uint64_t observedAt = (uint64_t)message->time.tv_sec * 1000ULL;
    observedAt += (uint64_t)message->time.tv_nsec / 1000000ULL;
    NSMutableDictionary *event = [@{
        @"schema_version": @1,
        @"event_id": NSUUID.UUID.UUIDString,
        @"boot_id": GenseeBootID(),
        @"observed_at_ms": @(observedAt),
        @"event_type": GenseeEventName(message->event_type),
        @"action": message->action_type == ES_ACTION_TYPE_AUTH ? @"auth" : @"notify",
        @"message_version": @(message->version),
        @"actor": GenseeProcessDictionary(message->process, message->version),
        @"arguments": @[],
        @"attribution": @{},
        @"decision": @{
            @"mode": mode,
            @"result": result,
            @"cache": @NO,
            @"latency_us": @(latencyMicroseconds),
        },
    } mutableCopy];
    NSMutableDictionary *decision = [event[@"decision"] mutableCopy];
    if (ruleID.length > 0) decision[@"rule_id"] = ruleID;
    if (reason.length > 0) decision[@"reason"] = reason;
    event[@"decision"] = decision;
    if (message->version >= 2) {
        event[@"seq_num"] = @(message->seq_num);
    }
    if (message->version >= 4) {
        event[@"global_seq_num"] = @(message->global_seq_num);
    }

    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
        case ES_EVENT_TYPE_NOTIFY_EXEC: {
            const es_event_exec_t *exec = &message->event.exec;
            event[@"target"] = GenseeProcessDictionary(exec->target, message->version);
            uint32_t count = MIN(es_exec_arg_count(exec), 128U);
            NSMutableArray<NSString *> *arguments = [NSMutableArray arrayWithCapacity:count];
            NSUInteger bytes = 0;
            for (uint32_t index = 0; index < count; index++) {
                NSString *argument = GenseeStringFromToken(es_exec_arg(exec, index));
                bytes += argument.length;
                if (bytes > 16384) break;
                [arguments addObject:argument];
            }
            event[@"arguments"] = arguments;
            if (message->version >= 2 && exec->script != NULL) {
                event[@"script"] = GenseeStringFromToken(exec->script->path);
            }
            if (message->version >= 3 && exec->cwd != NULL) {
                event[@"cwd"] = GenseeStringFromToken(exec->cwd->path);
            }
            break;
        }
        case ES_EVENT_TYPE_NOTIFY_FORK:
            event[@"target"] = GenseeProcessDictionary(message->event.fork.child, message->version);
            break;
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            event[@"exit_status"] = @(message->event.exit.stat);
            break;
        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            event[@"file"] = GenseeFileDictionary(message->event.open.file);
            event[@"open_flags"] = @(message->event.open.fflag);
            break;
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            event[@"file"] = GenseeFileDictionary(message->event.close.target);
            event[@"modified"] = @(message->event.close.modified);
            break;
        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            if (message->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                event[@"file"] = GenseeFileDictionary(message->event.create.destination.existing_file);
            } else {
                event[@"file"] = GenseeNewPathFile(message->event.create.destination.new_path.dir,
                                                    message->event.create.destination.new_path.filename,
                                                    message->event.create.destination.new_path.mode);
            }
            break;
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            event[@"file"] = GenseeFileDictionary(message->event.write.target);
            break;
        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            event[@"file"] = GenseeFileDictionary(message->event.rename.source);
            if (message->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                event[@"destination"] = GenseeFileDictionary(message->event.rename.destination.existing_file);
            } else {
                event[@"destination"] = GenseeNewPathFile(message->event.rename.destination.new_path.dir,
                                                           message->event.rename.destination.new_path.filename,
                                                           0);
            }
            break;
        case ES_EVENT_TYPE_AUTH_UNLINK:
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            event[@"file"] = GenseeFileDictionary(message->event.unlink.target);
            break;
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            event[@"file"] = GenseeFileDictionary(message->event.truncate.target);
            break;
        case ES_EVENT_TYPE_AUTH_READDIR:
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            event[@"file"] = GenseeFileDictionary(message->event.readdir.target);
            break;
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            event[@"file"] = GenseeFileDictionary(message->event.mmap.source);
            event[@"open_flags"] = @(message->event.mmap.protection);
            break;
        default:
            break;
    }
    return event;
}

@interface GenseeSensorService : NSObject <GenseeEndpointSecurityXPC, NSXPCListenerDelegate>
@property(nonatomic) dispatch_queue_t queue;
@property(nonatomic) NSMutableArray<NSDictionary *> *events;
@property(nonatomic) uint64_t nextCursor;
@property(nonatomic) uint64_t totalEvents;
@property(nonatomic) uint64_t ringDrops;
@property(nonatomic) uint64_t lastGlobalSequence;
@property(nonatomic) uint64_t kernelDrops;
@property(nonatomic) uint64_t reportedDrops;
@property(nonatomic) NSString *mode;
@property(nonatomic) NSArray<NSString *> *protectedPaths;
@property(nonatomic) NSSet<NSString *> *blockedExecutables;
@property(nonatomic) NSDictionary<NSNumber *, NSString *> *managedRoots;
@property(nonatomic) NSMutableDictionary<NSString *, NSString *> *managedProcesses;
@property(nonatomic) uint64_t maxAuthorizationLatencyUS;
@property(nonatomic) uint64_t authorizationCount;
@property(nonatomic) uint64_t deniedCount;
@property(nonatomic) uint64_t maximumAuthorizationLatency;
@property(nonatomic) es_client_t *client;
@property(nonatomic) NSXPCListener *listener;
@end

@implementation GenseeSensorService

- (instancetype)init
{
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("ai.gensee.crate.endpoint-security.event-ring", DISPATCH_QUEUE_SERIAL);
        _events = [NSMutableArray arrayWithCapacity:GenseeRingCapacity];
        _nextCursor = 1;
        _mode = @"observe";
        _protectedPaths = @[];
        _blockedExecutables = [NSSet set];
        _managedRoots = @{};
        _managedProcesses = [NSMutableDictionary dictionary];
        _maxAuthorizationLatencyUS = 10000;
    }
    return self;
}

- (void)startListener
{
    NSString *serviceName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"NSEndpointSecurityMachServiceName"];
    self.listener = [[NSXPCListener alloc] initWithMachServiceName:serviceName];
    if (@available(macOS 13.0, *)) {
        [self.listener setConnectionCodeSigningRequirement:GenseeHostRequirement];
    }
    self.listener.delegate = self;
    [self.listener activate];
    os_log_info(GenseeLog(), "XPC sensor service listening as %{public}@", serviceName);
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection
{
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(GenseeEndpointSecurityXPC)];
    connection.exportedObject = self;
    [connection activate];
    os_log_info(GenseeLog(), "accepted signed host connection pid=%d uid=%d",
                connection.processIdentifier, connection.effectiveUserIdentifier);
    return YES;
}

- (NSString *)keyForProcess:(const es_process_t *)process
{
    return [NSString stringWithFormat:@"%d:%d",
            audit_token_to_pid(process->audit_token),
            audit_token_to_pidversion(process->audit_token)];
}

- (NSString *_Nullable)sessionForProcessLocked:(const es_process_t *)process
                                messageVersion:(uint32_t)messageVersion
{
    NSString *key = [self keyForProcess:process];
    NSString *session = self.managedProcesses[key];
    if (session != nil) return session;
    NSNumber *pid = @(audit_token_to_pid(process->audit_token));
    session = self.managedRoots[pid];
    if (session != nil) {
        self.managedProcesses[key] = session;
        return session;
    }
    if (messageVersion >= 4) {
        NSString *parentKey = [NSString stringWithFormat:@"%d:%d",
                               audit_token_to_pid(process->parent_audit_token),
                               audit_token_to_pidversion(process->parent_audit_token)];
        session = self.managedProcesses[parentKey];
        if (session != nil) self.managedProcesses[key] = session;
    }
    return session;
}

- (BOOL)path:(NSString *)path hasProtectedPrefixLocked:(NSArray<NSString *> *)prefixes
{
    for (NSString *prefix in prefixes) {
        if ([path isEqualToString:prefix]) return YES;
        NSString *directoryPrefix = [prefix hasSuffix:@"/"] ? prefix : [prefix stringByAppendingString:@"/"];
        if ([path hasPrefix:directoryPrefix]) return YES;
    }
    return NO;
}

- (NSNumber *_Nullable)rootPIDForSessionLocked:(NSString *)session
{
    for (NSNumber *pid in self.managedRoots) {
        if ([self.managedRoots[pid] isEqualToString:session]) return pid;
    }
    return nil;
}

- (BOOL)isOwnProcessLocked:(const es_process_t *)process
{
    return GenseeIsOwnProcess(process);
}

- (void)authorizeMessage:(const es_message_t *)message
                   result:(NSString **)result
                   ruleID:(NSString **)ruleID
                   reason:(NSString **)reason
                latencyUS:(uint64_t *)latencyUS
{
    uint64_t started = mach_absolute_time();
    __block BOOL deny = NO;
    __block NSString *decisionRule = nil;
    __block NSString *decisionReason = nil;
    __block uint64_t authorizationBudgetUS = 10000;
    @synchronized (self) {
        authorizationBudgetUS = self.maxAuthorizationLatencyUS;
        NSString *session = [self sessionForProcessLocked:message->process messageVersion:message->version];
        BOOL enforcing = [self.mode isEqualToString:@"protect"] || [self.mode isEqualToString:@"strict"];
        BOOL ownExecTarget = message->event_type == ES_EVENT_TYPE_AUTH_EXEC &&
            GenseeIsOwnProcess(message->event.exec.target);
        if (enforcing && session != nil && ![self isOwnProcessLocked:message->process] && !ownExecTarget) {
            NSString *path = GenseeAuthorizationPath(message);
            NSString *secondaryPath = GenseeSecondaryAuthorizationPath(message);
            if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC && [self.blockedExecutables containsObject:path]) {
                deny = YES;
                decisionRule = @"endpoint_security_blocked_exec";
                decisionReason = @"Executable is blocked for this managed agent session.";
            } else if ((path.length > 0 && [self path:path hasProtectedPrefixLocked:self.protectedPaths]) ||
                       (secondaryPath.length > 0 && [self path:secondaryPath hasProtectedPrefixLocked:self.protectedPaths])) {
                deny = YES;
                decisionRule = @"endpoint_security_protected_path";
                decisionReason = @"Managed agent access to this protected path is denied.";
            }
        }
    }

    // Never miss Endpoint Security's response deadline in order to enforce a
    // local rule. The configured budget is intentionally fail-open. Every
    // authorization eligible for a deny belongs to a managed session, so the
    // resulting allow decision is recorded for the console below.
    uint64_t decisionElapsed = GenseeElapsedMicroseconds(started);
    if (deny && decisionElapsed > authorizationBudgetUS) {
        deny = NO;
        decisionRule = @"endpoint_security_latency_budget_fail_open";
        decisionReason = @"The authorization decision exceeded its configured latency budget.";
    }

    es_respond_result_t response;
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        uint32_t authorizedFlags = deny ? 0U : (uint32_t)message->event.open.fflag;
        response = es_respond_flags_result(self.client, message, authorizedFlags, false);
    } else {
        response = es_respond_auth_result(
            self.client,
            message,
            deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW,
            false
        );
    }
    uint64_t elapsed = GenseeElapsedMicroseconds(started);
    @synchronized (self) {
        self.authorizationCount += 1;
        if (deny) self.deniedCount += 1;
        self.maximumAuthorizationLatency = MAX(self.maximumAuthorizationLatency, elapsed);
    }
    if (response != ES_RESPOND_RESULT_SUCCESS) {
        os_log_error(GenseeLog(), "authorization response failed type=%{public}@ result=%d",
                     GenseeEventName(message->event_type), response);
    }
    *result = deny ? @"deny" : @"allow";
    *ruleID = decisionRule;
    *reason = decisionReason;
    *latencyUS = elapsed;
}

- (void)recordMessage:(const es_message_t *)message
                  mode:(NSString *)mode
                result:(NSString *)result
                ruleID:(NSString *_Nullable)ruleID
                reason:(NSString *_Nullable)reason
             latencyUS:(uint64_t)latencyUS
{
    __block NSString *actorSession = nil;
    __block NSNumber *actorRootPID = nil;
    __block BOOL actorIsOwn = NO;
    @synchronized (self) {
        actorIsOwn = [self isOwnProcessLocked:message->process];
        actorSession = [self sessionForProcessLocked:message->process messageVersion:message->version];
        if (actorSession != nil) actorRootPID = [self rootPIDForSessionLocked:actorSession];
        if (message->event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
            if (actorSession != nil) self.managedProcesses[[self keyForProcess:message->event.fork.child]] = actorSession;
        } else if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
            if (actorSession != nil) {
                NSString *actorKey = [self keyForProcess:message->process];
                NSString *targetKey = [self keyForProcess:message->event.exec.target];
                self.managedProcesses[targetKey] = actorSession;
                if (![actorKey isEqualToString:targetKey]) {
                    [self.managedProcesses removeObjectForKey:actorKey];
                }
            }
        } else if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
            [self.managedProcesses removeObjectForKey:[self keyForProcess:message->process]];
            NSNumber *pid = @(audit_token_to_pid(message->process->audit_token));
            if (self.managedRoots[pid] != nil) {
                NSMutableDictionary<NSNumber *, NSString *> *remainingRoots = [self.managedRoots mutableCopy];
                [remainingRoots removeObjectForKey:pid];
                self.managedRoots = remainingRoots;
            }
        }
    }
    // The ES client receives system-wide events so it can follow roots and
    // descendants exactly, but the host only needs durable evidence for a
    // managed agent tree. This keeps unrelated host activity out of Crate's
    // database and prevents legacy unmatched-event heuristics from firing.
    if (actorSession == nil || actorIsOwn) return;
    NSMutableDictionary *serialized = [GenseeSerializeMessage(message, mode, result, ruleID, reason, latencyUS) mutableCopy];
    serialized[@"attribution"] = @{
        @"session_id": actorSession,
        @"root_pid": actorRootPID ?: @0,
        @"confidence": @1.0,
        @"matched_by": @"endpoint_security_process_tree",
    };
    dispatch_async(self.queue, ^{
        NSMutableDictionary *withCursor = [serialized mutableCopy];
        withCursor[@"sensor_cursor"] = @(self.nextCursor++);
        uint64_t cumulativeDrops = self.kernelDrops + self.ringDrops;
        withCursor[@"dropped_events"] = @(cumulativeDrops >= self.reportedDrops
            ? cumulativeDrops - self.reportedDrops
            : cumulativeDrops);
        self.reportedDrops = cumulativeDrops;
        [self.events addObject:withCursor];
        self.totalEvents += 1;
        if (self.events.count > GenseeRingCapacity) {
            [self.events removeObjectAtIndex:0];
            self.ringDrops += 1;
        }
    });
}

- (void)observeGlobalSequence:(const es_message_t *)message
{
    uint64_t globalSequence = message->version >= 4 ? message->global_seq_num : 0;
    if (globalSequence == 0) return;
    dispatch_async(self.queue, ^{
        if (self.lastGlobalSequence > 0 && globalSequence > self.lastGlobalSequence + 1) {
            self.kernelDrops += globalSequence - self.lastGlobalSequence - 1;
        }
        self.lastGlobalSequence = MAX(self.lastGlobalSequence, globalSequence);
    });
}

- (NSDictionary *)healthLocked
{
    NSNumber *oldest = self.events.firstObject[@"sensor_cursor"] ?: @(self.nextCursor);
    __block NSUInteger managedProcessCount = 0;
    __block NSString *mode = @"observe";
    @synchronized (self) {
        managedProcessCount = self.managedProcesses.count;
        mode = self.mode;
    }
    return @{
        @"schema_version": @1,
        @"mode": mode,
        @"boot_id": GenseeBootID(),
        @"running": @YES,
        @"total_events": @(self.totalEvents),
        @"buffered_events": @(self.events.count),
        @"oldest_cursor": oldest,
        @"next_cursor": @(self.nextCursor),
        @"ring_drops": @(self.ringDrops),
        @"kernel_drops": @(self.kernelDrops),
        @"last_global_seq_num": @(self.lastGlobalSequence),
        @"authorization_count": @(self.authorizationCount),
        @"denied_count": @(self.deniedCount),
        @"max_authorization_latency_us": @(self.maximumAuthorizationLatency),
        @"configured_max_authorization_latency_us": @(self.maxAuthorizationLatencyUS),
        @"managed_processes": @(managedProcessCount),
    };
}

- (void)fetchEventsAfterCursor:(uint64_t)cursor
                         limit:(NSUInteger)limit
                     withReply:(void (^)(NSArray<NSDictionary *> *, uint64_t, NSDictionary *))reply
{
    dispatch_async(self.queue, ^{
        NSUInteger safeLimit = MIN(MAX(limit, 1), 1000);
        NSMutableArray *batch = [NSMutableArray arrayWithCapacity:safeLimit];
        uint64_t next = cursor;
        for (NSDictionary *event in self.events) {
            uint64_t eventCursor = [event[@"sensor_cursor"] unsignedLongLongValue];
            if (eventCursor <= cursor) continue;
            [batch addObject:event];
            next = eventCursor;
            if (batch.count >= safeLimit) break;
        }
        reply(batch, next, [self healthLocked]);
    });
}

- (void)healthWithReply:(void (^)(NSDictionary *))reply
{
    dispatch_async(self.queue, ^{ reply([self healthLocked]); });
}

- (void)updateConfiguration:(NSDictionary *)configuration
                   withReply:(void (^)(BOOL, NSString *_Nullable))reply
{
    NSString *requestedMode = configuration[@"mode"];
    if (requestedMode == nil || ![@[@"off", @"observe", @"protect", @"strict"] containsObject:requestedMode]) {
        reply(NO, @"Endpoint Security mode must be off, observe, protect, or strict.");
        return;
    }
    NSArray *protectedPaths = configuration[@"protected_paths"];
    NSArray *blockedExecutables = configuration[@"blocked_executables"];
    NSArray *managedRoots = configuration[@"managed_roots"];
    NSNumber *failClosedManagedOnly = configuration[@"fail_closed_managed_only"];
    NSNumber *maxAuthorizationLatencyMS = configuration[@"max_auth_latency_ms"];
    if (!GenseeIsAbsoluteStringArray(protectedPaths) ||
        !GenseeIsAbsoluteStringArray(blockedExecutables) ||
        (managedRoots != nil && ![managedRoots isKindOfClass:NSArray.class])) {
        reply(NO, @"Protected paths and blocked executables must be arrays of absolute paths; managed roots must be an array.");
        return;
    }
    if (failClosedManagedOnly != nil &&
        (![failClosedManagedOnly isKindOfClass:NSNumber.class] || !failClosedManagedOnly.boolValue)) {
        reply(NO, @"fail_closed_managed_only is reserved and must remain true.");
        return;
    }
    if (maxAuthorizationLatencyMS != nil &&
        (![maxAuthorizationLatencyMS isKindOfClass:NSNumber.class] ||
         maxAuthorizationLatencyMS.doubleValue != floor(maxAuthorizationLatencyMS.doubleValue) ||
         maxAuthorizationLatencyMS.unsignedLongLongValue < 1 ||
         maxAuthorizationLatencyMS.unsignedLongLongValue > 100)) {
        reply(NO, @"max_auth_latency_ms must be an integer from 1 through 100.");
        return;
    }
    NSMutableDictionary<NSNumber *, NSString *> *roots = [NSMutableDictionary dictionary];
    for (NSDictionary *root in managedRoots ?: @[]) {
        NSNumber *pid = root[@"pid"];
        NSString *sessionID = root[@"session_id"];
        if ([pid isKindOfClass:NSNumber.class] && [sessionID isKindOfClass:NSString.class] && pid.unsignedIntValue > 0) {
            roots[pid] = sessionID;
        }
    }
    @synchronized (self) {
        NSSet<NSString *> *activeSessions = [NSSet setWithArray:roots.allValues];
        NSMutableDictionary<NSString *, NSString *> *activeProcesses = [NSMutableDictionary dictionary];
        [self.managedProcesses enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *sessionID, BOOL *stop) {
            if ([activeSessions containsObject:sessionID]) activeProcesses[key] = sessionID;
        }];
        self.mode = requestedMode;
        self.protectedPaths = [(protectedPaths ?: @[]) valueForKey:@"stringByStandardizingPath"];
        self.blockedExecutables = [NSSet setWithArray:[(blockedExecutables ?: @[]) valueForKey:@"stringByStandardizingPath"]];
        self.managedRoots = roots;
        self.managedProcesses = activeProcesses;
        self.maxAuthorizationLatencyUS = (maxAuthorizationLatencyMS ?: @10).unsignedLongLongValue * 1000ULL;
    }
    if (self.client != NULL) es_clear_cache(self.client);
    reply(YES, nil);
}

@end

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        GenseeSensorService *service = [[GenseeSensorService alloc] init];
        [service startListener];

        __block es_client_t *client = NULL;
        es_new_client_result_t result = es_new_client(&client, ^(
            es_client_t *eventClient,
            const es_message_t *message
        ) {
            [service observeGlobalSequence:message];
            NSString *mode;
            @synchronized (service) { mode = service.mode; }
            if (message->action_type == ES_ACTION_TYPE_AUTH) {
                NSString *decision = @"allow";
                NSString *ruleID = nil;
                NSString *reason = nil;
                uint64_t latency = 0;
                [service authorizeMessage:message
                                    result:&decision
                                    ruleID:&ruleID
                                    reason:&reason
                                 latencyUS:&latency];
                if (![mode isEqualToString:@"off"]) {
                    [service recordMessage:message mode:mode result:decision ruleID:ruleID reason:reason latencyUS:latency];
                }
            } else if (![mode isEqualToString:@"off"]) {
                [service recordMessage:message mode:mode result:@"observed" ruleID:nil reason:nil latencyUS:0];
            }
        });
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS || client == NULL) {
            os_log_error(GenseeLog(), "es_new_client failed with result=%d", result);
            return EXIT_FAILURE;
        }
        service.client = client;

        es_event_type_t events[] = {
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_AUTH_TRUNCATE,
            ES_EVENT_TYPE_NOTIFY_TRUNCATE,
            ES_EVENT_TYPE_AUTH_READDIR,
            ES_EVENT_TYPE_NOTIFY_READDIR,
            ES_EVENT_TYPE_NOTIFY_MMAP,
        };
        es_return_t subscribed = es_subscribe(client, events, (uint32_t)(sizeof(events) / sizeof(events[0])));
        if (subscribed != ES_RETURN_SUCCESS) {
            os_log_error(GenseeLog(), "es_subscribe failed with result=%d", subscribed);
            es_delete_client(client);
            return EXIT_FAILURE;
        }
        os_log_info(GenseeLog(), "Gensee Endpoint Security sensor started in observe mode");
        dispatch_main();
    }
}
