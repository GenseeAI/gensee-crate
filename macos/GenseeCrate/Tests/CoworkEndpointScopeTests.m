// Exercise the actual extension without starting an ES client or requiring an
// entitlement. Synthetic process generations cover adoption and attribution.
#define main GenseeExtensionMain
#import "../EndpointSecurityExtension/main.m"
#undef main

static int snapshotFetches;
static BOOL snapshotAlwaysGrows;
static int CoworkTestSysctl(int *name, u_int count, void *output, size_t *size, void *input, size_t inputSize)
{
    if (output == NULL) { *size = sizeof(struct kinfo_proc); return 0; }
    snapshotFetches++;
    if (snapshotAlwaysGrows || snapshotFetches == 1) { errno = ENOMEM; return -1; }
    struct kinfo_proc entries[3] = {0};
    entries[0].kp_proc.p_pid = 500;
    entries[0].kp_eproc.e_ppid = 1;
    entries[1].kp_proc.p_pid = 501;
    entries[1].kp_eproc.e_ppid = 500;
    entries[2].kp_proc.p_pid = 502;
    entries[2].kp_eproc.e_ppid = 501;
    NSCAssert(*size >= sizeof(entries), @"snapshot must reserve slack");
    memcpy(output, entries, sizeof(entries));
    *size = sizeof(entries);
    return 0;
}
#define sysctl CoworkTestSysctl
#import "../Host/GenseeEndpointSecurityBridge.m"
#undef sysctl

static es_process_t CoworkProcess(pid_t pid, const char *signingID, const char *teamID)
{
    es_process_t process = {0};
    process.audit_token.val[5] = pid;
    process.audit_token.val[7] = 1;
    process.signing_id = (es_string_token_t){strlen(signingID), signingID};
    process.team_id = (es_string_token_t){strlen(teamID), teamID};
    return process;
}

static NSDictionary *CoworkRoot(NSNumber *pid)
{
    return @{@"pid": pid, @"root_pid": @500, @"session_id": @"cowork",
             @"kind": @"claude-cowork", @"cowork_session_mode": @"local"};
}

static BOOL Configure(GenseeSensorService *service, NSArray *roots)
{
    __block BOOL accepted = NO;
    [service updateConfiguration:@{@"mode": @"observe", @"managed_roots": roots,
                                  @"protected_paths": @[], @"blocked_executables": @[]}
                       withReply:^(BOOL success, NSString *message) { accepted = success; }];
    return accepted;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        NSCAssert(argc == 2, @"shared signing fixture path required");
        NSData *fixtureData = [NSData dataWithContentsOfFile:@(argv[1])];
        NSArray *fixtures = [NSJSONSerialization JSONObjectWithData:fixtureData options:0 error:NULL];
        NSCAssert(fixtures.count > 0, @"shared signing fixtures must load");
        for (NSDictionary *fixture in fixtures) {
            es_process_t actor = CoworkProcess(501, [fixture[@"signing_id"] UTF8String], [fixture[@"team_id"] UTF8String]);
            actor.is_platform_binary = [fixture[@"platform"] boolValue];
            NSCAssert(GenseeIsTrustedCoworkProcess(&actor) == [fixture[@"trusted"] boolValue], @"shared signing identity parity");
        }
        es_process_t impostor = CoworkProcess(502, "com.anthropic.claudefordesktop.helper-evil", "Q6L2SF6YDW");
        NSCAssert(!GenseeIsTrustedCoworkProcess(&impostor), @"helper prefix must end at a component boundary");
        es_process_t vm = CoworkProcess(503, "com.apple.Virtualization.VirtualMachine", "");
        NSCAssert(!GenseeIsTrustedCoworkProcess(&vm), @"VM signing ID alone is insufficient");
        vm.is_platform_binary = YES;
        NSCAssert(GenseeIsTrustedCoworkProcess(&vm), @"platform VM is adoptable");

        GenseeSensorService *service = [[GenseeSensorService alloc] init];
        NSArray *roots = @[CoworkRoot(@502), CoworkRoot(@501), CoworkRoot(@500)];
        NSCAssert(Configure(service, roots), @"valid adoption configuration");
        NSCAssert([[service rootPIDForSessionLocked:@"cowork"] isEqual:@500], @"canonical root is the app");
        NSCAssert(Configure(service, [[roots reverseObjectEnumerator] allObjects]), @"reverse adoption order");
        NSCAssert([[service rootPIDForSessionLocked:@"cowork"] isEqual:@500], @"root is independent of order");
        NSCAssert(Configure(service, @[CoworkRoot(@501)]), @"invalid Cowork must not reject all configuration");
        NSCAssert(service.managedRoots.count == 0, @"exclude missing canonical app root");
        NSMutableDictionary *conflict = [CoworkRoot(@501) mutableCopy];
        conflict[@"root_pid"] = @501;
        NSCAssert(Configure(service, @[CoworkRoot(@500), conflict]), @"isolate conflicting canonical roots");
        NSCAssert(service.managedRoots.count == 0, @"exclude entire conflicting session");
        NSMutableDictionary *legacy = [CoworkRoot(@500) mutableCopy];
        [legacy removeObjectForKey:@"root_pid"];
        NSCAssert(Configure(service, @[legacy, @{@"pid": @900, @"session_id": @"ordinary"}]), @"accept ordinary roots alongside old Cowork schema");
        NSCAssert(service.managedRoots.count == 1 && [service.managedRoots[@900] isEqual:@"ordinary"], @"invalid Cowork must not bypass signing checks as an ordinary root");
        NSCAssert(service.coworkSessionModes.count == 0, @"invalid session metadata removed");
        legacy[@"cowork_session_mode"] = @"invalid";
        NSCAssert(Configure(service, @[legacy, @{@"pid": @900, @"session_id": @"ordinary"}]), @"invalid mode is isolated too");
        NSCAssert(service.managedRoots.count == 1 && [service.managedRoots[@900] isEqual:@"ordinary"], @"preserve unrelated configuration");
        NSCAssert(Configure(service, roots), @"restore valid roots");

        es_process_t helper = CoworkProcess(501, "com.anthropic.claudefordesktop.helper.Renderer", "Q6L2SF6YDW");
        NSCAssert([[service sessionForProcessLocked:&helper messageVersion:4] isEqual:@"cowork"], @"adopt running renderer");
        // A rejected snapshot candidate must still inherit a verified parent.
        impostor.parent_audit_token = helper.audit_token;
        NSCAssert([[service sessionForProcessLocked:&impostor messageVersion:4] isEqual:@"cowork"], @"preserve independently verified ancestry");
        es_process_t reused = impostor;
        reused.audit_token.val[7] = 2;
        reused.parent_audit_token = (audit_token_t){0};
        NSCAssert([service sessionForProcessLocked:&reused messageVersion:4] == nil, @"PID reuse must not inherit prior generation");

        vm.ppid = 1;
        vm.responsible_audit_token = helper.audit_token;
        NSCAssert([[service sessionForProcessLocked:&vm messageVersion:4] isEqual:@"cowork"], @"adopt launchd VM through verified responsible generation");
        es_process_t unrelatedVM = vm;
        unrelatedVM.audit_token.val[5] = 504;
        unrelatedVM.responsible_audit_token.val[7]++;
        NSCAssert([service sessionForProcessLocked:&unrelatedVM messageVersion:4] == nil, @"responsible PID reuse is not association");
        unrelatedVM.responsible_audit_token = helper.audit_token;
        unrelatedVM.is_platform_binary = NO;
        NSCAssert([service sessionForProcessLocked:&unrelatedVM messageVersion:4] == nil, @"untrusted VM cannot use responsible-process adoption");
        unrelatedVM.is_platform_binary = YES;
        NSCAssert([service sessionForProcessLocked:&unrelatedVM messageVersion:3] == nil, @"old ES messages lack responsible tokens");

        es_message_t message = {0};
        message.version = 4;
        message.process = &helper;
        message.event_type = ES_EVENT_TYPE_NOTIFY_WRITE;
        message.action_type = ES_ACTION_TYPE_NOTIFY;
        [service recordMessage:&message mode:@"observe" result:@"allow" ruleID:nil reason:nil latencyUS:0];
        dispatch_sync(service.queue, ^{});
        NSDictionary *event = service.events.lastObject;
        NSCAssert([event[@"cowork"][@"tool_surface"] isEqual:@"unknown"], @"local tree must not invent host-tool evidence");
        NSCAssert([event[@"attribution"][@"root_pid"] isEqual:@500], @"recorded root remains canonical");

        message.process = &vm;
        [service recordMessage:&message mode:@"observe" result:@"allow" ruleID:nil reason:nil latencyUS:0];
        dispatch_sync(service.queue, ^{});
        NSCAssert([service.events.lastObject[@"cowork"][@"tool_surface"] isEqual:@"shell"], @"associated platform VM records shell boundary");
        NSCAssert(Configure(service, @[]), @"disable Cowork roots");
        NSCAssert([service sessionForProcessLocked:&vm messageVersion:4] == nil, @"disabling Cowork revokes cached VM association");

        GenseeSensorService *ring = [[GenseeSensorService alloc] init];
        dispatch_sync(ring.queue, ^{
            for (NSUInteger i = 0; i < GenseeRingCapacity + 7; i++) [ring appendEventLocked:@{}];
        });
        NSCAssert(ring.events.count == GenseeRingCapacity, @"ring memory stays bounded");
        __block NSArray *batch;
        __block NSDictionary *health;
        [ring fetchEventsAfterCursor:GenseeRingCapacity limit:10 withReply:^(NSArray *events, uint64_t next, NSDictionary *state) { batch = events; health = state; }];
        dispatch_sync(ring.queue, ^{});
        NSCAssert(batch.count == 7, @"fetch resumes at the durable cursor after wraparound");
        NSCAssert([health[@"ring_drops"] unsignedLongLongValue] == 0, @"consumed history eviction is not loss");
        for (NSDictionary *row in batch) NSCAssert([row[@"dropped_events"] unsignedLongLongValue] == 0, @"ordinary eviction emits no alert");
        [ring fetchEventsAfterCursor:0 limit:10 withReply:^(NSArray *events, uint64_t next, NSDictionary *state) { batch = events; health = state; }];
        dispatch_sync(ring.queue, ^{});
        NSCAssert([batch.firstObject[@"sensor_cursor"] unsignedLongLongValue] == 8, @"fresh cursor begins at retained history");
        NSCAssert([batch.firstObject[@"dropped_events"] unsignedLongLongValue] == 0 && [health[@"ring_drops"] unsignedLongLongValue] == 0, @"fresh attachment must not invent loss");

        [ring fetchEventsAfterCursor:2 limit:10 withReply:^(NSArray *events, uint64_t next, NSDictionary *state) { batch = events; health = state; }];
        dispatch_sync(ring.queue, ^{});
        NSCAssert([batch.firstObject[@"sensor_cursor"] unsignedLongLongValue] == 8, @"oldest cursor survives wraparound");
        NSCAssert([batch.firstObject[@"dropped_events"] unsignedLongLongValue] == 5, @"report only unread missing cursors");
        NSCAssert([health[@"ring_drops"] unsignedLongLongValue] == 5, @"health counts the actual missing range");
        [ring fetchEventsAfterCursor:2 limit:10 withReply:^(NSArray *events, uint64_t next, NSDictionary *state) { health = state; }];
        dispatch_sync(ring.queue, ^{});
        NSCAssert([health[@"ring_drops"] unsignedLongLongValue] == 5, @"retried fetch does not inflate loss counters");
        dispatch_sync(ring.queue, ^{ ring.kernelDrops = 3; [ring appendEventLocked:@{}]; });
        [ring fetchEventsAfterCursor:GenseeRingCapacity + 7 limit:10 withReply:^(NSArray *events, uint64_t next, NSDictionary *state) { batch = events; }];
        dispatch_sync(ring.queue, ^{});
        NSCAssert([batch.firstObject[@"dropped_events"] unsignedLongLongValue] == 3, @"real kernel loss remains visible");
        GenseeSensorService *pruned = [[GenseeSensorService alloc] init];
        dispatch_sync(pruned.queue, ^{
            for (NSUInteger i = 0; i < GenseeRingCapacity + 7; i++) {
                [pruned appendEventLocked:@{@"attribution": @{@"session_id": i % 2 ? @"keep" : @"remove"}}];
            }
        });
        NSCAssert(Configure(pruned, @[@{@"pid": @900, @"session_id": @"keep"}]), @"revoke a session after ring wrap");
        [pruned fetchEventsAfterCursor:8 limit:10 withReply:^(NSArray *events, uint64_t next, NSDictionary *state) { batch = events; }];
        dispatch_sync(pruned.queue, ^{});
        NSCAssert([batch.firstObject[@"sensor_cursor"] unsignedLongLongValue] == 10, @"revocation must not skip the next retained event");
        for (NSDictionary *event in batch) NSCAssert([event[@"attribution"][@"session_id"] isEqual:@"keep"], @"revoked payload must not be delivered");
        dispatch_sync(pruned.queue, ^{
            uint64_t previous = 0;
            for (NSUInteger i = 0; i < pruned.events.count; i++) {
                NSDictionary *event = [pruned eventAtOffsetLocked:i];
                uint64_t current = [event[@"sensor_cursor"] unsignedLongLongValue];
                NSCAssert(current > previous && ([event[@"sensor_revoked"] boolValue] || [event[@"attribution"][@"session_id"] isEqual:@"keep"]), @"pruning preserves logical cursor order");
                previous = current;
            }
            [pruned appendEventLocked:@{}];
            NSCAssert([[pruned eventAtOffsetLocked:pruned.events.count - 1][@"sensor_cursor"] unsignedLongLongValue] > previous, @"append remains ordered after pruning");
        });

        snapshotFetches = 0;
        NSArray *descendants = GenseeDescendantProcessIdentifiers(500);
        NSCAssert(snapshotFetches == 2, @"retry a growing process table");
        NSCAssert(([descendants isEqual:@[@501, @502]]), @"recover recursive descendants after resize");
        snapshotFetches = 0;
        snapshotAlwaysGrows = YES;
        NSCAssert(GenseeDescendantProcessIdentifiers(500).count == 0, @"failed snapshot returns no invented descendants");
        NSCAssert(snapshotFetches == 3, @"snapshot retries are bounded");
        puts("Cowork endpoint scope tests passed");
    }
    return 0;
}
