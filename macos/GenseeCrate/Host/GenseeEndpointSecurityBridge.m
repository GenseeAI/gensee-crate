#import "GenseeEndpointSecurityBridge.h"

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
