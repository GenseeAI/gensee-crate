#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^GenseeEndpointSecurityEventsReply)(NSArray<NSDictionary *> *events,
                                                   uint64_t nextCursor,
                                                   NSDictionary *health);
typedef void (^GenseeEndpointSecurityConfigurationReply)(BOOL accepted,
                                                          NSString *_Nullable message);
typedef void (^GenseeEndpointSecurityFailure)(NSError *error);

/// Keeps the dynamically manufactured NSXPC proxy on the Objective-C side.
/// This avoids Swift protocol-cast crashes observed on macOS 15.1.
@interface GenseeEndpointSecurityBridge : NSObject

@property(nonatomic, copy, nullable) dispatch_block_t interruptionHandler;
@property(nonatomic, copy, nullable) dispatch_block_t invalidationHandler;

- (instancetype)initWithMachServiceName:(NSString *)serviceName
                  codeSigningRequirement:(NSString *)requirement;
- (void)activate;
- (void)invalidate;
- (void)fetchEventsAfterCursor:(uint64_t)cursor
                         limit:(NSUInteger)limit
                         reply:(GenseeEndpointSecurityEventsReply)reply
                       failure:(GenseeEndpointSecurityFailure)failure;
- (void)updateConfiguration:(NSDictionary *)configuration
                       reply:(GenseeEndpointSecurityConfigurationReply)reply
                     failure:(GenseeEndpointSecurityFailure)failure;

@end

NS_ASSUME_NONNULL_END
