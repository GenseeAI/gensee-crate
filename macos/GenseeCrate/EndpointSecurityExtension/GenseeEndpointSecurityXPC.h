#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Property-list-only protocol between the root system extension and the
/// signed Gensee host. Events are pulled in bounded batches so the ES callback
/// never waits for UI, disk, SQLite, or XPC work.
@protocol GenseeEndpointSecurityXPC
- (void)fetchEventsAfterCursor:(uint64_t)cursor
                         limit:(NSUInteger)limit
                     withReply:(void (^)(NSArray<NSDictionary *> *events,
                                         uint64_t nextCursor,
                                         NSDictionary *health))reply;
- (void)healthWithReply:(void (^)(NSDictionary *health))reply;
- (void)updateConfiguration:(NSDictionary *)configuration
                   withReply:(void (^)(BOOL accepted, NSString *_Nullable error))reply;
@end

NS_ASSUME_NONNULL_END
