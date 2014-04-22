//
//  NBOAuth1SessionManager.m
//  Four
//
//  Created by Fabrice Aneche on 21/04/14.
//  Copyright (c) 2014 Fabrice Aneche. All rights reserved.
//

#import "NBOAuth1SessionManager.h"
#import <CommonCrypto/CommonHMAC.h>
#import "NSString+MKNetworkKitAdditions.h"

@interface NBOAuth1SessionManager ()
@property(readwrite, nonatomic) NSString *consumerKey;
@property(readwrite, nonatomic) NSString *consumerSecret;
@end

@implementation NBOAuth1SessionManager

- (instancetype)initWithBaseURL:(NSURL *)url
           sessionConfiguration:(NSURLSessionConfiguration *)configuration
                    consumerKey:(NSString *)consumerKey
                 consumerSecret:(NSString *)consumerSecret {

  self = [super initWithBaseURL:url sessionConfiguration:configuration];
  if (!self) {
    return nil;
  }
  _consumerKey = consumerKey;
  _consumerSecret = consumerSecret;

  return self;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSURLResponse *response, id responseObject,
                                                        NSError *error))completionHandler {
  NSMutableURLRequest *oAuthRequest = [request mutableCopy];
  [self addOAuth1AuthorizationHeaderForRequest:oAuthRequest];
  return [super dataTaskWithRequest:oAuthRequest completionHandler:completionHandler];
}

- (void)addOAuth1AuthorizationHeaderForRequest:(NSMutableURLRequest *)request {

  CFUUIDRef uuid = CFUUIDCreate(NULL);
  CFStringRef nounce = CFUUIDCreateString(NULL, uuid);
  CFRelease(uuid);
  NSDictionary *fixedHeaders = @{
    @"oauth_version" : @"1.0",
    @"oauth_consumer_key" : self.consumerKey,
    @"oauth_timestamp" : [NSString stringWithFormat:@"%d", (int)[[NSDate date] timeIntervalSince1970]],
    @"oauth_nonce" : (NSString *)CFBridgingRelease(nounce),
    @"oauth_signature_method" : @"HMAC-SHA1"
  };

  NSMutableDictionary *oauthHeaders = [NSMutableDictionary dictionaryWithDictionary:fixedHeaders];

  if (![request.HTTPMethod isEqualToString:@"GET"]) {
    unsigned char digestBytes[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([request.HTTPBody bytes], [request.HTTPBody length], digestBytes);
    NSData *digestBodyData = [NSData dataWithBytes:digestBytes length:CC_SHA1_DIGEST_LENGTH];
    NSData *digestB64Data = [digestBodyData base64EncodedDataWithOptions:0];
    NSString *digestBody = [[NSString alloc] initWithBytes:[digestB64Data bytes]
                                                    length:[digestB64Data length]
                                                  encoding:NSUTF8StringEncoding];
    [oauthHeaders setValue:digestBody forKey:@"oauth_body_hash"];
  }

  NSMutableArray *normalizedParams = [NSMutableArray array];
  [oauthHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
      [normalizedParams addObject:[NSString stringWithFormat:@"%@=%@", [key urlEncodedString], [obj urlEncodedString]]];
  }];

  NSArray *sortedParams = [normalizedParams sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];

  NSString *signatureBaseString =
      [NSString stringWithFormat:@"%@&%@&%@", [[request HTTPMethod] uppercaseString],
                                 [[request.URL absoluteString] urlEncodedString],
                                 [[sortedParams componentsJoinedByString:@"&"] urlEncodedString]];

  NSString *key = [NSString stringWithFormat:@"%@&", [_consumerSecret urlEncodedString]];

  const char *keyBytes = [key cStringUsingEncoding:NSUTF8StringEncoding];
  const char *baseStringBytes = [signatureBaseString cStringUsingEncoding:NSUTF8StringEncoding];
  unsigned char digestBytes[CC_SHA1_DIGEST_LENGTH];

  CCHmacContext ctx;
  CCHmacInit(&ctx, kCCHmacAlgSHA1, keyBytes, strlen(keyBytes));
  CCHmacUpdate(&ctx, baseStringBytes, strlen(baseStringBytes));
  CCHmacFinal(&ctx, digestBytes);

  NSData *digestb64Data =
      [[NSData dataWithBytes:digestBytes length:CC_SHA1_DIGEST_LENGTH] base64EncodedDataWithOptions:0];
  NSString *digestb64String = [[NSString alloc] initWithData:digestb64Data encoding:NSUTF8StringEncoding];

  NSMutableArray *headerParams = [NSMutableArray arrayWithCapacity:5];
  [oauthHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
      [headerParams addObject:[NSString stringWithFormat:@"%@=\"%@\"", key, [obj urlEncodedString]]];
  }];
  [headerParams addObject:[NSString stringWithFormat:@"oauth_signature=\"%@\"", [digestb64String urlEncodedString]]];
  NSString *oauthData = [NSString stringWithFormat:@"OAuth %@", [headerParams componentsJoinedByString:@", "]];

  // Add the Authorization header to the request
  [request addValue:oauthData forHTTPHeaderField:@"Authorization"];
}

@end
