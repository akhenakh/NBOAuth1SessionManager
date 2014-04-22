//
//  NBOAuth1SessionManager.h
//  Four
//
//  Created by Fabrice Aneche on 21/04/14.
//  Copyright (c) 2014 Fabrice Aneche. All rights reserved.
//

#import "AFHTTPSessionManager.h"

@interface NBOAuth1SessionManager : AFHTTPSessionManager

- (instancetype)initWithBaseURL:(NSURL *)url
           sessionConfiguration:(NSURLSessionConfiguration *)configuration
                    consumerKey:(NSString *)consumerKey
                 consumerSecret:(NSString *)consumerSecret;

@end
