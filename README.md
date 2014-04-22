NBOAuth1SessionManager
======================

A two legs OAuth 1.0a session manager for AFNetworking 2, with OAuth body hash extension.

NBOAuth1SessionManager is a `AFHTTPSessionManager` subclass, instantiate as follow and use it as a normal `AFHTTPSessionManager`.

```Objective-C
NSURLSessionConfiguration *sessionRestConfiguration = [NSURLSessionConfiguration defaultSessionConfiguration];
...
NBOAuth1SessionManager *manager = [[NBOAuth1SessionManager alloc] initWithBaseURL:[NSURL URLWithString:@"http://localhost"]
                                                               sessionConfiguration:sessionRestConfiguration
                                                                        consumerKey:_consumerKey
                                                                     consumerSecret:_consumerSecret];
  
[manager GET:@"/testauth" parameters:nil success:^(NSURLSessionDataTask *task, id responseObject) {
  NSLog(@"Yeah !");
} failure:^(NSURLSessionDataTask *task, NSError *error) {
  NSLog(@"Bouhh ! %@", [error localizedDescription]);
}];
```
