# GO JWT AUTHENTICATION

jwtauth uses [jwt-go](https://github.com/dgrijalva/jwt-go), [uuid](https://github.com/twinj/uuid) and [go-redis](https://github.com/go-redis/redis)

redis is used for blacklisting on logout

## USAGE
jwtauth.Setup(jwtsecret string, redisclient redis.Client): initializes jwt secret key and redis client

jwtauth.CreateToken(id uint64): 
* creates access and refresh token based on jwt secret key
* access token expires in 15 minutes
* refresh token expires in 7 days
* subject is id. 
* sets jti to uuid v4, same for access and refresh token

jwtauth.LogoutToken(r http.Request):
* requires access token in authorization header
* adds jti to blacklist with 7 days expiry

jwtauth.RefreshTokens(r http.Request):
* gets access token in authorization header, refresh token in body
* access token must be expired
* access token and refresh token must have same jti
* adds jti to blacklist with 7 days expiry
