# passport-setapp

Passport strategy for authenticating with SetApp using the OAuth 2.0 API.

This module lets you authenticate using SetApp in your Node.js applications. By plugging into Passport, SetApp authentication can be easily and unobtrusively integrated into any application or framework that supports Connect-style middleware, including Express.

## Install

`$ npm install passport-setapp`

## Usage

### Create an Application

Before using passport-setapp, you must register an application with SetApp. Your application will be issued a client ID and client secret, which need to be provided to the strategy. You will also need to configure a callback URL which matches the route in your application.

### Configure Strategy

The SetApp authentication strategy authenticates users using a GitHub account and OAuth 2.0 tokens. The client ID and secret obtained when creating an application are supplied as options when creating the strategy. The strategy also requires a verify callback, which receives the access token and optional refresh token, as well as profile which contains the authenticated user's SetApp email address and if they have been granted access to the application.

```
import { Strategy as SetAppStrategy } from 'passport-setapp';

passport.use(new SetAppStrategy({
    clientID: SETAPP_CLIENT_ID,
    clientSecret: SETAPP_CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/setapp/callback",
    passReqToCallback: true
  },,
  async function (req, accessToken, refreshToken, profile, expires_in, done) {
    if (!profile.granted) {
      done(
        new Error('SetApp user has not been granted access to use this app');
      )
    }
    const user = await User.findOrCreate({
      email: profile.email,
      setAppId: profile.id
    });
    done(null, user);
  }
));
```

The Strategy calls the [Access](https://docs.setapp.com/reference/post_application-access) and [UserInfo](https://docs.setapp.com/reference/get_userinfo) endpoints of the SetApp API to fetch the users' email address and determine if the user is allowed access to the app.

If the user is not allowed access then `profile.granted` will be `false`.

### Authenticate Requests

Use passport.authenticate(), specifying the 'setapp' strategy, to authenticate requests.

For example, as route middleware in an Express application:

```
app.get('/auth/setapp',
  passport.authenticate('setapp'));

app.get('/auth/setapp/callback',
  passport.authenticate('setapp', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```
