/**
 * Module dependencies.
 */
const OAuth2Strategy = require("passport-oauth").OAuth2Strategy;
const InternalOAuthError = require("passport-oauth").InternalOAuthError;
const fetch = require("node-fetch");

const defaultOptions = {
  authorizationURL: "https://vendor-api.setapp.com/auth/v1/authorize",
  tokenURL: "https://vendor-api.setapp.com/auth/v1/token",
};

class Strategy extends OAuth2Strategy {
  constructor(options = {}, verify) {
    const opts = {
      ...defaultOptions,
      ...options,
    };
    super(opts, verify);
    this._verify = verify;
    this._options = opts;
    this.name = "setapp";
  }

  async authenticate(req, options = {}) {
    if (req.query && req.query.error) {
      // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
      //       query parameters, and should be propagated to the application.
      return this.fail();
    }

    const callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      const parsed = new URL(callbackURL);
      if (!parsed.protocol) {
        return this.error(
          new InternalOAuthError("callbackURL must be absolute")
        );
      }
    }

    const code = req.query.code;

    if (code) {
      const bearer = Buffer.from(
        this._options.clientID + ":" + this._options.clientSecret
      ).toString("base64");

      const headers = {
        Authorization: `Basic ${bearer}`,
        "Content-Type": "application/x-www-form-urlencoded",
      };
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        redirect_uri: this._options.callbackURL,
        code,
      });

      try {
        const response = await fetch(this._options.tokenURL, {
          headers,
          method: "post",
          body,
        });

        const responseBody = await response.json();

        if (responseBody.error) {
          const message =
            responseBody.error.message || responseBody.error_description;
          return this.error(new InternalOAuthError(message));
        }

        const {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: expiresIn,
        } = responseBody;

        const onVerified = (err, user) => {
          if (err) {
            return this.error(err);
          }
          return this.success(user);
        };

        this._loadUserProfile(
          {
            accessToken: accessToken,
          },
          (err, profile) => {
            if (err) return this.error(err);
            if (this._options.passReqToCallback) {
              this._verify(
                req,
                accessToken,
                refreshToken,
                profile,
                expiresIn,
                onVerified
              );
            } else {
              this._verify(
                accessToken,
                refreshToken,
                profile,
                expiresIn,
                onVerified
              );
            }
          }
        );
      } catch (err) {
        return this.error(
          new InternalOAuthError("failed to obtain access token", err)
        );
      }
    } else {
      const params = {
        ...this.authorizationParams(options),
        response_type: "code",
        redirect_uri: callbackURL,
      };

      let scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) {
          scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
      }

      if (options.state) {
        params.state = options.state;
      }

      const prompt = options.prompt || this._prompt;
      if (prompt) {
        params.prompt = prompt;
      }

      const location = this._oauth2.getAuthorizeUrl(params);

      this.redirect(location);
    }
  }
}

/**
 * Check if the user has access via SetApp to the app
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = async function (accessToken, done) {
  this._oauth2._useAuthorizationHeaderForGET = true;

  try {
    const opts = {
      headers: {
        Accept: "application/json",
        Authorization: this._oauth2.buildAuthHeader(accessToken),
      },
    };
    const [userResponse, accessResponse] = await Promise.all([
      fetch("https://vendor-api.setapp.com/resource/v1/userinfo", opts),
      fetch(
        `https://vendor-api.setapp.com/resource/v1/application/access`,
        opts
      ),
    ]);

    const [user, access] = await Promise.all([
      userResponse.json(),
      accessResponse.json(),
    ]);

    let profile = { ...user.data, granted: false };
    if (access && access.data) {
      profile = { ...profile, access: true, granted: access.data.granted };
    }
    done(null, profile);
  } catch (err) {
    return done(new InternalOAuthError("Failed to fetch user profile", err));
  }
};

/**
 * User profile
 * @param {Object} params
 * @param {Function} done
 * @private
 */
Strategy.prototype._loadUserProfile = function (params, done) {
  return this.userProfile(params.accessToken, done);
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
