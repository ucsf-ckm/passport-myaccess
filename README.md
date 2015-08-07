passport-myaccess
=================

_Passport authentication strategy that works with UCSF MyAccess_

This uses the fabulous [passport-saml](https://github.com/bergie/passport-saml) module for all the heavy lifting, but sets all the default options so that it works properly with MyAccess.

Note that in order to use MyAccess for authentication, **you must [register your server](https://wiki.library.ucsf.edu/display/IAM/MyAccess+Integration+Request)**. During the registration process, you can gather your server's metadata via the route /Shibboleth.sso/Metadata. This module provides an implementation for that route, but you have to set that up in your main server script (see [/example/server.js](https://github.com/ucsf-ckm/passport-myaccess/blob/master/example/server.js)).

Installation
------------
    npm install --save passport-myaccess

Usage
-----
There is a fully-working example server script in [/example/server.js](https://github.com/ucsf-ckm/passport-myaccess/blob/master/example/server.js), and an associated [package.json](https://github.com/ucsf-ckm/passport-myaccess/blob/master/example/package.json), which you can use to install all the necessary packages to make the example script run.

This module provides a Strategy for the [Passport](http://passportjs.org/) framework, which is typically used with [Express](http://expressjs.com/). Thus, there are several modules you need to require in your server script in addition to this module.

The example script then gets the server's domain name from an environment variable. This allows you to run the example script without modification. Export a value for `DOMAIN` and run the script.

    export DOMAIN=mydomain.example.edu
    node server.js

You can also override the default HTTP and HTTPS ports if you wish by specifying `HTTPPORT` and `HTTPSPORT` environment variables.

The example script then loads a public certificates and associated private keys from files in a `/security` subdirectory.

    var samlCert = fs.readFileSync('./security/saml.crt', 'utf-8');
    var samlKey = fs.readFileSync('./security/saml.pem', 'utf-8');
    var httpsCert = fs.readFileSync('./security/https.cer', 'utf-8');
    var httpsKey = fs.readFileSync('./security/https.key', 'utf-8');

These are used to sign requests sent to the IdP and for the HTTPS server.

The script creates the strategy like this:

    var strategy = new myaccess.Strategy({
        entityId: domain,
        privateKey: privateKey,
        callbackUrl: loginCallbackUrl,
        domain: domain
    });

    passport.use(strategy);

You will typically want to use sessions to allow users to authenticate only once per-sesion. The next functions are called by Passport to serialize and deserialize the user to the session. As noted in the comments, you would typically want to serialize only the unique ID (`.netID`) and reconstitute the user from your database during deserialzie. But to keep things simple, the script serializes the entire user and deserializes it again.

    passport.serializeUser(function(user, done){
        done(null, user);
    });

    passport.deserializeUser(function(user, done){
        done(null, user);
    });

Next, the script registers a few routes to handle login, the login callback, and the standard metadata. This module provides implementations for the metadata route, and you use passport.authenticate for the login and login callback routes.

    app.get(loginUrl, passport.authenticate(strategy.name), myaccess.backToUrl());
    app.post(loginCallbackUrl, passport.authenticate(strategy.name), myaccess.backToUrl());
    app.get(myaccess.urls.metadata, myaccess.metadataRoute(strategy, publicCert));

The `myaccess.backToUrl()` is a convenience middleware that will redirect the browser back to the URL that was originally requested before authentication.

Lastly, the script tells Express to use the `ensureAuth()` middleware provided by this module to secure all routes declared after this.

    //secure all routes following this
    app.use(myaccess.ensureAuth(loginUrl));

Any route requested after this middleware will require authentication. When requested, those routes will automatically redirect to the `loginUrl` if the user has not already authenticated. After successful authentication, the browser will be redirected back to the original URL, and the user information will be available via the `.user` property on the request object.

Note that `ensureAuth` can also be used to selectively secure routes. For example:

    app.get('protected/resource', ensureAuth(loginUrl), function(req, res) {
        //user has authenticated, do normal route processing
        //user is available via req.user
    });

Acknowledgement
---------------

This module used [passport-uwshib](https://www.npmjs.com/package/passport-uwshib) as a starting point. Leveraging the existing work in that module saved us a ton of time. Most
of the text of this README and most of the code in the code files are (as of this writing)
unchanged from that project.
