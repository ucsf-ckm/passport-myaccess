"use strict";
/**
 * UCSF MyAccess Passport Authentication Module
 *
 * This module exposes a passport Strategy object that is pre-configured to
 * work with the UCSF's Shibboleth Identity Provider (IdP). To use this,
 * you must register your server with UCSF MyAccess. For details, see
 * https://github.com/ucsf-ckm/passport-myaccess
 *
 * @module passport-myaccess
 * @author Rich Trott
 */

var saml = require('passport-saml');
var util = require('util');

var idpCert = 'MIIDFzCCAf+gAwIBAgIUW2hLRYSTq6yflHpRZ5ZBXty14rYwDQYJKoZIhvcNAQEFBQAwFjEUMBIGA1UEAxMLZHAudWNzZi5lZHUwHhcNMDkwODI5MDQwMzU5WhcNMjkwODI5MDQwMzU5WjAWMRQwEgYDVQQDEwtkcC51Y3NmLmVkdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+WY9j/fuMEQ2u4mKKeU5LXO+mi7BKKkJP3PUN0Iz4whL/M9uTR+C7x6DCVbi4CXNia8hmoNbWIKCKto9UJT/e+Y4y+dZjC4TLcIvdUog7x4/3qlcwI76jkomyL5uy2/7Ow+l/pmX99wph+K4/d8EpwE3NTXcFOVv1D8M3pUrVEfT1aoAm7p4SXS3uohM7KDXTljqtxImt/Q+cRFBImNyp7YTFp37024eMwtNfLJxEajodIFOCCYP6DmN5I1RWTF808BPPbkt7agjuz50pCdXHxfgnCfUmHeeUz4yLI6cgOWkB9JISN567vAH68IInM9with782aIsVLf2Fs5pQqxECAwEAAaNdMFswOgYDVR0RBDMwMYILZHAudWNzZi5lZHWGImh0dHBzOi8vZHAudWNzZi5lZHUvaWRwL3NoaWJib2xldGgwHQYDVR0OBBYEFDfsmZZFJeq4xHogyRDy+1N69EEKMA0GCSqGSIb3DQEBBQUAA4IBAQBiK5W3RyQc/LL+FOy9mQIFzmobtJCGYUHwn/jMzZ+FdiV688MOA94AHGnxlvjjlVE7sjI83XgUK80IpLWz1QtCN9Pcwo5M0tNCxOFAkIe1xRadZmN4LpFOenH8vd5TF7DjrozFivFC4+l/mTTW4hfl+RaR34zgrzBAv+fUNrq7cNrid11w0h17HNqD964TR4QphmFyIrFR9skSs+41ScRMa4c7Svel8p4f+ptoATHSlSm0OZayjktgJp4o+Ld8xiH8Q5oLQ/qNG0hx9IRMaum9h0HCnxwHKsrxcJW2/A/CVhaVlj4Jp/B3Zs13i2Wc6VGZGK1rfVetLqSnvfVPnT+h';
var idpEntryPoint = 'https://dp.ucsf.edu/idp/profile/SAML2/Redirect/SSO';
var strategyName = 'myaccess';

/**
 * Standard URLs for Shibboleth Metadata route and the Logout page
 * You can use the urls.metadata in conjunction with the metadataRoute
 * function to create your server's metadata route implementation.
 *
 * @type {{metadata: string, logoutUrl: string}}
 */
module.exports.urls = {
    metadata: '/Shibboleth.sso/Metadata',
    logoutUrl: 'https://dp.ucsf.edu/idp/shib_logout.jsp'
};

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
var profileAttrs = {
    'urn:oid:0.9.2342.19200300.100.1.1': 'netId',
    'urn:oid:2.5.4.3': 'cn',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'principalName',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.5.4.4': 'surname',
    'urn:oid:2.16.840.1.113730.3.1.241': 'displayName'
};

function verifyProfile(profile, done) {
    if (!profile)
        return done(new Error('Empty SAML profile returned!'));
    else
        return done(null, convertProfileToUser(profile));
}

function convertProfileToUser(profile) {
    var user = {};
    var niceName;
    var idx;
    var keys = Object.keys(profile);
    var key;

    for (idx = 0; idx < keys.length; ++idx) {
        key = keys[idx];
        niceName = profileAttrs[key];
        if (niceName) {
            user[niceName] = profile[key];
        }
    }

    return user;    
}

/**
 * Passport Strategy for UCSF MyAccess Shibboleth Authentication
 *
 * This class extends passport-saml.Strategy, providing the necessary options for the MyAccess Shibboleth IdP
 * and converting the returned profile into a user object with sensible property names.
 *
 * @param {Object} options - Configuration options
 * @param {string} options.entityId - Your server's entity id (often same as domain name)
 * @param {string} options.domain - Your server's domain name
 * @param {number} options.port - Port your HTTPS server is running on (default: 443)
 * @param {string} options.callbackUrl - Relative URL for the login callback
 * @param {string} options.privateKey - Optional private key for signing SAML requests
 * @constructor
 */
module.exports.Strategy = function (options) {
    options = options || {};
    options.entryPoint = options.entryPoint || idpEntryPoint;
    options.cert = options.cert || idpCert;
    options.identifierFormat = null;
    options.issuer = options.issuer || options.entityId || options.domain;
    options.port = options.port || 443;
    options.callbackUrl = 'https://' + options.domain + ':' + options.port + options.callbackUrl;
    options.decryptionPvk = options.privateKey;
    options.privateCert = options.privateKey;


    saml.Strategy.call(this, options, verifyProfile);
    this.name = strategyName;
};


util.inherits(module.exports.Strategy, saml.Strategy);

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var myaccess = require(...);
        var strategy = new myaccess.Strategy({...});
        app.get(myaccess.urls.metadata, myaccess.metadataRoute(strategy, myPublicCert));
*/

/**
 * Returns a route implementation for the standard Shibboleth metadata route.
 * common usage:
 *  var myaccess = reuqire('passport-myaccess');
 *  var myPublicCert = //...read public cert PEM file
 *  var strategy = new myaccess.Strategy({...});
 *  app.get(myaccess.urls.metadata, myaccess.metadataRoute(strategy, myPublicCert));
 *
 * @param strategy - The new Strategy object from this module
 * @param publicCert - Your server's public certificate (typically loaded from a PEM file)
 * @returns {Function} - Route implementation suitable for handing to app.get()
 */
module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/xml');
        res.status(200).send(strategy.generateServiceProviderMetadata(publicCert));
    }
}; //metadataRoute

/**
 * Middleware for ensuring that the user has authenticated.
 * You can use this in two different ways. If you pass this to app.use(), it will secure all routes
 * that are added to the app after that. Or you can use this selectively on routes by adding it as
 * the first route handler function, like so:
 *  app.get('/secure/route', ensureAuth(loginUrl), function(req, res) {...});
 *
 * @param loginUrl - The URL to redirect to if the user is not authenticated
 * @returns {Function} - Middleware function that ensures authentication
 */
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            if (req.session) {
                req.session.authRedirectUrl = req.url;
            }
            else {
                console.warn('passport-myaccess: No session property on request!'
                    + ' Is your session store unreachable?')

            }
            res.redirect(loginUrl);
        }
    }
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var myaccess = require(...);
        var strategy = new myaccess.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), myaccess.backtoUrl());
        app.use(myaccess.ensureAuth('/login'));
*/
/**
 * Middleware for redirecting back to the originally requested URL after a successful authentication.
 * The ensureAuth() middleware in this same module will capture the current URL in session state, and
 * you can use this method to get back to the originally-requested URL during your login callback route.
 * Usage:
 *  var myaccess = require('passport-myaccess');
 *  var strategy = new myaccess.Strategy({...});
 *  app.get('/login', passport.authenticate(strategy.name));
 *  app.post('/login/callback', passport.authenticate(strategy.name), myaccess.backToUrl());
 *  app.use(myaccess.ensureAuth('/login'));
 *  //...rest of routes
 *
 * @param defaultUrl - Optional default URL to use if no redirect URL is in session state (defaults to '/')
 * @returns {Function} - Middleware function that redirects back to originally requested URL
 */
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = defaultUrl || '/';
        if (req.session) {
            url = req.session.authRedirectUrl || url;
            delete req.session.authRedirectUrl;
        }
        res.redirect(url);
    }
};

