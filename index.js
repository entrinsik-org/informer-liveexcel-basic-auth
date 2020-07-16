'use strict';
const _ = require('lodash');
const semverRegex = /5\.([0-9]*)\..*/;

/**
 * Uses domain driver to authenticate
 * @param domain
 * @param req
 * @returns {Promise}
 */
const domainAuthenticate = (domain, req) => {
    return new Promise((resolve, reject) => {
        const r = (err, result) => err ? reject(err) : resolve(result);
        req.server.plugins.travelite.passport.authenticate(
            'domain',
            domain,
            r
        )(req, reject);
    });
};

exports.register = (server, opts, next) => {
    server.auth.strategy('lebasic', 'basic', {
        unauthorizedAttributes: { realm: 'Informer' },
        async validateFunc (req, username, password, next) {
            try {
                let credentials = null;
                const { models: { Domain }, sequelize } = req.server.app.db;
                //find the domain of the user, if no user, no allow
                const [ domain ] = await sequelize.query(`
                    SELECT domain.* 
                      FROM domain, "user"
                     WHERE "user".domain = domain.id
                       AND lower("user".username) = lower(:username)`,
                    {
                        model: Domain,
                        type: sequelize.QueryTypes.SELECT,
                        replacements: { username: username }
                    }
                );
                if (domain) {
                    /*
                        mimic what a request payload would look like from informer login form. Currently the
                        domain strategy must handle the request in this manner, so SAML domains would error out, but that
                        doesn't fit the requirement anyway. But traditional user/pass domain implementations
                        would need to accept this form of payload, or have an identifier on the domain driver that
                        specifies what they should be, to coerce later
                     */
                    _.merge(req, { payload: { username: username, password: password } });
                    const res = await domainAuthenticate(domain, req);
                    //coerce user in case username needs coercion
                    const user = res && await domain.coerce(res);
                    credentials = user && await server.methods.auth.userCredentials(user.username);
                }
                next(null, !!credentials, credentials);
            } catch (err) {
                next(err);
            }
        }
    });

    server.on('start', () => {
        try {
            const minor = semverRegex.exec(_.get(server,['app','config','build','version']));
            const deprecated = minor && (parseInt(minor[1]) > 3);
            if(deprecated) console.log(`
*******************************************************************************************
*
*     informer-livexcel-basic-auth plugin is no longer necessary as of version 5.4.0
*
*******************************************************************************************`);
        } catch (e) {
            //do nothing
        }
        const liveExcelRoute = server.match('post','/api/live-excel/basic');
        if(liveExcelRoute) {
            liveExcelRoute.auth = 'lebasic';
            const strategies = _.get(liveExcelRoute, ['settings', 'auth', 'strategies']);
            strategies[0] = 'lebasic';
        }
    });
    next();
};

exports.register.attributes = { name: 'liveexcel-basic-auth'};


