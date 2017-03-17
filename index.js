'use strict';

var util = require('util');
var xtend = require('xtend');
var get = require('lodash.get');
var foreach = require('lodash.foreach');
var filter = require('lodash.filter');

var UnauthorizedError = require('./error');
var PermissionError = new UnauthorizedError(
  'permission_denied', {
    message: 'Permission denied'
  }
);

var Guard = function (options) {
  var defaults = {
    requestProperty: 'user',
    permissionsProperty: 'permissions'
  };

  this._options = xtend(defaults, options);
};

Guard.prototype = {
  //Checks if user is a member of any role out of array of roles passed.
	checkRoleInRoles: function(required) {
		if (typeof required === 'string') {
			required = [required];
		}

		return _middleware.bind(this)

		function _middleware(req, res, next) {
			var self = this;
			var options = self._options;

			var user = req[options.requestProperty];
			if (!user) {
				return next();
			}

			var permissions = user[options.permissionsProperty];

			if (!permissions) {
				return next(new UnauthorizedError('permissions_not_found', {
					message: 'Could not find permissions for user. Bad configuration?'
				}));
			}

			if (!Array.isArray(permissions)) {
				return next(new UnauthorizedError('permissions_invalid', {
					message: 'Permissions should be an Array. Bad format?'
				}));
			}

			var rolesPermissions = filter(permissions, function(perm) {
				return perm.indexOf('role:') !== -1;
			});

			var sufficientRoleAccess = false;
			foreach(rolesPermissions, function(permission) {
				foreach(required, function(requiredPermission) {
					if (permission.indexOf(requiredPermission) !== -1) {
						sufficientRoleAccess = true;
					}
				});
			});

			return next(!sufficientRoleAccess ? PermissionError : null);
		}
	},
	//Checks if user has any of the permissions out of the array of permissions passed.
	checkPermInPermissions: function(required) {
		if (typeof required === 'string') {
			required = [required];
		}

		return _middleware.bind(this)

		function _middleware(req, res, next) {
			var self = this;
			var options = self._options;

			var user = req[options.requestProperty];
			if (!user) {
				return next();
			}

			var permissions = user[options.permissionsProperty];

			if (!permissions) {
				return next(new UnauthorizedError('permissions_not_found', {
					message: 'Could not find permissions for user. Bad configuration?'
				}));
			}

			if (!Array.isArray(permissions)) {
				return next(new UnauthorizedError('permissions_invalid', {
					message: 'Permissions should be an Array. Bad format?'
				}));
			}

			var permissionsOnly = filter(permissions, function(perm) {
				return perm.indexOf('role:') === -1;
			});

			var sufficientPermissionsAccess = false;
			foreach(permissionsOnly, function(permission) {
				foreach(required, function(requiredPermission) {
					if (permission.indexOf(requiredPermission) !== -1) {
						sufficientPermissionsAccess = true;
					}
				});
			});

			return next(!sufficientPermissionsAccess ? PermissionError : null);
		}
	},
	//original check; is inclusive so that all 'required' must be in the permissions array
  check: function (required) {
    if (typeof required === 'string') {
      required = [required];
    }

    return _middleware.bind(this);

    function _middleware(req, res, next) {
      var self = this;
      var options = self._options;

      if (!options.requestProperty) {
        return next(new UnauthorizedError('request_property_undefined', {
          message: 'requestProperty hasn\'t been defined. Check your configuration.'
        }));
      }

      var user = req[options.requestProperty]
      if (!user) {
        return next(new UnauthorizedError('user_object_not_found', {
          message: util.format('user object "%s" was not found. Check your configuration.', options.requestProperty)
        }));
      }

      var permissions = get(user, options.permissionsProperty, undefined)
      if (!permissions) {
        return next(new UnauthorizedError('permissions_not_found', {
          message: 'Could not find permissions for user. Bad configuration?'
        }));
      }

      if (!Array.isArray(permissions)) {
        return next(new UnauthorizedError('permissions_invalid', {
          message: 'Permissions should be an Array. Bad format?'
        }));
      }

      var sufficient = required.every(function (permission) {
        return permissions.indexOf(permission) !== -1;
      });

      return next(!sufficient ? PermissionError : null);
    }
  }

};

module.exports = function (options) {
  return new Guard(options);
};