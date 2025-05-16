##
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# nuget.inc
#
# Revision: 0.2
#
###

##
#
#   nuget related functions.
#
##

include('compat_shared.inc');
include('hostlevel_funcs.inc');
include('debug.inc');

namespace nuget {
  ##
  #  Query package info from NuGet package repository database built in
  #  nuget_package_enumeration_win_installed.nbin and nuget_package_enumeration_nix_installed.nbin

  #  @param {String} pkg_name NuGet package name.
  #  @returns {NULL or Array} NULL or Array containing info regarding the package.
  ##
  var NUGET_PACKAGE_REPO_DB = 'nuget_pkg_inventory';

  function query_nuget_package(pkg_name)
  {
    var query_db;

    if ( empty_or_null(pkg_name) )
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Missing required argument "pkg_name".');
      return NULL;
    }

    query_db = NUGET_PACKAGE_REPO_DB;

    return query_scratchpad(
      strcat('SELECT subpath, version from ', query_db, ' WHERE name = ?;'),
      pkg_name
    );
  }
}