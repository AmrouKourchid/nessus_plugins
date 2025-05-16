##
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# jai_ext.inc
#
# Revision: 0.3
#
###

##
#
#   Jai-Ext related functions.
#
##

include('compat_shared.inc');
include('hostlevel_funcs.inc');
include('debug.inc');

namespace jai_ext {
  ##
  #  Query package info from Jai-Ext package repository database built in
  #  geosolutions_jai_ext_nix_installed.nbin

  #  @param {String} pkg_name Jai-Ext package name.
  #  @returns {NULL or Array} NULL or Array containing info regarding the package.
  ##

  #pragma const
  var JAI_EXT_PACKAGE_REPO_DB = 'jai_ext_pkg_inventory';
  var scheme = 'pkg';
  var type = 'Jai-Ext';
  #pragma const(false)

  function query_jai_ext_package(pkg_name)
  {
    var query_db;

    if ( empty_or_null(pkg_name) )
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Missing required argument "pkg_name".');
      return NULL;
    }

    return query_scratchpad(
      strcat('SELECT subpath, version from ', JAI_EXT_PACKAGE_REPO_DB, ' WHERE name = ?;'),
      pkg_name
    );
  }

  function init_scratchpad()
  {
    query_scratchpad(strcat(
      '
        CREATE TABLE IF NOT EXISTS ', JAI_EXT_PACKAGE_REPO_DB, ' 
        (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scheme TEXT,
          type TEXT,
          name TEXT,
          version TEXT,
          subpath TEXT,
          purl TEXT
          
        );
      '
    ));
  }

  function insert_package(name,version,subpath)
  {
    # standard for PURL = scheme:type/namespace/name@version
    var purl = strcat(scheme, ':', type, '/', name, '@', version);

    query_scratchpad(
      strcat('INSERT INTO ', jai_ext::JAI_EXT_PACKAGE_REPO_DB, ' VALUES (null, ?, ?, ?, ?, ?, ?);'),
      scheme,
      type,
      name,
      version,
      subpath,
      purl
    );
  }
}