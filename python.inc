###
# Library for Python package related functions.
#
# @license
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 0.4
#
# @os Windows
# @os Linux
###

include('compat_shared.inc');
include('hostlevel_funcs.inc');
include('debug.inc');
include('vcf.inc');

global_var PYTHON_PACKAGE_REPO_DB_NIX = 'python_pkg_inventory_nix';
global_var PYTHON_PACKAGE_REPO_DB_WIN = 'python_pkg_inventory_win';

namespace python {
  ##
  # Obtains information for a given python package.
  #
  # @param [pkg_name:string] Name of the Python package.
  # @param [search:string] String for the SQL package search. (optional, defaults to NULL)
  #
  # @return [array] The organized pakage informaiton.
  #
  # @tags branch
  # @remark
  #  This function can exit.
  ##
  function get_package_info(pkg_name, search)
  {
    local_var os, found_libs, lib, lib_info;

    if (isnull(pkg_name)) exit(1, "No pkg_name was passed to python:get_package_info.");

    if (get_kb_item("Host/nix/Python/Packages/Enumerated"))
      os = 'nix';
    else if (get_kb_item("Host/win/Python/Packages/Enumerated"))
      os = 'win';
    else
      exit(0, "No python packages have been enumerated.");

    found_libs = query_python_package(os:os, pkg_name:pkg_name, search:search);

    if (empty_or_null(found_libs))
      audit(AUDIT_NOT_INST, pkg_name);

    lib = branch(found_libs);

    lib_info = {
      'app'            : pkg_name,
      'version'        : lib.version,
      'parsed_version' : vcf::parse_version(lib.version),
      'path'           : lib.path
    };

    return lib_info;
  }

  ##
  #  Query package info from Python package repository database built in
  #  python_packages_installed_nix.nbin and python_package_installed_win.nbin
  #
  #  @param [os:string] os The OS name. Valid values can be 'nix' or 'win'.
  #  @param [pkg_name:string] pkg_name Python package name.
  #  @param [search:string] String for the SQL package search. (optional, defaults to NULL)
  # 
  #  @returns [array] NULL or an Array containing info regarding the package.
  #
  # @remark
  #  Has some debug logging.
  ##
  function query_python_package(os, pkg_name, search)
  {
    var query_db, ret;

    if ( empty_or_null(os) || empty_or_null(pkg_name) )
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Missing required argument "os" or "pkg_name".');
      return NULL;
    }

    if ( os != 'nix' && os != 'win' )
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Valid values for "os" are: "nix" or "win".');
      return NULL;
    }

    if ( os == 'nix' )
      query_db = PYTHON_PACKAGE_REPO_DB_NIX;
    else
      query_db = PYTHON_PACKAGE_REPO_DB_WIN;

    if (!empty_or_null(search))
      ret = query_scratchpad(strcat('SELECT pkg_name,path,version from ', query_db, ' WHERE pkg_name LIKE \'', search, '\';'));
    else
      ret = query_scratchpad(strcat('SELECT pkg_name,path,version from ', query_db, ' WHERE pkg_name = ?;'), pkg_name);

    dbg::detailed_log(lvl:1, src:SCRIPT_NAME,
      msg:'Package Search Details.',
      msg_details:{
        'Package Name':{'lvl':1,'value':pkg_name},
        'Search String':{'lvl':1,'value':search},
        'Search Results':{'lvl':2,'value':ret},
        'Full DB':{'lvl':3,'value':query_scratchpad(strcat('SELECT * from ', query_db, ' WHERE pkg_name LIKE \'%',pkg_name,'%\';'))}
    });

    return ret;
  }
}

