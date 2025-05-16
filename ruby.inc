#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ruby.inc
#
# Revision: 0.2
#
###

##
#
#   Ruby related functions.
#
##

include('compat_shared.inc');
include('hostlevel_funcs.inc');
include('debug.inc');


global_var RUBY_GEM_REPO_DB = 'ruby_module_inventory';

namespace ruby {
  ##
  #  Query gem info from Ruby gem repository database built in
  #  ruby_modules_nix_installed.nasl and ruby_modules_win_installed.nasl

  #  @param {String} os The OS name. Valid values can be 'nix' or 'win'.
  #  @param {String} gem_name Ruby gem name.
  #  @returns {NULL or Array} NULL or Array containing info regarding the gem.
  ##
  function query_ruby_gem(gem_name)
  {
    if (empty_or_null(gem_name) )
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Missing required argument "gem_name".');
      return NULL;
    }

    return query_scratchpad(
      strcat('SELECT module_version, module_path FROM ', RUBY_GEM_REPO_DB, ' WHERE module_name = ?;'),
      gem_name
    );
  }
}

