###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_nodejs.inc
#
# Revision: 1.1
###

include('vcf.inc');
include('compat_shared.inc');

namespace vcf_extras
{
  namespace nodejs_modules
  {
    ##
    # Same as standard VCF function but pulls module information from scratch pad
    # Node.js install for Windows, Linux and macOS targets.
    #
    # @param [app:string] The app name for which to get the info.
    #
    # @return [array] The app info array containing:
    # app name, version, path, parsed version, cpe, and port.
    ##
    function get_app_info(app) {

      var nodejs_info = vcf::combined_get_app_info(app:'Node.js');
      get_kb_item_or_exit('Host/nodejs/modules/enumerated');
      var found_modules = query_scratchpad('SELECT * FROM nodejs_module_inventory WHERE module_name = ?', app);
      if (empty_or_null(found_modules)) ::audit(AUDIT_NOT_INST, app);

      var info = branch(found_modules);
      var install_info =
      {
        'app':app,
        'version':info.module_version,
        'path':info.module_path,
        'parsed_version':vcf::parse_version(info.module_version),
        'cpe':info.module_cpe,
        'webapp':FALSE,
        'port':nodejs_info.port,
        'cpe/v23':nodejs_info["cpe/v23"]
      };

      return install_info;
    }
  }
}

