##
# (C) Tenable, Inc.
##
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# vcf_extras_trendmicro.inc
#
# Revision: 1.1

include('compat_shared.inc');
include('install_func.inc');
include('vcf.inc');

namespace vcf
{
  namespace trendmicro
  {
    namespace apex_central
    {
      function get_app_info() {
        var app_name = 'Trend Micro Apex Central';
        var app_info = vcf::get_app_info(app:app_name);

        if (empty_or_null(app_info.Build))
          ::audit(AUDIT_VER_NOT_GRANULAR, app_name, app_info['version']);

        app_info.display_version = app_info.version;
        app_info.version = app_info.Build;

        # Workaround for the issue with single segment versions
        var parsed_version = vcf::parse_version(app_info.version + '.0');
        if (vcf::is_error(parsed_version))
          return vcf::vcf_exit(1, parsed_version.message);

        app_info.parsed_version = parsed_version;
        
        app_info.display_version = app_info.display_version + ' Build ' + app_info.version;
        if(!empty_or_null(app_info.Hotfix))
          app_info.display_version = app_info.display_version + ' Patch ' + app_info.Hotfix;

        return app_info;
      }
    }
  }
}
