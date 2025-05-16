##
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_autodesk.inc
#
# Revision: 1.1
##

include('compat_shared.inc');
include('vcf.inc');

namespace vcf
{
  namespace autodesk
  {
    namespace navisworks
    {
      ##
      # Gather the Autodesk Navisworks (Freedom, Manage, Simulate, etc.) info and formats it correctly
      #
      # @param [type:string] The type of Navisworks install (e.g. Freedom, Manage, Simulate)
      #
      # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
      ##
      function get_app_info(type)
      {
        local_var app_info, sw_edition, update, update_number;
        if (isnull(type)) return arg_error(arg:'type', func:FUNCTION_NAME);

        # Autodesk Navisworks is only available on Windows
        get_kb_item_or_exit('SMB/Registry/Enumerated');

        var app = 'Autodesk Navisworks ' + type;

        app_info = vcf::get_app_info(app:app, win_local:TRUE);

        # Version numbers does not change when updates are applied. We need to use 'sw_edition' and 'update' info
        sw_edition = app_info.sw_edition;
        update = app_info.update;

        # If sw_edition is null, we cannot transform the version. Exit, because we cannot perform a proper version check
        if (empty_or_null(sw_edition))
        {
          exit(0, 'The edition of the Autodesk Navisworks install (e.g. 2025) at ' + app_info.path + ' is unknown. A proper version check cannot be done.');
        }

        app_info.version = sw_edition;

        update_number = pregmatch(string:update, pattern:"^(?:Update )?(\d+)", icase:TRUE);
        if (!empty_or_null(update_number) && !empty_or_null(update_number[1]))
        {
          app_info.version = app_info.version + '.' + update_number[1];
        }
        else
        {
          app_info.display_version = app_info.version;
          app_info.version = app_info.version + '.0';
        }

        app_info.parsed_version = parse_version(app_info.version);

        return app_info;
      }
    }
  }
}
