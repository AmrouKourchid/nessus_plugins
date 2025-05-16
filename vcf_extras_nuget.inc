###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_nuget.inc
#
# Revision: 1.4
###

include('compat_shared.inc');
include('vcf.inc');
include('nuget.inc');
include('install_func.inc');

namespace vcf
{
  namespace nuget_package
  {
    ##
    # Gather the NuGet package installs info and puts them into an array.
    #
    # @param [pkg_name:string] The NuGet package name to search for.
    #
    # @return [array] The consolidated app info array, originally gathered from the scratchpad ``nuget::NUGET_PACKAGE_REPO_DB`` table.
    #
    # @remark
    # This function will branch out if multiple installs are found. But it will audit out if none are found.
    ##
    function get_app_info(pkg_name)
    {
      local_var app_info, pkg_info;
      if (isnull(pkg_name)) return arg_error(arg:"pkg_name", func:FUNCTION_NAME);

      if (query_scratchpad(strcat("SELECT name FROM sqlite_master WHERE type = 'table' AND name = '", nuget::NUGET_PACKAGE_REPO_DB, "';")))
        pkg_info = nuget::query_nuget_package(pkg_name:tolower(pkg_name));
      else
        vcf::vcf_exit(0);

      if (pkg_info)
      {
        app_info = branch(pkg_info);
        app_info.path = app_info.subpath;

        # Inform customers they need paranoid if they want to fire against unknown versions
        if (tolower(app_info.version) == 'unknown' && report_paranoia < 2)
          exit(0, 'The version of NuGet Package: ' + pkg_name + ' could not be determined, but it may ' +
              'still be vulnerable. To report on unknown versions, please enable Paranoid scanning.');

        app_info.parsed_version = vcf::parse_version(app_info.version);
        app_info.app = pkg_name;
        app_info["cpe/v23"] = "cpe:2.3:a:microsoft:nuget";

        return app_info;
      }
      else
        vcf::audit();
    }


    ##
    # Registers a detected installation of Nuget
    #
    # @param [app_info:array] Information about the installation.
    #
    # @remark
    # This function audits on error.
    ##
    function reg_install(app_info)
    {
      if (!empty_or_null(app_info))
      {
        var lib = branch(app_info);
        var lib_info = {
          'app' : app_info.app,
          'version' : app_info.version,
          'display_version' : app_info.version,
          'path' : app_info.path
        };

        if(empty_or_null(lib_info.vendor))
          lib_info.vendor = lib_info.app;

        if(empty_or_null(lib_info.xcpe))
          lib_info.xcpe = strcat('a:', lib_info.app, ':', lib_info.app);

        register_install(
            app_name        : lib_info.app,
            vendor          : lib_info.vendor,
            path            : lib_info.path,
            version         : lib_info.version,
            cpe             : strcat('x-cpe:/',lib_info.xcpe)
          );
        report_installs(app_name:lib_info.app);
      }
      else
        audit(AUDIT_NOT_DETECT, app_info.app);
    }
  }
}
