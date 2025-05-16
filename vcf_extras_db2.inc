###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_db2.inc
#
# Revision: 1.2
###

include('compat_shared.inc');
include('db2_report_func.inc');
include('install_func.inc');
include('vcf.inc');

namespace vcf
{
  namespace ibm_db2
  {
    ##
    # Gather the IBM DB2 install info and puts it in an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    ##
    function get_app_info()
    {
        var app_name = 'DB2 Server';
        var app_info = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

        app_info['app'] = app_name;
        app_info['version'] = app_info['kb_version'] = app_info['version'];
        app_info['parsed_version'] = vcf::parse_version(app_info['version']);

        if (!app_info['port'])
          app_info['port'] = 0;

        if (empty_or_null(app_info['special_build']))
          app_info['special_build'] = 'None';

        return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    #   This function calls ``report_db2()`` to report results then exits or audits if no
    #   matching constraint is found.
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags)
    {
      var fix, matching_constraint;
      var vuln = FALSE;
      if (isnull(app_info))
          return arg_error(arg:'app_info', func:FUNCTION_NAME);
      if (isnull(severity))
          return arg_error(arg:'severity', func:FUNCTION_NAME);
      if (isnull(constraints))
          return arg_error(arg:'constraints', func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);

      if (vcf::is_error(matching_constraint))
        return vcf::vcf_exit(1, matching_constraint.message);

      if (isnull(matching_constraint))
        return vcf::audit(app_info);

      vuln = TRUE;
      if (!empty_or_null(matching_constraint.equal))
      {
        if(app_info.special_build != 'None' &&
           ver_compare(ver:app_info.special_build, fix:matching_constraint.fixed_build, strict:FALSE) >= 0)
          vuln = FALSE;
      }

      if (!vuln)
        return vcf::audit(app_info);

      fix = matching_constraint.fixed_display;
      if (isnull(fix))
        fix = matching_constraint.fixed_version;

      if (isnull(fix))
        fix = matching_constraint.equal;

      store_structured_data(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version,
                            port:app_info.port);

      report_db2(
        severity          : severity,
        port              : app_info.port,
        product           : app_info.app,
        path              : app_info.path,
        installed_version : app_info.version,
        fixed_version     : fix,
        special_installed : app_info.special_build,
        special_fix       : matching_constraint.fixed_build
      );

      return vcf::vcf_exit(0);
    }
  }
}
