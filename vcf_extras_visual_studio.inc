###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_visual_studio.inc
#
# Revision: 1.3
###

include('compat_shared.inc');
include('install_func.inc');
include('lists.inc');
include('vcf.inc');

namespace vcf
{
  namespace visual_studio
  {
    ##
    # Builds app_info for Visual Studio
    #
    # @return [array] an array containing application info
    ##
    function get_app_info()
    {
      var app_info = {'app': 'Microsoft Visual Studio'};
      var port = get_kb_item('SMB/transport');
      if(port)
        app_info['port'] = int(port);
      else
        app_info['port'] = 445;

      var install = get_single_install(app_name:app_info.app, exit_if_unknown_ver:TRUE);
      app_info['product'] = install.product_version;
      app_info['path'] = install.path;
      app_info['version'] = install.version;
      app_info['parsed_version'] = vcf::parse_version(app_info.version);

      return app_info;
    }

    ##
    # Checks a Visual Studio app_info array version and reports results
    #
    # @param [app_info:array]   array containing application info
    # @param [constraints:list] list of constraint arrays
    # @param [severity:int]     severity used for reporting
    # @param [strict:boolean]   bool that determines whether or not version/fix should
    #                           require the same number of fields
    # @param [flags:array]      array of reporting flags (xss, sqli, xsrf)
    #
    # @remark
    # This function exits.
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags)
    {
      if(isnull(app_info))
        return arg_error(arg:'app_info', func:FUNCTION_NAME);
      if(isnull(severity))
        return arg_error(arg:'severity', func:FUNCTION_NAME);
      if(isnull(constraints))
        return arg_error(arg:'constraints', func:FUNCTION_NAME);

      var filtered_constraints = _filter_constraints(app_info:app_info, constraints:constraints);

      if(empty_or_null(filtered_constraints))
        return vcf::audit(app_info);

      var matching_constraint = vcf::check_version(
        version:app_info.parsed_version,
        constraints:filtered_constraints,
        strict:strict
      );

      if(vcf::is_error(matching_constraint))
        return vcf::vcf_exit(1, matching_constraint.message);

      if(empty_or_null(matching_constraint))
        return vcf::audit(app_info);

      var fix = matching_constraint.fixed_display;
      if(empty_or_null(fix))
        fix = matching_constraint.fixed_version;

      var order = ['Path', 'Installed version', 'Fixed version'];
      var report_items = make_array(
        order[0], app_info.path,
        order[1], app_info.version,
        order[2], fix
      );
      var report = report_items_str(report_items:report_items, ordered_fields:order);

      store_structured_data(app_info:app_info,
                            fix:fix,
                            fix_version:matching_constraint.fixed_version,
                            port:app_info.port);

      security_report_v4(
        severity:severity,
        port:app_info.port,
        extra:report,
        xss:flags.xss,
        xsrf:flags.xsrf,
        sqli:flags.sqli
      );
      return vcf_exit(0);
    }

    ##
    # Filter out constraints which aren't relevant to the app_info's product version (E.g 2017 / 2019).
    #
    # @param [app_info:array]   array containing application info
    # @param [constraints:list] list of constraint arrays
    ##
    function _filter_constraints(app_info, constraints)
    {
      return collib::filter(constraints, args:[app_info], f: function ()
      {
        var app_info = _FCT_ANON_ARGS[0];
        var constraint = _FCT_ANON_ARGS[1];
        return app_info.product >< constraint.product;
      });
    }
  }
}
