###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_tenda.inc
#
# Revision: 1.2
###

include('compat_shared.inc');
include('vcf.inc');

namespace vcf
{
  namespace tenda
  {
    ##
    # Switch version checking from "version" to "firmware"
    #
    # @return [array] app_info
    ##
    function get_app_info()
    {
      var app, parsed_version;

      app = vcf::get_app_info(app:'Tenda AC Router');

      if (empty_or_null(app['firmware']))
        ::audit (AUDIT_UNKNOWN_APP_VER, 'Tenda AC Router firmware');

      parsed_version = parse_version(app['firmware']);
      app['parsed_version'] = parsed_version;
      app['display_version'] = app['firmware'];

      return app;
    }

    ##
    # Checks a Tenda app_info array version and reports results
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
      if (isnull(app_info))
          return arg_error(arg:'app_info', func:FUNCTION_NAME);
      if (isnull(severity))
          return arg_error(arg:'severity', func:FUNCTION_NAME);
      if (isnull(constraints))
          return arg_error(arg:'constraints', func:FUNCTION_NAME);

      # Check model
      if (empty_or_null(app_info.model))
        vcf::audit(app_info);

      var filtered_constraints = make_list();

      foreach var constraint (constraints)
      {
        if (tolower(constraint.model) == tolower(app_info.model))
          append_element(var:filtered_constraints, value:constraint);
      }

      var matching_constraint = vcf::check_version(
        version:app_info.parsed_version,
        constraints:filtered_constraints,
        strict:strict
      );

      if (vcf::is_error(matching_constraint))
        return vcf::vcf_exit(1, matching_constraint.message);

      if (empty_or_null(matching_constraint))
        return vcf::audit(app_info);

      var fix = matching_constraint.fixed_display;
      if (empty_or_null(fix))
        fix = matching_constraint.fixed_version;

      var order = ['Model', 'Firmware version', 'Fixed version'];
      var report_items = make_array(
        order[0], app_info.model,
        order[1], app_info.display_version,
        order[2], fix
      );

      var report = report_items_str(report_items:report_items, ordered_fields:order);

      store_structured_data(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, port:0);

      security_report_v4(
        severity:severity,
        port:0,
        extra:report,
        xss:flags.xss,
        xsrf:flags.xsrf,
        sqli:flags.sqli,
        proto:app_info.proto
      );
      return vcf_exit(0);
    }
  }
}
