###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_netscaler.inc
#
# Revision: 1.6
###
include('compat_shared.inc');
include('vcf.inc');

namespace vcf
{
  namespace citrix_netscaler
  {
    ##
    # Builds app_info for Netscaler
    #
    # @return [array] an array containing application info
    ##
    function get_app_info()
    {
      get_kb_item_or_exit('Host/NetScaler/Detected');
      var app_info = {};

      var version = get_kb_item_or_exit('Host/NetScaler/Version');
      var build = get_kb_item_or_exit('Host/NetScaler/Build');
      var fipsStatus = get_kb_item('Host/NetScaler/fipsStatus');
      # Can either be TRUE, FALSE or not set (NULL) in the NTP case
      var enhanced = get_kb_item('Host/NetScaler/Enhanced');
      if (!isnull(enhanced))
        app_info['enhanced'] = enhanced;

      app_info['app'] = 'Citrix NetScaler';
      app_info['port'] = 0;
      app_info['version'] = version + '.' + build;
      app_info['display_version'] = version + '-' + build;
      app_info['parsed_version'] = vcf::parse_version(app_info['version']);
      app_info['fips_status'] = fipsStatus;
      app_info["cpe/v23"] = "cpe:2.3:a:citrix:netscaler";

      return app_info;
    }

    ##
    # Checks a Netscaler app_info array version and reports results
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

      var matching_constraint = check_version(
        version:app_info.parsed_version,
        constraints:constraints,
        fips:app_info['fips_status'],
        strict:strict
      );

      if (vcf::is_error(matching_constraint))
        return vcf::vcf_exit(1, matching_constraint.message);

      if (empty_or_null(matching_constraint))
        return vcf::audit(app_info);

      var fix = matching_constraint.fixed_display;
      if (empty_or_null(fix))
        fix = matching_constraint.fixed_version;

      var order = ['Installed version', 'Fixed version'];
      var report_items = make_array(
        order[0], app_info.display_version,
        order[1], fix
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
        sqli:flags.sqli,
        proto:app_info.proto
      );
      return vcf_exit(0);
    }

    ##
    # Used to check whether or not a Netscaler application
    # version meets any of the given constraints
    #
    # @param [version:string]   version to be checked against constraints (already parsed)
    # @param [constraints:list] a list of constraint arrays
    # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
    # @param [fips:boolean]     if set, and fips is enabled on target will check against matching constraints.
    #
    # @return [array|error|NULL] a matching constraint
    #         Error object
    #         NULL - no matching constraints
    #
    # @remark
    # Possible constraint values:
    #  min_version - operates as >=
    #  max_version - operates as <=
    #  fixed_version - operates as <
    #  equal - operates as ==. no other checks performed within this same constraint
    #  fixed_display purely a display value and nothing more
    ##
    function check_version(version, constraints, strict, fips)
    {
      local_var meets_constraint, constraint;

      if (isnull(version) || typeof(version) != "array") return arg_error(arg:"version", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
      if (isnull(strict)) strict = FALSE;

      # [[],[0]] should not be handled as [[0],[0]] and should not match constraint {'min_version':'0.0',...}
      if (max_index(version) < 1 || max_index(version[0]) < 1) return NULL;

      foreach constraint (constraints)
      {
        if (fips != constraint.fips)
          continue;

        meets_constraint = vcf::check_version_against_constraint(version:version, constraint:constraint, strict:strict);
        if (is_error(meets_constraint)) return meets_constraint;

        if (meets_constraint) return constraint;
      }

      return NULL;
    }
  }
}
