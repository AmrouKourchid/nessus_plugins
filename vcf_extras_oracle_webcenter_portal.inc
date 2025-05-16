###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_webcenter_portal.inc
#
# Revision: 1.3
###

include('compat_shared.inc');
include('vcf.inc');
include('oracle_webcenter_portal_patch_mapping.inc');
include('patches.inc');
include('spad_log_func.inc');
include('debug.inc');

namespace vcf
{
  namespace oracle_webcenter_portal
  {
    ##
    # Builds app_info for Oracle WebCenter Portal
    #
    # @return [array] an array containing application info
    ##
    function get_app_info()
    {
      var app_info = vcf::get_app_info(app:'Oracle WebCenter Portal');
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Gathered first app_info",
        msg_details: {
          "app_info": {"lvl": 2, "value": obj_rep(app_info)}});
      var regex_ver = app_info['version'];

      # Remove trailing 0 for regex match
      if (regex_ver =~ ".0$")
        regex_ver = substr(regex_ver, 0, len(regex_ver) - 3);


      var esc_ver = ereg_replace(pattern:"\.", replace:"\.", string:regex_ver);
      var regex_filter = "^" + esc_ver + "\.";
      var patches = split(app_info['Patches'], sep:' ', keep:FALSE);
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Found patches",
        msg_details: {
          "patches": {"lvl": 3, "value": obj_rep(patches)}});
      var super_map = make_array();
      var patch_mapper = new oracle_ebusiness_patch_mapper(webcenter_portal_version_map, patches, super_map, regex_filter);
      var patched_version_list = patch_mapper.patched_version_list;
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Found patched_version_list",
        msg_details: {
          "patched_version_list": {"lvl":3, "value":obj_rep(patched_version_list)}});
      # If patches are installed, set the version accordingly, otherwise leave it as .0
      if (max_index(patched_version_list) > 0)
      {
        app_info['version'] = patched_version_list[max_index(patched_version_list) - 1];
        app_info['parsed_version'] = vcf::parse_version(app_info['version']);
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "Updated app_info",
          msg_details: {
            "app_info": {"lvl": 2, "value": obj_rep(app_info)}});
      }

      return app_info;
    }

    ##
    # Calls both ``vcf::check_version()`` and ``report_results()``.
    #
    # @param [app_info:array] array containing application info. requires, at minimum, a
    # key/value pair for 'version'
    # @param [constraints:list] list of constraint arrays
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] bool that determines whether or not version/fix should
    # require the same number of fields
    # @param [flags:array] array of reporting flags (xss, sqli, xsrf)
    #
    # @remark
    # This function exits.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      var matching_constraint, fix;
      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if (!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if (isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info,
                       fix:fix,
                       fix_version:matching_constraint.fixed_version,
                       severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf::vcf_exit(0);
    }

    ##
    # Call ``security_report_v4()`` with given severity and flags.
    #
    # @param [app_info:array] app info to use in report
    # @param [fix:string] the fixed version to include in report
    # @param [fix_version:string] The fixed version as a comparable string. (optional)
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] array of reporting flags (xss, sqli, xsrf)
    # @param [webapp:boolean] converts path to a URL
    #
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      var report, version, port, extra_report, order;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;
      report = vcf::build_report(version:version,
                                 fix:fix,
                                 path:app_info.path,
                                 source:app_info.source,
                                 webapp:app_info.webapp,
                                 port:app_info.port);

      # Remove final newline to add more entries to report
      report = substr(report, 0, len(report) - 2);
      extra_report = make_array();
      extra_report['Patches installed'] = app_info['Patches'];
      extra_report['Required patch'] = webcenter_portal_version_map[fix];
      extra_report['Oracle home'] = app_info['Home'];
      order = ['Oracle home', 'Required patch', 'Patches installed'];
      extra_report = report_items_str(report_items:extra_report, ordered_fields:order);
      report += extra_report;

      if (vcf::is_error(report)) return vcf::vcf_exit(1, report.message);

      port = app_info.port;
      if (isnull(port)) port = 0;

      store_structured_data(app_info:app_info, fix:fix, fix_version:fix_version, port:port);

      security_report_v4(severity:severity,
                         port:port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);
      return vcf::vcf_exit(0);
    }

  }
}
