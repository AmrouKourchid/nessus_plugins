###
# (C) Tenable, Inc.
###

include('compat_shared.inc');
include('install_func.inc');
include('openssl_version.inc');
include('vcf.inc');

namespace vcf
{
  namespace openssl
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If the installation doesn't match, the function audits out.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      if(empty_or_null(app_info))
          return arg_error(arg:'app_info', func:FUNCTION_NAME);
      if(empty_or_null(severity))
          return arg_error(arg:'severity', func:FUNCTION_NAME);
      if(empty_or_null(constraints))
          return arg_error(arg:'constraints', func:FUNCTION_NAME);
      # It's been observed that the openssl pkgd w/ Nessus Agents sometimes don't report file ownership.
      # This is a contingency in the event the openssl pkgd w/ Tenable products do not report file ownership.
      if((empty_or_null(app_info.Managed) || !app_info.Managed) &&
          (('nessus' >< tolower(app_info.path) ||
            '/opt/sc/' >< tolower(app_info.path) ||
            '/opt/nnm/' >< tolower(app_info.path))))
      {
        if(report_paranoia < 2)
          ::audit(AUDIT_MANAGED_INSTALL, app_info.app);
      }

      var fix, report, constraint;
      var vuln = FALSE;

      if(empty_or_null(app_info.port)) app_info.port = 0;

      # added loop to support multiple constraints
      foreach constraint (constraints)
      {
        if(empty_or_null(constraint.min_version) || empty_or_null(constraint.fixed_version))
        {
          return arg_error(arg:'app_info', func:FUNCTION_NAME);
        }

        if(!empty_or_null(constraint.min_version) &&
            openssl_ver_cmp(ver:app_info.version,
                            fix:constraint.min_version,
                            same_branch:FALSE,
                            is_min_check:TRUE) >= 0 &&
           !empty_or_null(constraint.fixed_version) &&
            openssl_ver_cmp(ver:app_info.version,
                            fix:constraint.fixed_version,
                            same_branch:FALSE,
                            is_min_check:FALSE) < 0)
        {
          vuln = TRUE;
          fix = constraint.display_version;
          if(empty_or_null(fix)) fix = constraint.fixed_version;

          if(!empty_or_null(app_info.pristine_banner))
          {
            report +=
            '\n  Banner           : ' + app_info.pristine_banner;
          }
          if(!empty_or_null(app_info.path))
          {
            report +=
            '\n  Path             : ' + app_info.path;
          }
          report +=
            '\n  Reported version : ' + app_info.version +
            '\n  Fixed version    : ' + fix;
          if(app_info.backported) report +=
              '\n\nBased on the banner, security patches may have been backported to' +
              '\nthis install of OpenSSL. A local check is needed to confirm the' +
              '\npresence of this vulnerability.';
        }
      }

      if(!vuln)
        vcf::audit(app_info);

      store_structured_data(app_info:app_info, fix:fix, fix_version:constraint.fixed_version, port:app_info.port);

      security_report_v4(severity:severity,
                         port:app_info.port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);
      exit(0);
    }
  }
}
