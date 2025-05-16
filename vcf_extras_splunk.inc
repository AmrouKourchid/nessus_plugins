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
# vcf_extras_splunk.inc
#
# Revision: 1.3

include('compat_shared.inc');
include('install_func.inc');
include('vcf.inc');

namespace vcf
{
  namespace splunk
  {
    ##
    # Retrive app info for both Splunk and Splunk Universal Forwader
    #
    # Returns both local and remote installs of Splunk and Splunk Universal Forwarder
    # auditing if neither is detected.
    #
    # @remark This function exits.
    ##
    function get_app_info()
    {
      var splunk_search = get_combined_installs(app_name:'Splunk');
      var uf_search = get_combined_installs(app_name:'Splunk Universal Forwarder');

      var installs;
      if (splunk_search[0] == IF_OK)
      {
        if (uf_search[0] == IF_OK)
          installs = make_list(splunk_search[1], uf_search[1]);
        else
          installs = splunk_search[1];
      }
      else
      {
        if (uf_search[0] == IF_OK)
          installs = uf_search[1];
        else
          ::audit(AUDIT_NOT_INST, 'Splunk');
      }
      var install = branch(installs);

      # Duplicate additional metadata added by vcf::get_combined_install
      var win_port, os, parsed_version;
      win_port = get_kb_item("SMB/transport");
      if (!win_port) win_port = 445;

      # local
      if (install.port == 0 || install.port == win_port)
      {
        # set the port if this is Windows
        os = get_kb_item("Host/OS");
        if ("windows" >< tolower(os))
          install.port = win_port;
      }
      else
      {
        # otherwise assume webapp
        install.webapp = TRUE;
      }

      if (install.license == 'Forwarder')
        install.app = 'Splunk Universal Forwarder';
      else
        install.app = 'Splunk';

      if (install.version == UNKNOWN_VER)
      {
        if (install.webapp)
        {
          if (!empty_or_null(install['path']))
            ::audit(AUDIT_UNKNOWN_WEB_APP_VER, install.app, build_url2(qs:install['path'], port:install.port));
          else
            ::audit(AUDIT_UNKNOWN_WEB_SERVER_VER, install.app, install.port);
        }
        else
          ::audit(AUDIT_UNKNOWN_APP_VER, install.app);
      }

      parsed_version = parse_version(install.version);
      if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      install.parsed_version = parsed_version;
      return install;
    }

    ##
    # Calls both check_version() and report_results()
    #
    # Constraints can contain a 'license' property. If multiple licenses are needed
    # for the same range they should be comma separated in a single constraint.
    # If a constraint contains license information but the app_info does not then
    # the check will audit unless the scan is paranoid.
    #
    # @param app_info    array containing application info. requires, at minimum, a
    #                    key/value pair for 'version'
    # @param constraints list of constraint arrays
    # @param severity    severity used in reporting
    # @param strict      bool that determines whether or not version/fix should
    #                    require the same number of fields
    # @param flags       array of reporting flags (xss, sqli, xsrf)
    #
    # @remark This function exits.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var constraint, meets_constraint, fix, report_ver;
      local_var wrong_license, missing_license;
      wrong_license = FALSE;
      missing_license = FALSE;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      foreach constraint (constraints)
      {
        meets_constraint = check_version_against_constraint(version:app_info.parsed_version, constraint:constraint);
        if (is_error(meets_constraint))
          vcf_exit(1, meets_constraint.message);
        if (!meets_constraint)
          continue;
        if (!isnull(constraint['license']))
        {
          if (!isnull(app_info['License']))
          {
            if (app_info['License'] >!< constraint['license'])
            {
              wrong_license = TRUE;
              continue;
            }
          }
          else
          {
            missing_license = TRUE;
            continue;
          }
        }
        fix = constraint.fixed_display;
        if (isnull(fix)) fix = constraint.fixed_version;
        vcf::report_results(app_info:app_info, fix:fix, fix_version:constraint.fixed_version, severity:severity, flags:flags);
        vcf::vcf_exit(0);
      }
      if (wrong_license)
        exit(0, 'The Splunk install uses a ' + app_info['License'] + ' license and is therefore not vulnerable.');
      if (missing_license)
        ::audit(AUDIT_POTENTIAL_VULN, app_info.app);
      # Audit
      vcf::audit(app_info);
    }
  }
}


