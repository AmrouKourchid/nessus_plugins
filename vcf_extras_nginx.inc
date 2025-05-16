###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_nginx.inc
#
# Revision: 1.1
###
include('compat_shared.inc');
include('lists.inc');
include('vcf.inc');
include('install_func.inc');

namespace vcf
{
  # Nginx Plus uses a different version format to Open Source Nginx
  # Nginx Plus e.g R25 P1, recorded in detection as r25-p1
  #   - R stands for 'Revision'
  #   - P stands for 'Patch'
  # Each Nginx Plus release is based on an Open Source version
  #   - e.g, R25 is based on Open Souce verion 1.21.3
  # Nginx Plus essentially backkports patches to its own release
  #   - R25 becomes R25-P1
  #   - Base version 1.21.3 stays the same however
  #
  # This namespace will deal with these discrepencies for Nginx Plus
  # If there are no patches install, use the base Open Source Version
  # If there are patches installed, used newly created Nginx Plus "dot" version
  #   e.g r25-p1 == 25.1
  #   e.g r25 == 25.0 == 1.21.3

  namespace nginx_plus
  {
    ##
    # Mostly the same as standarf vcf function, with extra for Nginx Plus
    #
    # @param [app:string] The app's name for which to gather information.
    #
    # @return [array] The consolidated app info array.
    ##
    function combined_get_app_info(app)
    {
      local_var install, win_port, os, parsed_version, base_ver_regex, base_ver_match,
      nginx_plus_parsed_version, ver, release, patch;

      if (isnull(app)) return arg_error(arg:"app", func:FUNCTION_NAME);

      install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE, combined:TRUE);

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

      # deal with Nginx Plus here
      if (install['Nginx Plus'] == 'True')
      {
        # get Nginx version (like r25-p1)
        install.nginx_plus_version = install.version;

        # get base Nginx version (like 1.21.3)
        base_ver_regex = "^(\d+\.)?(\d+\.)?(\*|\d+)";
        base_ver_match = pregmatch(string:install['Full Version'], pattern:base_ver_regex);
        if (!empty_or_null(base_ver_match) && base_ver_match[0])
          install.nginx_base_version = base_ver_match[0];

        # get Release version and patch level
        # e.g r25-p1, is Release 25, Patch 1
        nginx_plus_parsed_version = parse_version(install.version);
        ver = nginx_plus_parsed_version;
        ver = ver[0];
        release = ver[1];
        patch = ver[3];
        if (!patch)
          patch = '0';
        # change r25-p1 to a valid version string, 25.1
        install.nginx_dot_version = release + '.' + patch;
        install.version = install.nginx_dot_version;
        install.patches = TRUE;
      }

      parsed_version = parse_version(install.version);

      if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      install.parsed_version = parsed_version;

      install.app = app;
      return install;
    }

    ##
    # unchanged, but we need it here because we need to make a minor change to report_results()
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # This function calls `report_results()`` directly
    # if the install is found vulnerable, or audits out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if (!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if (isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::nginx_plus::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Call security_report_v4() with given severity and flags
    #
    # @param [app_info:array]     app info to use in report
    # @param [fix:string]         the fixed version to include in report
    # @param [fix_version:string] the fixed version to include in structured report
    # @param [severity:int]       SECURITY_(NOTE|HOLE|WARNING)
    # @param [flags:int]          xss, xsrf, and sqli
    # @param [webapp:boolean]     converts path to a URL
    #
    # @remark
    #   minor change to make sure we still report the 'R' version for Nginx Plus
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      local_var report, version, port;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      # Nginx Plus
      if (app_info['Nginx Plus'] == 'True')
        version = app_info['Full Version'];

      report = build_report(version:version,
                            fix:fix,
                            path:app_info.path,
                            source:app_info.source,
                            webapp:app_info.webapp,
                            port:app_info.port);

      if (is_error(report)) return vcf_exit(1, report.message);

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
      return vcf_exit(0);
    }

    ##
    # Generates an audit tailored to specific Nginx cases.
    ##
    function audit()
    {
      local_var app_info = _FCT_ANON_ARGS[0];
      local_var display_version;

      if (TAP) return vcf_exit(0);

      if (max_index(_FCT_ANON_ARGS) > 1 && (_FCT_ANON_ARGS[1] == AUDIT_MANAGED_INSTALL || _FCT_ANON_ARGS[1] == AUDIT_BACKPORT_SERVICE))
      {
        if (app_info.Managed == 1 || app_info['Managed by OS'])
        {
          ::audit(AUDIT_MANAGED_INSTALL, app_info.app);
        }
        else if (app_info.backported == 1)
        {
          ::audit(AUDIT_BACKPORT_SERVICE, app_info.port, app_info.app);
        }
      }

      if (app_info.app && app_info.version)
      {
        if (!empty_or_null(app_info.display_version))
          display_version = app_info.display_version;
        else
          display_version = app_info.version;

        # Nginx Plus
        if (app_info['Nginx Plus'] == 'True')
        {
          display_version = app_info['Full Version'];
        }

        if (app_info.webapp)
        {
          ::audit(AUDIT_WEB_APP_NOT_AFFECTED, app_info.app, build_url2(qs:app_info.path, port:app_info.port), display_version);
        }
        else if (app_info.service)
        {
          if (!isnull(app_info.proto)) ::audit(AUDIT_LISTEN_NOT_VULN, app_info.app, app_info.port, display_version, app_info.proto);
          else ::audit(AUDIT_LISTEN_NOT_VULN, app_info.app, app_info.port, display_version);
        }
        else if (!empty_or_null(app_info.path))
        {
          ::audit(AUDIT_INST_PATH_NOT_VULN, app_info.app, display_version, app_info.path);
        }
        else ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app, display_version);
      }
      else ::audit(AUDIT_HOST_NOT, "affected");
    }
  }
}
