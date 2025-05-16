###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_qnap.inc
#
# Revision: 1.10
###
include('compat_shared.inc');
include('vcf.inc');
include('spad_log_func.inc');
include('debug.inc');
include('install_func.inc');

namespace vcf
{
  namespace qnap
  {
    ##
    # Builds app_info for QNAP QTS/QES/QuTS hero
    #
    # @return [array] an array containing application info
    ##
    function get_app_info(exit_if_unknown_ver)
    {
      var products = make_list('QTS', 'QuTS hero', 'QES');
      var install, app_info;

      if (empty_or_null(exit_if_unknown_ver))
        exit_if_unknown_ver = TRUE;

      # Need to use a C-style for loop due to Bad enumerator bug
      var i;
      for (i=0; i < len(products); i++)
      {
        install = get_combined_installs(app_name:'QNAP ' + products[i]);
        if (install[0] == IF_OK)
        {
          app_info = get_single_install(app_name:'QNAP ' + products[i], combined:TRUE, webapp:TRUE);
          dbg::detailed_log(
            lvl: 2,
            src: FUNCTION_NAME,
            msg: "Initial app_info",
            msg_details: {
              "app_info": {"lvl": 2, "value": obj_rep(app_info)}});
          app_info['product'] = products[i];
          break;
        }
      }
      if(install[0] != IF_OK) ::audit(AUDIT_NOT_INST, 'QNAP QTS/QES/QuTS hero');

      # set the port for the vuln plugins to retrieve
      if (!empty_or_null(install['port']))
        app_info['port'] = install['port'];

      # Set display_version to product + version.number + build <build>
      app_info['display_version'] = app_info['product'] + ' ' + app_info['version'];

      if (!empty_or_null(app_info['Number']))
        app_info['display_version'] += '.' + app_info['Number'];
      if (!empty_or_null(app_info['Build']))
        app_info['display_version'] += ' build ' + app_info['Build'];

      # Make sure Number and Build are always set, to 0 by default
      if (empty_or_null(app_info['Number']))
        app_info['Number'] = 0;
      if (empty_or_null(app_info['Build']))
        app_info['Build'] = 0;

      # hero versions are prefixed w/ a 'h'.
      if ('h' >< tolower(app_info['version']))
        app_info['version'] = ereg_replace(string:app_info['version'], pattern:"^h", replace:"");

      if (exit_if_unknown_ver && (app_info['version'] == UNKNOWN_VER || empty_or_null(app_info['version'])))
        ::audit(AUDIT_UNKNOWN_APP_VER, 'QNAP');

      if (!empty_or_null(app_info['version']) && app_info['version'] != UNKNOWN_VER)
        app_info['parsed_version'] = vcf::parse_version(app_info['version']);

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::report_results()``.
    # @param [strict:boolean] Flag to set version comparision in strict mode (optional, defaults to FALSE).
    #
    # @remark If no constraint matches the install version this function audits out,
    # otherwise it reports the vulnerability and exits.
    ##
    function check_version_and_report(app_info, constraints, severity, flags, strict)
    {
      if (isnull(app_info))
        return arg_error(arg:'app_info', func:FUNCTION_NAME);
      if (isnull(severity))
        return arg_error(arg:'severity', func:FUNCTION_NAME);
      if (isnull(constraints))
        return arg_error(arg:'constraints', func:FUNCTION_NAME);
      if (isnull(strict)) strict = FALSE;

      foreach var constraint (constraints)
      {
        if (app_info['product'] != constraint['product'])
          continue;

        var matching_constraint = vcf::check_version_against_constraint(version:app_info['parsed_version'], constraint:constraint, strict:FALSE);
        if (is_error(matching_constraint))
          return vcf_exit(1, matching_constraint.message);

        if (matching_constraint)
        {
          # If version == max version, check Build and Number - if both Build and Number are patched, don't flag
          if (!empty_or_null(constraint.max_version) && ver_compare(ver:app_info.version, fix:constraint.max_version, strict:FALSE) == 0)
          {
            var vuln = FALSE;
            # If constraint specifies a Build, ver_compare it against detected Build
            if (!empty_or_null(constraint['Build']) && ver_compare(ver:app_info['Build'], fix:constraint['Build'], strict:FALSE) < 0)
              vuln = TRUE;

            # If constraint specifies a Number, ver_compare it against detected Number
            if (!empty_or_null(constraint['Number']) && ver_compare(ver:app_info['Number'], fix:constraint['Number'], strict:FALSE) < 0)
              vuln = TRUE;

            if (!vuln)
              continue;
          }

          var fix = constraint.fixed_display;
          if (isnull(fix)) fix = constraint.fixed_version;
          vcf::report_results(app_info:app_info, fix:fix, fix_version:constraint.fixed_version, severity:severity, flags:flags);
        }
      }
      return vcf::audit(app_info);
    }
  }

  namespace qnap_module
  {
    ##
    # Builds app_info for QNAP module checks
    #
    # @param [app:string] The app name to look for.
    # @param [module:string] The module name to look for in the install's app info (as an array key).
    #
    # @return [array] An array containing application info.
    #
    # @remark The function audits out if the module's version is unknown.
    ##
    function get_app_info(app, module)
    {

      var app_info = vcf::get_app_info(app:app);

      if (empty_or_null(app_info[module]))
      {
        ::audit(AUDIT_NOT_INST, module);
      }
      if (app_info[module] == UNKNOWN_VER)
      {
        ::audit(AUDIT_UNKNOWN_APP_VER, module);
      }

      app_info['app'] = module;
      app_info['version'] = app_info[module];
      app_info['parsed_version'] = vcf::parse_version(app_info['version']);

      return app_info;
    }
  }
}
