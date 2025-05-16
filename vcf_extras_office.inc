###
# (C) Tenable, Inc.
###
include('compat_shared.inc');
include('spad_log_func.inc');
include('debug.inc');
include('vcf.inc');
include('smb_func.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('install_func.inc');

namespace vcf
{
  namespace microsoft
  {
    namespace office
    {
      ##
      # Gather the app's installs info and puts them into an array.
      #
      # @param [app:string] The app name to search for.
      # @param [kbs:list] A list of Microsoft KBs associated with the bulletin.
      # @param [bulletin:string] The vulnerability bulletin to check.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      #
      # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
      ##
      function get_app_info(app, kbs, bulletin, severity)
      {
        var app_info;
        get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

        # C2R only plugins may not have kbs, skip this check if so
        if(!empty_or_null(kbs))
        {
          if(empty_or_null(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
          if(empty_or_null(bulletin))
            return arg_error(arg:'bulletin', func:FUNCTION_NAME);

          if(get_kb_item('Host/patch_management_checks'))
            hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:severity);
        }

        get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

        if(empty_or_null(app))
          return arg_error(arg:'app', func:FUNCTION_NAME);
        app_info = get_single_install(app_name:app, exit_if_unknown_ver:FALSE);

        if(empty_or_null(app_info.port))
          app_info.port = kb_smb_transport();

        return app_info;
      }

      ##
      # Check the version against the constraints and only report versions matching those constraints.
      #
      # @param [app_info:array] The app information to check.
      # @param [constraints:list] The list of array making up the constraints.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      # @param [flags:array] An array of reporting flags to be passed to ``hotfix_security_report()``.
      # @param [bulletin:string] The vulnerability bulletin to check.
      # @param [subproduct:string] The Microsoft Office sub-product name.
      ##
      function check_version_and_report(app_info, constraints, severity, flags, bulletin, subproduct)
      {
        var constraint, check, found_file, fixed_major, fversion_major, path, fversion;
        var vuln = FALSE;
        dbg::detailed_log(
          lvl: 3,
          src: FUNCTION_NAME,
          msg: "Given app_info",
          msg_details: {
            "app_info": {"lvl": 3, "value": obj_rep(app_info)}});
        if(empty_or_null(app_info))
          return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(empty_or_null(constraints))
          return arg_error(arg:'constraints', func:FUNCTION_NAME);
        if(empty_or_null(severity))
          return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(empty_or_null(bulletin))
          return arg_error(arg:'bulletin', func:FUNCTION_NAME);
        if(empty_or_null(subproduct))
          return arg_error(arg:'subproduct', func:FUNCTION_NAME);

        foreach constraint (constraints)
        {
          fversion = NULL;
          path = NULL;
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Parsing constraint",
            msg_details: {
              "constraint": {"lvl": 3, "value": obj_rep(constraint)}});
          if(empty_or_null(constraint.file))
            return arg_error(arg:'constraint.file', func:FUNCTION_NAME);
          if(empty_or_null(constraint.fixed_version))
            return arg_error(arg:'constraint.fixed_version', func:FUNCTION_NAME);

          # Assumes for each app_info there is only 1 file with this name stored (so e.g. graph.exe is present at only 1
          # path for this install)
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Searching for found_file that matches constraint",
            msg_details: {
              "constraint.file": {"lvl": 3, "value": obj_rep(constraint.file)}});
          foreach found_file (app_info.files)
          {
            #spad_log(message:'found_file: ' + obj_rep(found_file));
            if(found_file.path =~ "[\W]" + constraint.file + "$")
            {
              dbg::detailed_log(
                lvl: 3,
                src: FUNCTION_NAME,
                msg: "Setting fversion to version because found_file matches constraint.file.",
                msg_details: {
                  "constraint.file": {"lvl": 3, "value": obj_rep(constraint.file)},
                  "version": {"lvl": 3, "value": obj_rep(found_file.version)},
                  "found_file": {"lvl": 3, "value": obj_rep(found_file)}});
              fversion = found_file.version;
              path = found_file.path;
              break;
            }
          }
          path = path - constraint.file;
          dbg::detailed_log(
            lvl: 2,
            src: FUNCTION_NAME,
            msg: "Found install with path and file version.",
            msg_details: {
              "path": {"lvl": 2, "value": obj_rep(path)},
              "fversion": {"lvl": 2, "value": obj_rep(fversion)}});
          # Check that constraint and file version are the same major version
          fversion_major = split(fversion, sep:'.', keep:FALSE);
          fversion_major = fversion_major[0];
          fixed_major = split(constraint.fixed_version, sep:'.', keep:FALSE);
          fixed_major = fixed_major[0];
          if(fversion_major != fixed_major)
            continue;

          # hotfix_check_fversion() checks
          if(constraint.channel)
          {
            if(hotfix_check_fversion(
                  file:constraint.file,
                  version:constraint.fixed_version,
                  kb:constraint.kb,
                  bulletin:constraint.bulletin,
                  product:constraint.product,
                  channel:constraint.channel,
                  channel_version:constraint.channel_version,
                  channel_product:'Office',
                  fversion_only:TRUE,
                  fversion:fversion,
                  path:path
                  ) == HCF_OLDER)
            {
              vuln = TRUE;
            }
          }
          else
          {
            if(hotfix_check_fversion(
                  file:constraint.file,
                  version:constraint.fixed_version,
                  kb:constraint.kb,
                  bulletin:constraint.bulletin,
                  product:constraint.product,
                  fversion_only:TRUE,
                  fversion:fversion,
                  path:path
                  ) == HCF_OLDER)
            {
              vuln = TRUE;
            }
          }

          # hotfix_check_office_product() checks for C2R only
          if(!empty_or_null(constraint.channel) && constraint.channel != 'MSI')
          {
            check = make_array('16.0', make_nested_list(
                                         make_array('version', constraint.fixed_version,
                                                    'channel', constraint.channel,
                                                    'channel_version', constraint.channel_version)));
            if(hotfix_check_office_product(product:subproduct, checks:check, bulletin:bulletin))
            {
              vuln = TRUE;
            }

          }
        }

        if(vuln)
        {
          store_structured_data(app_info:app_info, bulletin:bulletin, port:app_info.port);
          replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
          hotfix_security_report(severity:severity, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
          hotfix_check_fversion_end();
          exit(0);
        }
        else
        {
          hotfix_check_fversion_end();
          ::audit(AUDIT_HOST_NOT, 'affected');
        }
      }
    }

    namespace office_product
    {
      ##
      # Check the version against the constraints and only report versions matching those constraints.
      #
      # @param [kbs:list] A list of Microsoft KBs associated with the bulletin.
      # @param [constraints:list] The list of array making up the constraints.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      # @param [flags:array] An array of reporting flags to be passed to ``hotfix_security_report()``.
      # @param [bulletin:string] The vulnerability bulletin to check.
      # @param [subproduct:string] The Microsoft Office sub-product name.
      ##
      function check_version_and_report(kbs, constraints, severity, flags, bulletin, subproduct)
      {
        var constraint, check, fixed_major, check_ver;
        var vuln = FALSE;
        var fversion = NULL;

        if(empty_or_null(constraints))
          return arg_error(arg:'constraints', func:FUNCTION_NAME);
        if(empty_or_null(severity))
          return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(empty_or_null(bulletin))
          return arg_error(arg:'bulletin', func:FUNCTION_NAME);
        if(empty_or_null(subproduct))
          return arg_error(arg:'subproduct', func:FUNCTION_NAME);

        # kb checks to run before checking constraints
        get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

        if(get_kb_item('Host/patch_management_checks'))
          hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:severity);

        get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

        # check constraints
        foreach constraint (constraints)
        {
          var fixed_ver_parts;

          if(empty_or_null(constraint.fixed_version))
            return arg_error(arg:'constraint.fixed_version', func:FUNCTION_NAME);

          fixed_ver_parts = split(constraint.fixed_version, sep:'.', keep:FALSE);
          check_ver = fixed_ver_parts[0] + '.' + fixed_ver_parts[1];

          check = make_array(check_ver, make_nested_list(
                                          make_array('version', constraint.fixed_version,
                                                     'channel', constraint.channel,
                                                     'channel_version', constraint.channel_version,
                                                     'sp', constraint.sp, 'kb', constraint.kb)));
          if(hotfix_check_office_product(product:subproduct, checks:check, bulletin:bulletin))
          {
            vuln = TRUE;
          }
        }

        if(vuln)
        {
          var port = kb_smb_transport();
          var app_info = get_single_install(app_name:"Microsoft " + subproduct, exit_if_unknown_ver:FALSE);
          store_structured_data(app_info:app_info, bulletin:bulletin, port:port);
          replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
          hotfix_security_report(severity:severity, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
          hotfix_check_fversion_end();
          exit(0);
        }
        else
        {
          hotfix_check_fversion_end();
          ::audit(AUDIT_HOST_NOT, 'affected');
        }
      }
    }
    namespace office_for_mac
    {
      ##
      # Collect installs for a list of apps.
      #
      # @param [apps:list] a list of apps to check, e.g. make_list('Microsoft Excel', 'Microsoft Word')
      #
      # @return [array] An array with keys set to product name and values a list returned by ``get_installs()``.
      ##
      function get_app_info(apps)
      {
        var app_info;

        get_kb_item_or_exit('Host/MacOSX/Version');
        if(empty_or_null(apps)) return vcf::arg_error(arg:'apps', func:FUNCTION_NAME);

        foreach var app (apps)
        {
          var installs = get_installs(app_name:app);
          if(empty_or_null(installs[1]))
            continue;

          var product_name = app + ' for Mac';
          app_info[product_name] = installs[1];
        }

        if(empty_or_null(app_info))
          return ::audit(AUDIT_HOST_NOT, 'affected');

        return app_info;
      }

      ##
      # Calls vcf::check_version() and reports on the results.
      #
      # @param [app_info:array] array containing application info, as defined above.
      # @param [constraints:list] list of constraint arrays, identical to normal vcf constraints.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      # @param [flags:array] array of reporting flags (xss, sqli, xsrf).
      # @param [os_min_lvl:string] the minimum macOS level required for the patch.
      #
      # @remark
      # This function exits.
      ##
      function check_version_and_report(app_info, constraints, severity, flags, os_min_lvl)
      {
        var report, matching_constraint, fix, version, parsed_version, app, os, os_ver, install;
        if(isnull(app_info)) return vcf::arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity)) return vcf::arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints)) return vcf::arg_error(arg:'constraints', func:FUNCTION_NAME);


        foreach app (keys(app_info))
        {
          foreach install(app_info[app])
          {
            version = install['version'];
            parsed_version = vcf::parse_version(version);
            matching_constraint = vcf::check_version(version:parsed_version, constraints:constraints, strict:FALSE);
            if(is_error(matching_constraint))
            {
              dbg::detailed_log(
                lvl: 1,
                src: FUNCTION_NAME,
                msg: "Matching constraint error",
                msg_details: {
                  "Error": {"lvl": 1, "value": obj_rep(matching_constraint.message)}});
              continue;
            }

            if(!empty_or_null(matching_constraint))
            {
              fix = matching_constraint.fixed_display;
              if(empty_or_null(fix))
                fix = matching_constraint.fixed_version;
              report +=
                '\n\n  Product           : ' + app +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : ' + fix;

            }
          }
        }

        if(empty_or_null(report))
          return ::audit(AUDIT_HOST_NOT, 'affected');

        os = get_kb_item_or_exit('Host/MacOSX/Version');
        os_ver = pregmatch(string:os, pattern:"^Mac OS X ([0-9.]+)");
        if(!empty_or_null(os_ver) && !empty_or_null(os_min_lvl))
        {
          if(ver_compare(ver:os_ver[1], fix:os_min_lvl, strict:FALSE) < 0)
            report += '\n  Note              : Update will require macOS ' + os_min_lvl + ' or later.\n';
        }

        store_structured_data(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, port:0);
        security_report_v4(
          severity:severity,
          port:0,
          extra:report,
          xss:flags.xss,
          xsrf:flags.xsrf,
          sqli:flags.sqli
        );
        return vcf::vcf_exit(0);
      }
    }
  }
}
