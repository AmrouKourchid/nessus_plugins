###
# Microsoft version checks
###
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('install_func.inc');
include('compat_shared.inc');
include('smb_reg_query.inc');
include('vcf.inc');
include("debug.inc");
include('lists.inc');

namespace vcf
{
  namespace microsoft
  {
    namespace azure_devops_server
    {
      ##
      # Returns information related to an installed Microsoft Team Foundation Server
      #
      # @return [array] Microsoft Team Foundation Server install particulars
      ##
      function get_app_info()
      {
        var app_info = {};
        var install = get_single_install(app_name:'Microsoft Team Foundation Server');
        app_info.path = install['path'];
        app_info.release = install['Release'];
        app_info.update = install['Update'];
        app_info.version = install['version'];

        app_info.product = install['vendor'] + ' ' + install['product'] + ' ' + app_info.release;
        if(app_info.update != '0')
          app_info.product = app_info.product + ' ' + 'Update ' + app_info.update;

        app_info.files = [];

        var i = 0;
        while (!isnull(install.files[i]))
        {
          var file_path = install.files[i].path;
          var file_version = install.files[i].version;
          app_info.files[file_path] = file_version;
          i++;
        }

        return app_info;
      }

      ##
      # Checks version of Microsoft Team Foundation Server against a MS security advisory.
      #
      # @param [app_info:array] Details of the Microsoft Team Foundation Server installed on the target
      # @param [bulletin:string] The bulletin that is being checked
      # @param [constraints:list] Version constraints that define vulnerable versions.
      # @param [severity:int] It is a security hole, warning or note?
      # @param [flags:array] Flags for identifying certain classes of vulnerabilities (XSS, XSRF, SQLi)
      ##
      function check_version_and_report(app_info, bulletin, constraints, severity, flags)
      {
        # Those without update mappings
        if(empty_or_null(app_info.update) || empty_or_null(app_info.release))
          ::audit(AUDIT_HOST_NOT, 'affected');

        foreach var check (constraints)
        {
          var vuln = FALSE;
          var fix;

          # skip this check if the release doesn't match
          if(app_info.release != check.release)
            continue;

          # skip this check if the update version isn't at least minimum or is higher than the max
          var update_compare = ver_compare(ver:app_info.update,
                                           fix:check.update_max_ver,
                                           minver:check.update_min_ver,
                                           strict:FALSE);
          if(isnull(update_compare) || update_compare > 0)
            continue;

          # only do file check if we have a file constraint
          if(!isnull(check.file))
          {
            var path = hotfix_append_path(path:app_info.path, value:check.append_path);

            var file_path = hotfix_append_path(path:path, value:check.file);
            var file_version = app_info.files[file_path];
            if(empty_or_null(file_version))
            {
              dbg::detailed_log(
                lvl: 2,
                src: FUNCTION_NAME,
                msg:'Error: Tried to obtain the file version of a file that was not collected by our ADO detection!',
                msg_details: {
                  "check.append_path": {"lvl": 2, "value": check.append_path},
                  "check.file": {"lvl": 2, "value": check.file}});
              file_version = UNKNOWN_VER;
            }

            # we can only compare known versions and should only flag vuln when version < fix
            if(file_version != UNKNOWN_VER &&
               ver_compare(ver:file_version, fix:check.file_fix_ver, minver:check.file_min_ver, strict:FALSE) < 0)
            {
              fix = "file";
              vuln = TRUE;
              var report =
                '\n' + app_info.product + '\n' +
                '  - ' + file_path + ' has not been patched.\n' +
                '    Remote version : ' + file_version + '\n' +
                '    Should be      : ' + check.file_fix_ver + '\n';
              hotfix_add_report(report, bulletin:bulletin);
              hotfix_add_report(check.note, bulletin:bulletin);
            }
          }

          # add a manual patch note if the report_paranoia paranoid, we have a manual note, and the version is unknown
          if(report_paranoia > 1 && !isnull(check.manual_note) && file_version == UNKNOWN_VER)
          {
            vuln = TRUE;
            hotfix_add_report(check.manual_note, bulletin:bulletin);
          }

          # finally, report the vuln
          if(vuln == TRUE)
          {
            var port = kb_smb_transport();
            store_structured_data(app_info:app_info, bulletin:bulletin, port:port);
            replace_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
            hotfix_security_report(severity:severity, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
            exit(0);
          }
        }
        # we didn't find any vuln installs
        ::audit(AUDIT_HOST_NOT, 'affected');
      }
    }

    namespace sharepoint
    {
      ##
      # Returns information related to an installed Microsoft SharePoint Server
      #
      # @return [array] Microsoft SharePoint Server install particulars
      ##
      function get_app_info()
      {
        var app_info = {};
        var install = get_single_install(app_name:'Microsoft SharePoint Server');
        app_info.product = install['Product'];
        app_info.sp = install['SP'];
        app_info.edition = install['Edition'];
        app_info.path = install['path'];
        app_info.hotfix_path = hotfix_get_commonfilesdir();
        return app_info;
      }

      ##
      # Checks version of Microsoft SharePoint Server against a MS security advisory.
      #
      # @param [app_info:array] Details of the Microsoft SharePoint Server installed on the target
      # @param [bulletin:string] The bulletin that is being checked
      # @param [constraints:list] Version constraints that define vulnerable versions.
      # @param [severity:int] It is a security hole, warning or note?
      ##
      function check_version_and_report(app_info, bulletin, constraints, severity)
      {
        var are_we_vuln, kb, vuln, report, kb_location;
        var found, cu_non_paranoid = FALSE;
        get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

        if(get_kb_item('Host/patch_management_checks'))
        {
          dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Patch Management System detected');
          var kbs = [];
          foreach kb (constraints)
          {
            append_element(var:kbs, value:kb['kb']);
          }
          hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:severity);
        }

        get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);
        dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'SMB Enumerated.');
        var right_product = FALSE;
        var check;
        foreach check (constraints)
        {
          if(app_info.product == check['product'] &&
             app_info.edition == check['edition'] &&
             (empty_or_null(check['sp']) || check['sp'] == app_info.sp))
            right_product = TRUE;
        }

        if(right_product != TRUE)
          ::audit(AUDIT_HOST_NOT, 'affected: Server is Sharepoint' + app_info.product + ' ' + app_info.edition);

        # Attempt to pull the versions and checks for the files in question.

        # If it fails, or language files, we fall back on the older method used for uncertain directories.
        var kb_found = FALSE;
        var kb_file_version;

        dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Starting DB constraint check.');
        foreach check (constraints)
        {
          dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Checking for product and edition.');
          if(app_info.product != check['product'] || app_info.edition != check['edition'])
            continue;
          dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Checking for version.');
          if(!isnull(check['version']))
          {
            dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Identifying iflanguage check.');
            if(empty_or_null(check['language']))
            {
              kb_location = str_replace(string: "SMB/FileVersions/" +
                                                tolower(check['path'] +
                                                        check['append'] + "/" +
                                                        check['file']),
                                        find:"\", replace:"/");
              kb_location = str_replace(string: kb_location, find:":", replace:"");
              kb_file_version = get_kb_item(kb_location);
              dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:kb_location +"="+ kb_file_version);
              if(empty_or_null(kb_file_version)) continue;
              dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Kb found as ' + kb_file_version);
              kb_found = TRUE;
              if(kb_file_version == UNKNOWN_VER ||
                 ver_compare(ver:kb_file_version, fix:check['version'], strict:FALSE) < 0)
              {
                vuln = TRUE;
                report = '  Product : ' + check['product_name'] + '\n';
                report = '  Version : ' + kb_file_version + '\n';
                if(check['kb'])  report += '  KB : ' + check['kb'] + '\n';
                hotfix_add_report(report, kb:check['kb']);
              }
            }
          }
        }

        if(!kb_found)
        {
          dbg::detailed_log(lvl: 2,
                            src: FUNCTION_NAME,
                            msg:'Starting backup detections. If this is new code and you are seeing this, ' +
                                'you need to add file to detected files list.');
          var windir = hotfix_get_systemroot();
          if(isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');
          registry_init();
          var port = kb_smb_transport();
          # grab the path otherwise

          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Found ' + path +
                                                          ' version ' + check['version'] +
                                                          ' to return hotfix code ' + are_we_vuln);
          dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'checking constraints');

          foreach check (constraints)
          {
            if(app_info.product != check['product'] || app_info.edition != check['edition'])
              continue;
            if(!isnull(check['version']))
            {
              if(empty_or_null(check['language']))
              {
                var path = check['path'];
                if(!empty_or_null(check['append']))
                  path = hotfix_append_path(path:check['path'], value:check['append']);
                dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'checking ' + path +
                                                                  ' for version ' + check['version'] +
                                                                  ' for kb:' + check['kb']);
                are_we_vuln = hotfix_check_fversion(
                  file:check['file'],
                  version:check['version'],
                  path:path,
                  kb:check['kb'],
                  product:check['product_name']
                );
              }
              else
              {
                var path_list = hotfix_append_path(path:check['path'], value:check['append']);
                path_list = language_pack_iterate(language_lists:check['language'], file_directory:path_list);
                are_we_vuln = hotfix_check_fversion_multipath(
                  file_name:check['file'],
                  version:check['version'],
                  path_list:path_list,
                  kb:check['kb'],
                  product:check['product_name']
                );
              }
              if(are_we_vuln)
                dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Found ' + path +
                                                                  ' version ' + check['version'] +
                                                                  ' to return hotfix code ' + are_we_vuln);
            }
            else
            {
              report = '\n';
              if(check['product_name'])
                report += '  Product : ' + check['product_name'] + '\n';
              if(check['kb'])
                report += '  KB : ' + check['kb'] + '\n';
              hotfix_add_report(report, kb:check['kb']);
            }

            if(are_we_vuln == HCF_OLDER) vuln = TRUE;
            if(vuln) dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg:'Are_We_Vuln Triggered');
          }
        }
        if(vuln)
        {
          port = kb_smb_transport();
          store_structured_data(app_info:app_info, bulletin:bulletin, port:port);
          replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
          hotfix_security_report(severity:severity);
          exit(0);
        }
        else
        {
          hotfix_check_fversion_end();
          ::audit(AUDIT_INST_VER_NOT_VULN, app_info.product + ' ' + app_info.edition);
        }
      }
    }

    namespace exchange
    {
      ##
      # Returns information related to an installed Microsoft Exchange Server
      #
      # @return [array] Microsoft Exchange Server install particulars
      ##
      function get_app_info()
      {
        var install = get_single_install(app_name:'Microsoft Exchange');
        install.port = kb_smb_transport();
        return install;
      }

      ##
      # Maps an Exchange product name to a release version
      #
      # @param [product:string] Product name
      # @return [string] Release version.
      ##
      function map_product_to_release(product)
      {
        local_var release_mapping = {
          '2010': '140',
          '2013': '150',
          '2016': '151',
          '2019': '152'
        };
        local_var result = release_mapping[product];
        if(empty_or_null(result))
          result = UNKNOWN_VER;
        return result;
      }

      ##
      # Gets the version of 'exsetup.exe' from a list of file information.
      #
      # @param [files:list] Arrays of information on discovered files
      # @return [string|NULL] The version of 'exsetup.exe' if it was found.
      ##
      function get_ex_setup_version(files)
      {
        foreach var file (files)
        {
          if('exsetup.exe' >< tolower(file['path']))
            return file['version'];
        }
        return NULL;
      }

      ##
      # Checks version of Microsoft Exchange Server against a MS security advisory.
      #
      # @param [app_info:array] Details of the Microsoft Exchange Server installed on the target
      # @param [bulletin:string] The bulletin that is being checked
      # @param [constraints:list] Version constraints that define vulnerable versions.
      # @param [severity:int] It is a security hole, warning or note?
      # @param [strict:boolean] Perform strict version checking?
      # @param [flags:array] Flags for identifying certain classes of vulnerabilities (XSS, XSRF, SQLi)
      # @param [cves:list] CVEs addressed in the indicated advisory bulletin for the detected product.
      ##
      function check_version_and_report(app_info, bulletin, constraints, severity, strict, flags, cves)
      {
        get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

        exit_if_productname_not_server();
        var release, cu;
        var found, cu_non_paranoid = FALSE;
        var cpe;

        if(get_kb_item('Host/patch_management_checks'))
        {
          var kbs = [];
          foreach item (constraints)
          {
            if(!empty_or_null(item['kb']))
              append_element(var:kbs, value:item['kb']);
          }
          hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:severity);
        }

        foreach var item (constraints)
        {
          item['release'] = map_product_to_release(product:item['product']);

          if(item['release'] == app_info['RELEASE'])
          {
            if(!empty_or_null(item['sp']) && item['sp'] != app_info['sp'])
              continue;

            if(!empty_or_null(item['unsupported_cu']) && item['unsupported_cu'] >= app_info['CU'])
            {
              if(report_paranoia != 2)
              {
                ::audit(AUDIT_HOST_NOT, 'affected: However the Cumulative update version installed reports as no longer supported.  Run a Paranoid Scan ifyou think this is a issue.');
              }
              hotfix_add_report('The Microsoft Exchange Server installed at ' + app_info.path +
              ' has an unsupported Cumulative Update (CU) installed and may be ' +
              'vulnerable to the CVEs contained within the advisory. Unsupported ' +
              'Exchange CU versions are not typically included in Microsoft ' +
              'advisories and are not indicated as affected.\n',
              bulletin:bulletin, kb:item['kb']);
              found = TRUE;
              break;
            }

            if(!empty_or_null(item['cu']) && item['cu'] != app_info['CU'])
              continue;

            var file_ver = app_info.version;

            var file_ver_display = file_ver;
            if(!empty_or_null(file_ver))
            {
              file_ver = vcf::parse_version(file_ver);
              found = check_version_against_constraint(version:file_ver, constraint:item, strict:strict);
            }

            if(found)
            {
              var report_items;
              var order = ['Path', 'Installed version', 'Fixed version'];
              if(!empty_or_null(item.fixed_display))
              {
                report_items = make_array(
                  order[0], app_info.path,
                  order[1], file_ver_display,
                  order[2], item.fixed_display
                );
              }
              else
              {
                report_items = make_array(
                  order[0], app_info.path,
                  order[1], file_ver_display,
                  order[2], item.fixed_version
                );
              }
              hotfix_add_report(
                report_items_str(report_items:report_items, ordered_fields:order),
                bulletin:bulletin,
                kb:item['kb']
              );
              if(!empty_or_null(item['cves'])){
                cpe = construct_cpe(cpe_ver:"23",
                                    part:"a",
                                    vendor:"microsoft",
                                    product:"exchange_server",
                                    version:item['product'],
                                    update:"cumulative_update_" + item['cu']);
                if(cpe[0] != IF_OK)
                  continue;

                cpe = cpe[1];
              }
              break;
            }
          }
        }

        if(!found)
          ::audit(AUDIT_HOST_NOT, 'affected');

        var port = kb_smb_transport();
        store_structured_data(app_info:app_info, bulletin:bulletin, port:port);
        set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
        hotfix_security_report(severity:severity, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
      }
    }

    namespace mssql
    {
      ##
      # Returns information related to an installed Microsoft SQL Server
      #
      # @return [array] Microsoft SQL Server install particulars
      ##
      function get_app_info()
      {
        var app_info = get_single_install(app_name:'Microsoft SQL Server');
        return app_info;
      }

      ##
      # Checks version of Microsoft SQL Server against a MS security advisory.
      #
      # @param [app_info:array] Details of the Microsoft SQL Server installed on the target
      # @param [bulletin:string] The bulletin that is being checked
      # @param [constraints:list] Version constraints that define vulnerable versions.
      # @param [severity:int] It is a security hole, warning or note?
      # @param [flags:array] Flags for identifying certain classes of vulnerabilities (XSS, XSRF, SQLi)
      ##
      function check_version_and_report(app_info, bulletin, constraints, severity, flags)
      {
        get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

        if(get_kb_item('Host/patch_management_checks'))
        {
          var kbs = [];
          foreach var item (constraints)
          {
            if(!empty_or_null(item['kb']))
              append_element(var:kbs, value:item['kb']);
          }

          hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:severity);
        }

        get_kb_item_or_exit('SMB/Registry/Enumerated');
        get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

        var constraint, found_vuln;
        foreach constraint (constraints)
        {
          if(empty_or_null(app_info.is_accessible_share) || app_info.is_accessible_share == 0) continue;
          if(report_paranoia < 2 && app_info.localdb)
          {
            dbg::detailed_log(lvl: 2, src:FUNCTION_NAME, msg:'Skipping ' + app_info.instance_name + ' because it is a LOCALDB.');
            continue;
          }

          if(empty_or_null(constraint.target_hw)) constraint.target_hw = 'x64, x86';
          if(empty_or_null(app_info.target_hw))
            ::audit(AUDIT_HOST_NOT, 'affected, system architecture kb is not found');

          if( app_info.product_version == constraint.product_version && app_info.target_hw >< constraint.target_hw )
          {
            var found_file, f, f_version, f_path;
            foreach found_file(keys(app_info.files))
            {
              # Verify the appropriate file version is being used for the correct instance
              if((!empty_or_null(found_file)) && ((app_info.path + '\\' + constraint.file) == app_info.files[found_file]['path']))
              {
                f_path =  app_info.files[found_file]['path'];
                f_version = app_info.files[found_file]['version'];
              }
              if(empty_or_null(constraint.file))
                ::audit(AUDIT_HOST_NOT, 'affected, no available file(s) to check');

              if(constraint.file >< f_path)
              {
                app_info.version = f_version;
                app_info.parsed_version = vcf::parse_version(f_version);

                if(hotfix_is_vulnerable(path          : app_info['path'],
                                         file          : constraint['file'],
                                         fversion      : app_info['version'],
                                         version       : constraint['fixed_version'],
                                         min_version   : constraint['min_version'],
                                         fversion_only : TRUE,
                                         kb            : constraint['kb']))
                {
                  found_vuln = TRUE;
                  break;
                }
              }
            }
          }
        }
        hotfix_check_fversion_end();

        if(found_vuln)
        {
          var port = kb_smb_transport();
          store_structured_data(app_info:app_info, bulletin:bulletin, port:port);
          hotfix_security_report(severity:severity, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
          exit(0);
        }
        ::audit(AUDIT_HOST_NOT, 'affected');
      }
    }

    namespace endpoint_cm
    {
      ##
      # Returns information related to an installed Microsoft Endpoint Configuration Manager
      #
      # @return [array] Microsoft Endpoint Configuration Manager install particulars
      ##
      function get_app_info()
      {
        var app_info = vcf::get_app_info(app:'Microsoft Endpoint Configuration Manager', win_local:TRUE);
        var files = {};
        foreach var file (app_info.files)
        {
          var parts = split(file.path, sep:"\", keep:FALSE);
          var exe = parts[max_index(parts) - 1];
          var parsed_version = vcf::parse_version(file.version);
          files[exe] = {'version': file.version, 'parsed_version': parsed_version};
        }
        app_info.files = files;
        return app_info;
      }

      ##
      # Checks supplied version against constraints.
      #
      # @param [app_info:array] Details of the Microsoft Endpoint Configuration Manager installed on the target
      # @param [constraints:list] Version constraints that define vulnerable versions.
      #
      # @return [NULL|int|array] Returns matching constraint, NULL if no match or an error code.
      ##
      function check_version(app_info, constraints)
      {
        if(isnull(app_info) || typeof(app_info) != "array") return arg_error(arg:"version", func:FUNCTION_NAME);
        if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

        foreach var item (constraints)
        {
          var version = app_info.parsed_version;
          if(!empty_or_null(item.file))
          {
            if(empty_or_null(app_info.files[item.file]))
              exit(0, 'The file ' + item.file + ' was not detected');
            version = app_info.files[item.file].parsed_version;
          }
          var meets_constraint = check_version_against_constraint(version:version, constraint:item, strict:FALSE);
          if(is_error(meets_constraint)) return meets_constraint;
          if(meets_constraint) return item;
        }
        return NULL;
      }

      ##
      # Checks version of Microsoft Endpoint Configuration Manager against a MS security advisory.
      #
      # @param [app_info:array] Details of the Microsoft Endpoint Configuration Manager installed on the target
      # @param [constraints:list] Version constraints that define vulnerable versions.
      # @param [severity:int] It is a security hole, warning or note?
      # @param [flags:array] Flags for identifying certain classes of vulnerabilities (XSS, XSRF, SQLi)
      ##
      function check_version_and_report(app_info, constraints, severity, flags)
      {
        var constraint = check_version(app_info:app_info, constraints:constraints);
        if(empty_or_null(constraint))
          vcf::audit(app_info);
        var fix = constraint.fixed_version;
        if(!empty_or_null(constraint.fixed_display))
          fix = constraint.fixed_display;
        var report_items = {
          'Installed version': app_info.version,
          'Fixed version': fix
        };
        var ordering = ['Installed version', 'Fixed version'];
        if(!empty_or_null(constraint.file))
        {
          ordering = ['Installed version', constraint.file + ' version', 'Fixed version'];
          report_items[constraint.file + ' version'] = app_info.files[constraint.file].version;
        }
        if(!empty_or_null(app_info.path))
        {
          append_element(var:ordering, value:'Path');
          report_items['Path'] = app_info.path;
        }
        store_structured_data(app_info:app_info, fix:fix, fix_version:constraint.fixed_version, port:app_info.port);
        var extra = report_items_str(report_items:report_items, ordered_fields:ordering);
        security_report_v4(severity:severity,
                           port:app_info.port,
                           extra:extra,
                           xss:flags.xss,
                           xsrf:flags.xsrf,
                           sqli:flags.sqli,
                           proto:app_info.proto);
      }
    }

    namespace odbc_driver
    {
      ##
      # Filters constraints by OS
      # @param [os:string] Operating system to filter on.
      # @param [constraints:list] List of arrays detailing vulnerable ranges.
      # @return [list] Constraints which are applicable to the given app_info's os
      ##
      function _filter_constraints_for_os(os, constraints)
      {
          dbg::log(msg:'[pre][_filter_constraint]');
          return collib::filter(constraints, args:[os], f:function ()
          {
              local_var os = _FCT_ANON_ARGS[0];
              local_var constraint = _FCT_ANON_ARGS[1];
              dbg::log(msg:'[constraint.os][' + constraint.os + '][os][' + os + ']');
              return constraint.os >< os;
          });
      }

      ##
      # Wrapper around VCF functionality to report
      # @param [app_info:array] install info
      # @param [severity:int] It is a security hole, warning or note?
      # @param [constraints:list] Constraints that define vulnerable versions.
      # @param [strict:boolean] if set, versions MUST have the same number of fields (segments)
      # @param [flags:array] Flags for identifying certain classes of vulnerabilities (XSS, XSRF, SQLi)
      ##
      function check_version_and_report(app_info, severity, constraints, strict, flags) {
          local_var extra, os;
          local_var report_items;

          os = tolower(get_kb_item("Host/OS"));
          dbg::log(msg:'[OS][' + obj_rep(os) + ']');
          if(!empty_or_null(os))
          {
            dbg::log(msg:'[null-OS][' + obj_rep(os) + ']');
              if(os =~ "(aix|hpux|linux|solaris|nix)$")
                os = 'unix';
              else if(os =~ "(windows)")
                os = 'win';
              else if(os =~ "(mac osx)")
                os = 'osx';
          }
          dbg::log(msg:'[final-OS][' + os + ']');
          local_var os_constraints = _filter_constraints_for_os(os:os, constraints:constraints);
          dbg::log(msg:'[os_constraints][' + obj_rep(os_constraints) + ']');
          local_var order = ['Installed version', 'Fixed version'];

          if(isnull(app_info))
              return arg_error(arg:'app_info', func:FUNCTION_NAME);
          if(isnull(severity))
              return arg_error(arg:'severity', func:FUNCTION_NAME);
          if(isnull(constraints))
              return arg_error(arg:'constraints', func:FUNCTION_NAME);

          var matching_os_constraint = vcf::check_version(version:app_info.parsed_version,
                                                          constraints:os_constraints,
                                                          strict:strict);
          dbg::log(msg:'Matching OS constraint: ' + obj_rep(matching_os_constraint));
          if(vcf::is_error(matching_os_constraint))
              return vcf::vcf_exit(1, matching_os_constraint.message);

          if(!empty_or_null(matching_os_constraint)) {
              report_items = {
                  'Installed version' : app_info.version,
                  'Fixed version'     : matching_os_constraint.fixed_version
              };
              extra = report_items_str(report_items:report_items, ordered_fields:order);
          }

          if(empty_or_null(matching_os_constraint))
              vcf::audit(app_info);
          var port;
          if(empty_or_null(app_info.port)) port=0;
          else port = app_info.port;
          store_structured_data(app_info:app_info, fix_version:matching_os_constraint.fixed_version, port:port);
          security_report_v4(severity:severity,
                             port:port,
                             extra:extra,
                             xss:flags.xss,
                             xsrf:flags.xsrf,
                             sqli:flags.sqli);

      }
    }
  }
}
