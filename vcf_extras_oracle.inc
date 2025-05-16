###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_oracle.inc
#
# Revision: 1.1
###
include('compat_shared.inc');
include('debug.inc');
include('lists.inc');
include('oracle_rdbms_cpu_func.inc');
include('vcf.inc');
include('install_func.inc');
include('spad_log_func.inc');

namespace vcf
{
  namespace oracle_rdbms
  {
    ##
    # Returns detected installs in a format VCF can make vulnerability determinations on
    # @return app_info [Array] An array describing a detected install.
    # Audits if No installs are found
    # Note: This function branches.
    ##
    function get_app_info() {
        local_var installs = _get_installs();
         if(empty_or_null(installs))
            audit(AUDIT_NOT_INST, 'Oracle Database');

        local_var install = branch (installs);
        return _convert_install_to_app_info(install:install);
    }

    ##
    # Wrapper around VCF functionality to report
    # @param [app_info:array]   Array containing install info
    # @param [severity:int]     Severity of the vulnerability to report
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
    # @param [flags:array]      xss, xsrf, and sqli
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags) {
        local_var extra, extra_rdbms, extra_ojvm;
        local_var report_items;
        local_var rdbms_constraints = _filter_constraints(os:app_info.os, component:'db', constraints:constraints);
        local_var ojvm_constraints = _filter_constraints(os:app_info.os, component:'ojvm', constraints:constraints);
        local_var order = ['Component', 'Installed version', 'Fixed version', 'Missing patch'];
        local_var exp_order = ['Component', 'Installed version', 'Fixed version', 'Edition Note'];

        local_var express_note = 'This instance appears to be an Oracle DB XE. ' +
        'Oracle does not release patches for XE. To mitigate vulnerabilities, Oracle ' +
        'recommends migrating to a fully supported edition.';

        if(isnull(app_info))
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints))
            return arg_error(arg:'constraints', func:FUNCTION_NAME);

        local_var matching_rdbms_constraint = vcf::check_version(version:app_info.parsed_version,
                                                                 constraints:rdbms_constraints,
                                                                 strict:strict);
        dbg::log(msg:'Matching RDBMS constraint: ' + obj_rep(matching_rdbms_constraint));
        if(vcf::is_error(matching_rdbms_constraint))
            return vcf::vcf_exit(1, matching_rdbms_constraint.message);

        if (!isnull(app_info.edition) && (app_info.edition =~ 'Express') && !empty_or_null(matching_rdbms_constraint)) {
            report_items = {
                'Component'         : 'RDBMS',
                'Installed version' : app_info.version,
                'Fixed version'     : matching_rdbms_constraint.fixed_version,
                'Edition Note'      : express_note
            };
            extra_rdbms = report_items_str(report_items:report_items, ordered_fields:exp_order);
        }
        else if (!empty_or_null(matching_rdbms_constraint)) {
            report_items = {
                'Component'         : 'RDBMS',
                'Installed version' : app_info.version,
                'Fixed version'     : matching_rdbms_constraint.fixed_version,
                'Missing patch'     : matching_rdbms_constraint.missing_patch
            };
            extra_rdbms = report_items_str(report_items:report_items, ordered_fields:order);
        }

        # Now Check OJVM:
        if(!empty_or_null(app_info.ojvm_patchlevel))
        {
            app_info.parsed_version = vcf::parse_version(app_info.ojvm_patchlevel);
            app_info.version = app_info.ojvm_patchlevel;
            local_var matching_ojvm_constraint = vcf::check_version(version:app_info.parsed_version,
                                                                    constraints:ojvm_constraints,
                                                                    strict:strict);
            dbg::log(msg:'Matching OJVM constraint: ' + obj_rep(matching_ojvm_constraint));
            if(vcf::is_error(matching_ojvm_constraint))
                return vcf::vcf_exit(1, matching_ojvm_constraint.message);

            if(!empty_or_null(matching_ojvm_constraint)) {
                report_items = {
                    'Component'         : 'OJVM',
                    'Installed version' : app_info.version,
                    'Fixed version'     : matching_ojvm_constraint.fixed_version,
                    'Missing patch'     : matching_ojvm_constraint.missing_patch
                };
                extra_ojvm = report_items_str(report_items:report_items, ordered_fields:order);
            }
        }

        if(empty_or_null(matching_rdbms_constraint) && empty_or_null(matching_ojvm_constraint))
            vcf::audit(app_info);
        var port;
        if(empty_or_null(app_info.port)) port=0;
        else port = app_info.port;
        store_structured_data(app_info:app_info, fix_version:matching_ojvm_constraint.fixed_version, port:port);
        security_report_v4(severity:severity,
                           port:port,
                           extra:extra_rdbms + extra_ojvm,
                           xss:flags.xss,
                           xsrf:flags.xsrf,
                           sqli:flags.sqli);
    }

    ##
    # Finds Oracle database installs
    #   - Subset of oracle_rdbms_cpu_func.check_oracle_database()
    # @return [Array] An array of oracle database installs
    # Audits if:
    #   - OS cannot be identified
    #   - All KB items set by local / remote detection are NULL.
    ##
    function _get_installs()
    {
        var os, port, tnslsnr, lsnrversion, res;
        var sids, sid, ohome, installs, ver, dbversion;
        var rdbms_patchlevel, ojvm_patchlevel;
        var osandport;
        var ojvm_installed;
        var tns_os, edition;
        edition = NULL;
        os = NULL;

        if(get_kb_item('Oracle/Patches/local'))
        {
            osandport = get_oracledb_host_os_and_port();
            os = osandport['os'];
            port = osandport['port'];

            res = get_kb_list('Oracle/*/RDBMS Patch Level');
            dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg:'[_get_installs][patches/local][os][' + os + ']' +
                                                              '[port][' + port + '][' + obj_rep(res) + ']');
            foreach ohome (keys(res))
            {
                # Skip Remote port based entries in case Local and Remote both wrote KBs
                if(preg(string:ohome, pattern:'^Oracle/[0-9]+'))
                    continue;
                rdbms_patchlevel = res[ohome];
                ohome = ohome - 'Oracle/';
                ohome = ohome - '/RDBMS Patch Level';
                installs[ohome]['rdbms_patchlevel'] = rdbms_patchlevel;

                ver = split(rdbms_patchlevel, sep:'.', keep:FALSE);
                installs[ohome]['version'] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];

                edition = get_kb_item('Oracle/' + ohome + '/Edition');
                installs[ohome]['edition'] = edition;

                ojvm_patchlevel = get_kb_item('Oracle/' + ohome + '/OJVM Patch Level');
                ojvm_installed = NULL;
                # If remote detection happened then we probably know if OJVM is installed or not
                if(!empty_or_null(ojvm_patchlevel))
                    ojvm_installed = ojvm_remotely_detected(ohome: ohome);
                # If ojvm_installed is NULL then it means we couldn't find OJVM Installed in the KB
                # so to avoid FNs we report the patch level
                if(!empty_or_null(ojvm_patchlevel) && (ojvm_installed || isnull(ojvm_installed)))
                    installs[ohome]['ojvm_patchlevel'] = ojvm_patchlevel;
                else if(!empty_or_null(ojvm_patchlevel))
                    dbg::detailed_log(
                        lvl:3,
                        src:FUNCTION_NAME,
                        msg:'[_get_installs][patches/local][os][' + os + '][port][' + port + ']' +
                            '[OJVM patch level skipped]');
                 if(!empty_or_null(os))
                {
                    if(os =~ "(aix|hpux|linux|solaris|macosx|nix)$")
                        installs[ohome]['os'] = 'unix';
                    else if(os =~ "win(32|64|$)")
                        installs[ohome]['os'] = 'win';
                }
                installs[ohome]['port'] = 0;
                dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg:'[_get_installs][patches/local][ohome][' + ohome +
                                                                  '][port][' + port + '][' + obj_rep(res) + ']');
            }
        }
        else if(get_kb_item('Oracle/RDBMS/Patches/Remote'))
        {
            port = get_service(svc:'oracle_tnslsnr', default:1521, exit_on_fail:TRUE);
            tnslsnr = get_kb_item_or_exit('oracle_tnslsnr/' + port + '/version');
            tns_os = get_kb_item("oracle_tnslsnr/"+port+"/tns_os");
            os = get_oracle_os(tnslsnr:tnslsnr, tns_os:tns_os);
            if(os == 'unknown')
            {
                osandport = get_oracledb_host_os_and_port();
                os = osandport['os'];
            }

            sids = get_kb_list('Oracle/' + port + '/*/RDBMS Patch Level');
            foreach sid (keys(sids))
            {
                rdbms_patchlevel = sids[sid];
                sid = sid - ('Oracle/' + port + '/');
                sid = sid - '/RDBMS Patch Level';
                ver = split(rdbms_patchlevel, sep:'.', keep:FALSE);
                installs[sid]['version'] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
                installs[sid]['rdbms_patchlevel'] = rdbms_patchlevel;
                installs[sid]['port'] = port;

                ojvm_installed = get_kb_item('Oracle/' + port + '/' + sid + '/OJVM Installed');
                ojvm_patchlevel = get_kb_item('Oracle/' + port + '/' + sid + '/OJVM Patch Level');

                if(ojvm_installed && !empty_or_null(ojvm_patchlevel))
                    installs[sid]['ojvm_patchlevel'] = ojvm_patchlevel;

                if(!empty_or_null(os))
                {
                    if(os =~ "(aix|hpux|linux|solaris|macosx|nix)$")
                        installs[sid]['os'] = 'unix';
                    else if(os =~ "win(32|64|$)")
                        installs[sid]['os'] = 'win';
                }
            }
        }
        else if(get_kb_item('Settings/PCI_DSS') || (get_kb_item('Services/oracle_tnslsnr') && report_paranoia > 1))
        {
            port = get_service(svc:'oracle_tnslsnr', default:1521, exit_on_fail:TRUE);
            tnslsnr = get_kb_item_or_exit('oracle_tnslsnr/' + port + '/version');
            tns_os = get_kb_item("oracle_tnslsnr/"+port+"/tns_os");
            os = get_oracle_os(tnslsnr:tnslsnr, tns_os:tns_os);
            dbg::log(msg:'[_get_installs][pci/services][tnslsnr][' + tnslsnr + ']' +
                         '[port][' + port + '][os][' + os + ']');
            if(os == 'unknown')
            {
                osandport = get_oracledb_host_os_and_port();
                dbg::log(msg:'[_get_installs][pci/services][osandport][' + obj_rep(osandport) + ']');
                os = osandport['os'];
            }

            lsnrversion = get_oracle_version(tnslsnr:tnslsnr);
            ver = split(lsnrversion, sep:'.', keep:FALSE);
            installs[lsnrversion]['version'] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
            installs[lsnrversion]['rdbms_patchlevel'] = lsnrversion;
            installs[lsnrversion]['ojvm_patchlevel'] = lsnrversion;
            if(!empty_or_null(os))
            {
                if(os =~ "(aix|hpux|linux|solaris|macosx|nix)$")
                    installs[lsnrversion]['os'] = 'unix';
                else if(os =~ "win(32|64|$)")
                    installs[lsnrversion]['os'] = 'win';
            }
            dbg::log(msg:'[_get_installs][installs][' + obj_rep(installs) + ']');
        }
        else
        {
            exit(1, 'No Databases detected on the remote host.');
        }
        if(empty_or_null(os))
            exit(1, 'Failed to determine the host OS.');
       return installs;
    }

    ##
    # Convert each install to an app_info VCF can work with
    # @param [path:string]   Path where the installation was found
    # @param [install:array] Array of values to be converted
    # @return [array]        Array with members VCF can use for comparisons.
    ##
    function _convert_install_to_app_info(path, install) {
        local_var app_info = install;

        app_info.app_name = 'Oracle RDBMS';
        app_info.version = app_info.rdbms_patchlevel;
        app_info.parsed_version = vcf::parse_version(app_info.rdbms_patchlevel);
        if (!empty_or_null(path))
            app_info.path = path;

        return app_info;
    }

    ##
    # Filters constraints by OS
    # @param [os:string]        Operating system to filter on.
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @return [List] A list of constraints which are applicable to the given app_info's os
    ##
    function _filter_constraints_for_os(os, constraints)
    {
        return collib::filter(constraints, args:[os], f:function ()
        {
            local_var os = _FCT_ANON_ARGS[0];
            local_var constraint = _FCT_ANON_ARGS[1];
            return constraint.os >< os;
        });
    }

    ##
    # Filters constraints by component
    # @param [component:string] Component to filter on (ojvm / db)
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @return [list] A list of constraints which are applicable to the given app_info's component
    ##
    function _filter_constraints_for_component(component, constraints)
    {
        return collib::filter(constraints, args:[component], f:function ()
        {
            local_var component = _FCT_ANON_ARGS[0];
            local_var constraint = _FCT_ANON_ARGS[1];
            return constraint.component == component;
        });
    }

    ##
    # Filters constraints by component and OS
    # @param [app_info:array]   Array of install information
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @return [List] A list of constraints which are applicable to the given app_info's component
    ##
    function _filter_constraints(component, os, constraints)
    {
        local_var filtered = _filter_constraints_for_os(os:os, constraints:constraints);
        return _filter_constraints_for_component(component:component, constraints:filtered);
    }
  }

  namespace oracle_jdev
  {
    ##
    # Ensures that the version displayed in plugin output is not the official version, not our mapped version
    # @return app_info [Array] An array describing a detected install.
    # Audits if No installs are found
    ##
    function get_app_info()
    {
        var app_info = vcf::get_app_info(app:'Oracle JDeveloper');

        app_info.display_version = app_info.version;

        # Ensure we actually have an effective_version
        if(empty_or_null(app_info.effective_version))
        {
            app_info.effective_version = app_info.version;
        }
        else
        {
            app_info.version = app_info.effective_version;
            app_info.parsed_version = vcf::parse_version(app_info.version);
        }

        # Get list of patches
        var patch_info = find_patches_in_ohomes(ohomes:[ app_info.path, app_info.path + "\jdeveloper" ]);
        var patches = make_list();

        # this is the resulting list of ohomes
        foreach var ohome (keys(patch_info))
        {
            # these are the patches enumerated from each ohome
            foreach var patch (keys(patch_info[ohome]))
            {
                # build a list of all patches in all ohomes to test against
                append_element(var:patches, value:patch);
            }
        }

        app_info.patches = patches;

        return app_info;
    }

    ##
    # Wrapper around VCF functionality to report
    # @param [app_info:array]   Array containing install info
    # @param [severity:int]     Severity of the vulnerability to report
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
    # @param [flags:array]      xss, xsrf, and sqli
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags)
    {
        var extra;
        var report_items;
        var order = ['Path', 'Version', 'Required patch'];

        if(isnull(app_info))
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints))
            return arg_error(arg:'constraints', func:FUNCTION_NAME);

        var matching_constraint = vcf::check_version(version:app_info.parsed_version,
                                                     constraints:constraints,
                                                     strict:strict);
        dbg::log(msg:'Matching constraint: ' + obj_rep(matching_constraint));
        if(vcf::is_error(matching_constraint))
            return vcf::vcf_exit(1, matching_constraint.message);

        # Check for specific patch only if we're about to mark it as vulnerable
        var has_patch = FALSE;
        if(!empty_or_null(matching_constraint) && !empty_or_null(app_info.patches))
        {
            foreach var patch (app_info.patches)
            {
                if(matching_constraint.missing_patch == patch)
                {
                    has_patch = TRUE;
                    break;
                }
            }
        }

        if(empty_or_null(matching_constraint) || has_patch)
            vcf::audit(app_info);

        report_items = {
            'Path' : app_info.path,
            'Version' : app_info.display_version,
            'Required patch' : matching_constraint.missing_patch
        };
        extra = report_items_str(report_items:report_items, ordered_fields:order);

        store_structured_data(app_info:app_info, fix:matching_constraint.missing_patch, port:0);
        security_report_v4(severity:severity, port:0, extra:extra, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
    }
  }

  namespace oracle_weblogic
  {
    ##
    # Gathers the Oracle WebLogic installs info and puts them into an array.
    # @return [Array] An array describing a detected install.
    # Exits if No installs are found
    ##
    function get_app_info()
    {
      var app_name_lst = [
            "Oracle WebLogic Server",
            "Oracle Data Integrator Embedded Weblogic Server",
            "JDeveloper's Integrated WebLogic Server" ];

      var app_name = branch(app_name_lst);
      var app_info = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

      var os = get_kb_item_or_exit('Host/OS');
      var port = 0;
      if('windows' >< tolower(os))
      {
        port = get_kb_item('SMB/transport');
        if(!port) port = 445;
      }

      app_info.port = port;

      app_info.display_version = app_info.version;
      app_info.parsed_version = vcf::parse_version(app_info.version);

      # Ensure Oracle Home is set
      if(empty_or_null(app_info['Oracle Home']))
        app_info['Oracle Home'] = app_info['path'];

      return app_info;
    }

    ##
    # Wrapper around VCF functionality to report
    # @param [app_info:array]   Array containing install info
    # @param [severity:int]     Severity of the vulnerability to report
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
    # @param [flags:array]      xss, xsrf, and sqli
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags)
    {
        var extra;
        var report_items;
        var order = ['Oracle Home', 'Install path', 'Version', 'Fixes'];

        if(empty_or_null(app_info))
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(empty_or_null(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(empty_or_null(constraints))
            return arg_error(arg:'constraints', func:FUNCTION_NAME);

        var matching_constraint = vcf::check_version(version:app_info.parsed_version,
                                                     constraints:constraints,
                                                     strict:strict);
        dbg::log(msg:'Matching constraint: ' + obj_rep(matching_constraint));
        if(vcf::is_error(matching_constraint))
            return vcf::vcf_exit(1, matching_constraint.message);

        if(empty_or_null(matching_constraint))
            vcf::audit(app_info);
        if(empty_or_null(matching_constraint['fixed_display']))
            return arg_error(arg:'fixed_display', func:FUNCTION_NAME);

        # make sure ohome, fixed display both set
        report_items = {
            'Oracle Home'  : app_info['Oracle Home'],
            'Install path' : app_info['path'],
            'Version'      : app_info['version'],
            'Fixes'        : matching_constraint['fixed_display']
        };
        extra = report_items_str(report_items:report_items, ordered_fields:order);

        store_structured_data(app_info:app_info,
                              fix:matching_constraint.fixed_display,
                              fix_version:matching_constraint.fixed_version,
                              port:0);
        security_report_v4(severity:severity, port:0, extra:extra, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
    }
  }

  namespace oracle_ebusiness
  {
    ##
    # Build a vcf-style app_info
    # @return app_info [Array] An array describing a detected install.
    # Exits if No installs are found
    ##
    function get_app_info()
    {
      var app_name = 'Oracle E-Business';
      var version = get_kb_item_or_exit('Oracle/E-Business/Version');
      var patched_versions = get_kb_item('Oracle/E-Business/patched_versions');
      var parsed_version  = vcf::parse_version(version);
      var app_info = make_array();

      app_info['app'] = app_name;
      app_info['version'] = version;
      app_info['display_version'] = version;
      app_info['parsed_version'] = parsed_version;
      app_info['patched_versions'] =  patched_versions;
      app_info['cpe/v23'] = "cpe:2.3:a:oracle:e-business_suite";

      return app_info;
    }

    ##
    # Wrapper around VCF functionality to report
    # @param [app_info:array]   Array containing install info
    # @param [severity:int]     Severity of the vulnerability to report
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
    # @param [flags:array]      xss, xsrf, and sqli
    # @param [fix_date:string]  Mandatory argument, fix date, needed for patch mapping
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags, fix_date)
    {
        var extra;
        var report_items;
        var order = ['Installed version', 'Fixed version', 'Required Patches'];

        if(isnull(app_info))
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints))
            return arg_error(arg:'constraints', func:FUNCTION_NAME);
        if(isnull(fix_date))
            return arg_error(arg:'fix_date', func:FUNCTION_NAME);

        # check if patched
        var version_regex = "(^|[^0-9])" + app_info.version + "\." + fix_date + "([^0-9]|$)";
        if(!empty_or_null(app_info.patched_versions) && app_info.patched_versions =~ version_regex)
          ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version);

        var matching_constraint = vcf::check_version(version:app_info.parsed_version,
                                                     constraints:constraints,
                                                     strict:strict);
        dbg::log(msg:'Matching constraint: ' + obj_rep(matching_constraint));
        if(vcf::is_error(matching_constraint))
          return vcf::vcf_exit(1, matching_constraint.message);
        if(empty_or_null(matching_constraint))
          ::audit(AUDIT_INST_PATH_NOT_VULN, app_info.app, app_info.version);

        # Check for specific fixed_version, otherwise set this to version
        var fixed_version = app_info.version;
        if(!(empty_or_null(matching_constraint.fixed_display)))
          fixed_version = matching_constraint.fixed_display;

        report_items = {
            'Installed version' : app_info.version,
            'Fixed version'     : fixed_version,
            'Required Patches'  : matching_constraint.fix_patches
        };
        extra = report_items_str(report_items:report_items, ordered_fields:order);

        # Fixes driven by patches so fixed_version is rarely a comparable version so we report it
        # in the 'fix' argument to indicate that a fix is available.
        store_structured_data(app_info:app_info, fix:matching_constraint.fix_patches, port:0);

        security_report_v4(severity:severity, port:0, extra:extra, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
    }
  }

  namespace oracle_oats
  {
    ##
    # Build a vcf-style app_info
    # @return app_info [Array] An array describing a detected install.
    # Audits if No installs are found
    ##
    function get_app_info()
    {
      var app_name = 'Oracle Application Testing Suite';
      var app_info = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
      app_info.parsed_version = vcf::parse_version(app_info.version);

      if(get_kb_item('TESTING_ORACLE_OATS_SKIP_DB'))
        return app_info;

      var ohome = app_info['Oracle Home'];
      var ohomes = make_list(ohome);

      # Get list of patches
      var patch_info = find_patches_in_ohomes(ohomes:ohomes);
      var patches = make_list();

      # this is the resulting list of ohomes
      foreach var patch (keys(patch_info[ohome]))
      {
        # build a list of all patches in all ohomes to test against
        append_element(var:patches, value:patch);
      }

      app_info.patches = patches;

      return app_info;
    }

    ##
    # Wrapper around VCF functionality to report
    # @param [app_info:array]   Array containing install info
    # @param [severity:int]     Severity of the vulnerability to report
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
    # @param [flags:array]      xss, xsrf, and sqli
    # @param [patches_to_report:list] A list of patches to report on a vulnerable host. This should be all patches mentioned in
    # the CPU
    # @param [patches_to_check:list]  A list of patches to specifically check are installed. We only need to check for the
    # required patches that don't affect the version
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags, patches_to_report,
                                      patches_to_check)
    {
        if(isnull(app_info))
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints))
            return arg_error(arg:'constraints', func:FUNCTION_NAME);

        var matching_constraint = vcf::check_version(version:app_info.parsed_version,
                                                     constraints:constraints,
                                                     strict:strict);
        dbg::log(msg:'Matching constraint: ' + obj_rep(matching_constraint));
        if(vcf::is_error(matching_constraint))
            return vcf::vcf_exit(1, matching_constraint.message);

        # Check for presence of all specified patch(es) in patches_to_check
        var missing_a_patch = FALSE;
        if(!empty_or_null(patches_to_check))
        {
          foreach var patch_to_check (patches_to_check)
          {
            var missing_this_patch = TRUE;
            foreach var installed_patch (app_info.patches)
            {
              if(patch_to_check == installed_patch)
              {
                  missing_this_patch = FALSE;
                  break;
              }
            }
            if(missing_this_patch)
            {
              missing_a_patch = TRUE;
              break;
            }
          }
        }

        if(empty_or_null(matching_constraint) && !missing_a_patch)
          vcf::audit(app_info);

        var order = ['Oracle home', 'Install path', 'Version', 'Required patch(es)'];
        if(empty_or_null(app_info['Oracle Home']))
          app_info['Oracle Home'] = app_info['path'];
        var report_items = {
            'Oracle home'        : app_info['Oracle Home'],
            'Install path'       : app_info['path'],
            'Version'            : app_info['version'],
            'Required patch(es)' : join(patches_to_report, sep:', ')
        };
        var extra = report_items_str(report_items:report_items, ordered_fields:order);

        # Fixes driven by patches so fixed_version is rarely a comparable version so we report it
        # in the 'fix' argument to indicate that a fix is available.
        store_structured_data(app_info:app_info, fix:patches_to_report, port:0);

        security_report_v4(severity:severity, port:0, extra:extra, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
    }
  }

  namespace oracle_goldengate
  {
    ##
    # Build a vcf-style app_info
    # @return app_info [Array] An array describing a detected install.
    # Exits if No installs are found
    ##
    function get_app_info()
    {
      get_kb_item_or_exit('Oracle/GoldenGate/Installed');
      var app_info = vcf::get_app_info(app:'Oracle GoldenGate');
      if(!empty_or_null(app_info['Patch Version']))
        app_info['version'] = app_info['Patch Version'];

      app_info['parsed_version'] = vcf::parse_version(app_info['version']);
      app_info['cpe/v23'] = "cpe:2.3:a:oracle:goldengate";

      dbg::detailed_log(lvl:1, msg:'app_info:' + obj_rep(app_info));
      return app_info;
    }
  }
  namespace oracle_tuxedo
  {
    ##
    # Wrapper around VCF functionality to check constraints & report
    # @param [app_info:array]   Array containing install info
    # @param [severity:int]     Severity of the vulnerability to report
    # @param [constraints:list] List of arrays detailing vulnerable ranges.
    # @param [flags:array]      xss, xsrf, and sqli
    ##
    function check_version_and_report(app_info, severity, constraints, flags)
    {
        if(isnull(app_info))
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity))
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints))
            return arg_error(arg:'constraints', func:FUNCTION_NAME);

        local_var vuln = FALSE;
        local_var rp_fix;
        foreach var constraint (constraints)
        {
          if(app_info.version =~ constraint.version_regex)
          {
            if(!typeof(constraint.rp_fix == 'int'))
              constraint.rp_fix = int(constraint.rp_fix);

            if(app_info.RP == UNKNOWN_VER || app_info.RP < constraint.rp_fix)
            {
              vuln = TRUE;
              rp_fix = constraint.rp_fix;
              break;
            }
          }
        }

        if(!vuln)
          return vcf::audit(app_info);

        local_var order = make_list('Path', 'Version', 'RP', 'Required RP');
        local_var items = make_array(
          order[0], app_info.path,
          order[1], app_info.version,
          order[2], app_info.RP,
          order[3], rp_fix
        );
        local_var extra = report_items_str(report_items:items, ordered_fields:order);

        # Fixes driven by patches so fixed_version is rarely a comparable version so we report it
        # in the 'fix' argument to indicate that a fix is available.
        store_structured_data(app_info:app_info, fix:rp_fix, port:0);

        security_report_v4(
          severity:severity,
          port:0,
          extra:extra,
          xss:flags.xss,
          xsrf:flags.xsrf,
          sqli:flags.sqli
        );
    }
  }
}
