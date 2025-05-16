###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_nvidia.inc
#
# Revision: 1.4
###

include('compat_shared.inc');
include('lists.inc');
include('install_func.inc');
include('vcf.inc');

namespace vcf
{
  namespace nvidia_gpu
  {
    ##
    # Builds app_info for Nvidia
    # @param [win_local:boolean] bool indicating if a Windows install should be returned(omit / false for Unix).
    #
    # @return [array] an array containing application info
    ##
    function get_app_info(win_local)
    {
      var app_info;
      if(win_local)
        app_info =_get_app_info_windows();
      else
        app_info = _get_app_info_unix();

      app_info["cpe/v23"] = "cpe:2.3:a:nvidia:gpu_driver";
      return app_info;
    }

    ##
    # Returns an array of information about a Unix Nvidia GPU install.
    #
    # @return [array] Info to report on a discovered Unix Nvidia GPU install.
    ##
    function _get_app_info_unix()
    {
      var app_info = {};
      app_info['app'] = 'NVIDIA UNIX Driver';
      app_info['version'] = get_kb_item_or_exit('NVIDIA_UNIX_Driver/Version');
      app_info['gpumodel'] = tolower(get_kb_item_or_exit('NVIDIA_UNIX_Driver/GPU_Model'));
      app_info['parsed_version'] = vcf::parse_version(app_info['version']);
      app_info['port'] = 0;
      return app_info;
    }

    ##
    # Returns an array of information about a Windows Nvidia GPU install.
    #
    # @return [array] Info to report on a discovered Windows Nvidia GPU install.
    #
    # @remark
    #   This function audits on error.
    ##
    function _get_app_info_windows()
    {
      var app_info = {};

      var kb_base = 'WMI/DisplayDrivers/';
      var kbs = get_kb_list(kb_base + '*/Name');
      if(empty_or_null(kbs))
        exit(0, 'No display drivers were found.');

      var drivers = [];

      foreach var kb (keys(kbs))
      {
        var name = kbs[kb];
        # only check NVIDIA drivers
        if('NVIDIA' >!< toupper(name))
          continue;

        var id = kb - kb_base - '/Name';
        var driver_date = get_kb_item_or_exit(kb_base + id + '/DriverDate');
        var version = get_kb_item_or_exit(kb_base + id + '/Version');
        var gpumodel = tolower(get_kb_item_or_exit(kb_base + id + '/Processor'));

        var driver = {
          'device_name': name,
          'gpumodel': gpumodel,
          'version': version,
          'display_driver_date': driver_date
        };
        append_element(var:drivers, value:driver);
      }
      app_info['drivers'] = drivers;
      app_info['port'] = 0;
      app_info['win_local'] = TRUE;
      return app_info;
    }

    ##
    # Checks a Nvidia app_info array version and reports results
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
      var fix, matching_constraint, order, report, report_items;

      if(isnull(app_info))
          return arg_error(arg:'app_info', func:FUNCTION_NAME);
      if(isnull(severity))
          return arg_error(arg:'severity', func:FUNCTION_NAME);
      if(isnull(constraints))
          return arg_error(arg:'constraints', func:FUNCTION_NAME);

      if(app_info.win_local)
      {
        report = '';
        foreach var driver (app_info.drivers)
        {
          var driver_app_info = {
            'app':driver.device_name,
            'display_driver_date':driver.display_driver_date,
            'gpumodel':driver.gpumodel,
            'port':0,
            'version':driver.version
          };
          driver_app_info['parsed_version'] = vcf::parse_version(driver_app_info.version);

          var relevant_constraints = filter_constraints(app_info:driver_app_info, constraints:constraints);

          matching_constraint = vcf::check_version(
            version:driver_app_info.parsed_version,
            constraints:relevant_constraints,
            strict:strict
          );

          if(vcf::is_error(matching_constraint))
            return vcf::vcf_exit(1, matching_constraint.message);

          if(empty_or_null(matching_constraint))
            continue;

          fix = matching_constraint.fixed_display;
          if(empty_or_null(fix))
            fix = matching_constraint.fixed_version;


          order = ['Device name', 'Driver version', 'Driver date', 'Fixed version'];
          report_items = make_array(
            order[0], driver_app_info.app,
            order[1], driver_app_info.version,
            order[2], driver_app_info.display_driver_date,
            order[3], fix
          );

          report += report_items_str(report_items:report_items, ordered_fields:order);
          report += '\n';
        }
        if(empty_or_null(report))
          return vcf::audit(app_info);
      }
      else # Unix
      {
        constraints = filter_constraints(app_info: app_info, constraints: constraints);
        matching_constraint = vcf::check_version(version:app_info.parsed_version,
                                                 constraints:constraints,
                                                 strict:strict);

        if(vcf::is_error(matching_constraint))
          return vcf::vcf_exit(1, matching_constraint.message);

        if(empty_or_null(matching_constraint))
          return vcf::audit(app_info);

        fix = matching_constraint.fixed_display;
        if(empty_or_null(fix))
          fix = matching_constraint.fixed_version;

        report_items = {
          'Installed driver version' : app_info.version,
          'Fixed driver version' : fix
        };
        order = ['Installed driver version', 'Fixed driver version'];
        report = report_items_str(report_items:report_items, ordered_fields:order);
      }
      store_structured_data(app_info:app_info,
                            fix:fix,
                            fix_version:matching_constraint.fixed_version,
                            port:app_info.port);
      security_report_v4(severity:severity,
                         port:app_info.port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);
      return vcf_exit(0);
    }

    ##
    # Filter out constraints which aren't relevant to the app_info's gpumodel.
    #
    # @param [app_info:array]   array containing application info
    # @param [constraints:list] list of constraint arrays
    #
    # @return [boolean] Returns TRUE if the supplied app_info matches the supplied constraints,
    #                   FALSE otherwise.
    ##
    function filter_constraints(app_info, constraints)
    {
      return collib::filter(constraints, args:[app_info], f: function ()
      {
        var app_info = _FCT_ANON_ARGS[0];
        var constraint = _FCT_ANON_ARGS[1];

        if(!is_list(constraint.gpumodel))
          constraint.gpumodel = [constraint.gpumodel];

        foreach var model (constraint.gpumodel)
        {
          if(model >< app_info.gpumodel)
            return TRUE;
        }
        return FALSE;
      });
    }

  }
  namespace nvidia_dgx_a100_sbios
  {
    ##
    # Builds app_info for Nvidia DGX bios.
    #
    # @return [array] an array containing application info
    #
    # @remark
    # This function audits on error.
    ##
    function get_app_info()
    {
      var product_name = get_kb_item_or_exit('DMI/System/SystemInformation/ProductName');
      var manufacturer = get_kb_item_or_exit('DMI/System/SystemInformation/Manufacturer');
      var version = get_kb_item_or_exit('BIOS/Version');

      if(manufacturer != 'NVIDIA' || product_name !~ 'A[18]00' || 'Station' >< product_name)
        ::audit(AUDIT_HOST_NOT, 'an NVIDIA A100/A800 system');
      if(empty_or_null(version) || version == UNKNOWN_VER)
        ::audit(AUDIT_UNKNOWN_APP_VER, 'NVIDIA System BIOS');

      var match = pregmatch(string:product_name, pattern:"^DGX([^\s]+)\s");
      var cpemod;
      var cpe = "cpe:2.3:h:nvidia:dgx";
      if(!isnull(match) && !isnull(match[1]))
        cpe += "_" + tolower(match[1]);

      var parsed_version = parse_version(version);
      if(is_error(parsed_version)) return vcf_exit(1, parsed_version.message);
      var app_info = {
        'app': 'NVIDIA System BIOS',
        'version': version,
        'parsed_version': parsed_version,
        'cpe/v23': cpe
      };
      return app_info;
    }
  }
}
