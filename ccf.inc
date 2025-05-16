#TRUSTED 4cf7506b246602fc836c07fd68279c36f9f38820883ddda90ed558b0899c9fd233b56f8a8d73f1ab79106fab7307cbf2debfdcbebf4c0d2ee7885dde68e2b693216d61e00cb9d497faea70073dd9c45d5ea3f11cd3b065a07c8a77cfccab091ae22c9ea3b72fa90f549333a89f858496da9ee48b41691e6fdf2db9930bdf2998707db7fc8baaa543d42336b6ad45075d7a886d7215d7c4b0317a78da382ab2517b1e60ebadafcc8b0eb487feef47493c44e14982605abe8b752ef6a1b36ba50a64b9f7de95b3f29c0e1ff295b6b301a012859df6b8a3d75b17da31e7c6ead94fa69eed772a611e6f098f4ce15a7b8470a54b0d1ddfd3412f1292446225ecee400e300808b4290feba39a59f760b214af7e9c753c4d2f2815c984e811d9e74be101a48299250bc7e30b63550a1d5102d927e651583578b001c1e472dadd612bdc4250c04b28126c5c0ab4840466fed5d8c33aa84b1edc9d804b869d59c4001f6b713504a9a47a518fb5e4c14eb72cf84475efb45743d09787ef30178bf0220bc279025c02201f7bf55fb8937e654e3b7701a1653774a1bb978677c36f32071ecb2b18d5da397cd6f32096dd4322db5ffb5712368f3dcdc132117fba07e9446fc599bcb4768bc5d3211bbb50994d27cd5e32cd9dd112cff4b896ae366b3556c10bbc66fdba6dc5a0c58ba1a7c57e96fb921bb8fdbcbae146bef01acf358a31db98
#TRUST-RSA-SHA256 17d14eaf54db1d8217a1685f2fa593beb2047a57a904e2aaede6c7026ce3699e1590d390242e88320cbe2ec3d620eb4ae54e50d6de537c1197ee80c0be0d1a54bf5b6355da90513ee0d22bd73dc881b2fe13f4159cf4278be50e995214bf618fe725258b202651fd5b9e1f57f549101093939a9b6e4290e0507a87e56de9478f464e393affd6098b1f21019dce74f45ff518d98ffd4d63b26a9465f17f8d341071b80c518411be8a948d1704676ce280f3664ce945075b9b57dbf5ad64104141ba3cf6e1d9ab0c99391d01e50afd257718d0a268605018e72bd9a07ccf20f847179658f4c705bc95dc62821868ec7725be33fbeb3fcfdef6cfb05a60ee83c822e3c8630189d41a3a6bf708d41bda8a6114050e635dbfda62bfeecb364d896f657514661c0ee515563924d4a0448f585d38d148b0f407d28058f01ee8b82a3fbbf4fc1664cd60569d4de85670c267d943c92f078e56f3d652de7bc82050d7edf85f7a9210cc0f5386bdacca159cb0016879fed9246d1a1e5dc8755782e6b2e65fb2f29184e93a45d3ad9b2b41314eebd89a9cedb8827c1c4837eeef20bcef8b7062c6c517d67b1b9b8754a8047c739c33dc928f048101ec5e2bced770d10bac83427102634bbc21bc47c3aa328c2d499a7516e5f12e8c393c8753cda9448f0054a6cf683724d35e4fe4dcb9544b22a1e661f932aa4e2b911b975e36b5e25125fd
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ccf.inc
#
# Revision: 1.51

include("compat_shared.inc");
include("install_func.inc");
include("lists.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

namespace cisco
{

  global_var PRODUCT_KBS = make_array(
      "Cisco IOS", make_array(
          "version" ,"Host/Cisco/IOS/Version"
          ,"model" ,"Host/Cisco/IOS/Model"
          ,"port" ,"Host/Cisco/IOS/Port")
      ,"Cisco IOS XE Software" , make_array(
          "version" ,"Host/Cisco/IOS-XE/Version"
          ,"model" ,"Host/Cisco/IOS-XE/Model"
          ,"port" ,"Host/Cisco/IOS-XE/Port")
      ,"Cisco IOS XE SD-WAN Software" , make_array(
          "version" ,"Host/Cisco/SDWAN/Version"
          ,"model" ,"Host/Cisco/SDWAN/Model"
          ,"port" ,"Host/Cisco/IOS-XE/Port")
      ,"Cisco IOS XR" , make_array(
          "version" ,"Host/Cisco/IOS-XR/Version"
          ,"model" ,"Host/Cisco/IOS-XR/Model"
          ,"port" ,"Host/Cisco/IOS-XR/Port")
      ,"Cisco Identity Services Engine Software", make_array(
          "version" ,"Host/Cisco/ISE/version"
          ,"model" ,"",
          "patches", "Host/Cisco/ISE/patches"
          )
      ,"Cisco Application Control Engine (ACE)" , make_array(
          "version" ,"Host/Cisco/ACE/Version"
          ,"model" ,"")
      ,"Cisco Unified Computing System (Management Software)" ,make_array(
        "version" ,"Host/Cisco/CIMC/version"
        ,"model" ,"Host/Cisco/CIMC/model")
      ,"Cisco Unified Communications Manager" ,make_array(
        "version" ,"Host/Cisco/CUCM/Version"
        ,"display_version", "Host/Cisco/CUCM/Version_Display"
        ,"model" ,"")
      ,"Cisco NX-OS Software" ,make_array(
        "version" ,"Host/Cisco/NX-OS/Version"
        ,"model" ,"Host/Cisco/NX-OS/Model"
        ,"device" ,"Host/Cisco/NX-OS/Device")
      ,"Cisco Email Security Appliance (ESA)" ,make_array(
        "version" ,"Host/AsyncOS/Cisco Email Security Appliance/Version"
        ,"display_version" ,"Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion"
        ,"model" ,"Host/AsyncOS/Cisco Email Security Appliance/Model"
        ,"port" ,"Host/AsyncOS/Cisco Email Security Appliance/Port")
      ,"Cisco Content Security Management Appliance (SMA)" ,make_array(
        "version" ,"Host/AsyncOS/Cisco Content Security Management Appliance/Version"
        ,"display_version" ,"Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion"
        ,"model" ,"Host/AsyncOS/Cisco Content Security Management Appliance/Model"
        ,"port" ,"Host/AsyncOS/Cisco Content Security Management Appliance/Port")
      ,"Cisco Web Security Appliance (WSA)" ,make_array(
        "version" ,"Host/AsyncOS/Cisco Web Security Appliance/Version"
        ,"display_version" ,"Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion"
        ,"model" ,"")
      ,"Cisco APIC"  ,make_array(
        "version" ,""
        ,"model" ,"")
      ,"Cisco Adaptive Security Appliance (ASA) Software" ,make_array(
        "version", "Host/Cisco/ASA"
        ,"model", "Host/Cisco/ASA/model")
      ,"Cisco Wireless LAN Controller (WLC)" ,make_array(
        "version", "Host/Cisco/WLC/Version"
        ,"model", "Host/Cisco/WLC/Model"
        ,"port", "Host/Cisco/WLC/Port")
      ,"Cisco Unity Connection" ,make_array(
        "version", "Host/Cisco/Unity_Connection/Version"
        ,"model", "")
      ,"Cisco Unified Presence" ,make_array(
        "version", "Host/UCOS/Cisco Unified Presence/version"
        ,"model", "")
      ,"Cisco TelePresence VCS" ,make_array(
        "version", "Cisco/TelePresence_VCS/Version"
        ,"model", "")
      ,"Cisco Unified Communications Manager" ,make_array(
        "version", "Host/Cisco/CUCM/Version"
        ,"display_version" ,"Host/Cisco/CUCM/Version_Display"
        ,"model", "")
      ,"Cisco Small Business Series Router Firmware",make_array(
        "version", "Cisco/Small_Business_Router/Version"
        ,"model", "Cisco/Small_Business_Router/Model")
      ,"Cisco Viptela",make_array(
        "version", "Cisco/Viptela/Version"
        ,"model", "Cisco/Viptela/Model"
        ,"patches", "Cisco/Viptela/Build")
      ,"Cisco Aironet Series Router Firmware",make_array(
        "version", "Cisco/Aironet/Version"
        ,"model", "Cisco/Aironet/Model"
        ,"port", "Cisco/Aironet/Port")
      ,"IoT Field Network Director",make_array(
        "version", "Cisco/IoT Field Network Director/Version"
        ,"port", "Cisco/IoT Field Network Director/Port")
      ,"DNA Spaces Connector",make_array(
        "version", "Cisco/DNA Spaces Connector/Version"
        ,"port", "Cisco/DNA Spaces Connector/Port")
      ,"StarOS",make_array(
        "version", "Host/Cisco/StarOS/Version")
  );

  ##
  # Determines if a Cisco device is a switch
  #
  # @return TRUE if it is known to be a switch OR paranoid > 2
  ##
  function cisco_is_switch()
  {
    if(report_paranoia > 2)  return TRUE;
    return get_kb_item('Host/Cisco/device_type') == 'switch';
  }

  ##
  # Determines if a Cisco device is a router
  #
  # @return TRUE if it is known to be a router OR paranoid > 2
  ##
  function cisco_is_router()
  {
    if(report_paranoia > 2)  return TRUE;
    return get_kb_item('Host/Cisco/device_type') == 'router';
  }

  function get_product_info(name, port)
  {
    # This should check the PRODUCT_KBS array for KBs that do not use
    # register install, otherwise it will default to 

    if(!isnull(PRODUCT_KBS[name]))
    {
      var product_info = make_array();
      var ver_kb = PRODUCT_KBS[name]['version'];
      product_info['version'] = get_kb_item_or_exit(ver_kb);
      var model_kb = PRODUCT_KBS[name]['model'];

      if(model_kb == "")
        product_info['model'] = '';
      else
      {
        product_info['model'] = get_kb_item(model_kb);
        if(isnull(product_info['model']))
          product_info['model'] = '';
      }
      var device_kb = PRODUCT_KBS[name]['device'];
      if(device_kb == "")
        product_info['device'] = '';
      else
      {
        product_info['device'] = get_kb_item(device_kb);
        if(isnull(product_info['device']))
          product_info['device'] = '';
      }
      var display_version = PRODUCT_KBS[name]['display_version'];
      if(display_version == "")
        product_info['display_version'] = '';
      else
      {
        product_info['display_version'] = get_kb_item(display_version);
        if(isnull(product_info['display_version']))
          product_info['display_version'] = '';
      }
      var detection_port = PRODUCT_KBS[name]['port'];
      if(detection_port == "")
        product_info['port'] = 0;
      else
      {
        product_info['port'] = get_kb_item(detection_port);
        if(isnull(product_info['port']))
          product_info['port'] = 0;
      }
      var patches_kb = PRODUCT_KBS[name]['patches'];
      if(patches_kb == "")
        product_info['patches'] = '';
      else
      {
        product_info['patches'] = get_kb_item(patches_kb);
        if(isnull(product_info['patches']))
          product_info['patches'] = '';
      }
    }
    else
    {
      if(isnull(port))
        product_info = get_single_install(app_name:name, exit_if_unknown_ver:TRUE);
      else
        product_info = get_single_install(app_name:name, port:port, exit_if_unknown_ver:TRUE);

      if (!empty_or_null(product_info['Model']) && empty_or_null(product_info['model']))
        product_info['model'] = product_info['Model'];
      if (!empty_or_null(product_info['Version']) && empty_or_null(product_info['version']))
        product_info['version'] = product_info['Version'];
    }

    product_info['name'] = name;
    var sdwan_kb = get_kb_item('Host/Cisco/SDWAN/Version');

    if(product_info['name'] == "Cisco Adaptive Security Appliance (ASA) Software")
      product_info['version'] = extract_asa_version(product_info['version']);
      if (isnull(product_info['version'])) audit(AUDIT_FN_FAIL, 'extract_asa_version');
    else if(product_info['name'] == "Cisco Unified Presence" && !isnull(product_info['version']))
      product_info['version'] = str_replace(string:product_info['version'], find:"-", replace:".");
    else if(product_info['name'] == "Cisco IOS XE Software SDWAN" && !isnull(sdwan_kb))
      {
        product_info['sdwan_version'] = sdwan_kb;
        product_info['version'] = sdwan_kb;
      }

    return product_info;
  }

  ##
  # Wrapper around security_report_cisco to unpack array arguments
  # @reporting array of reporting values
  #
  # @return NULL
  ##
  function security_report_cisco_v2(reporting)
  {
    ##
    # Based on security_report_v4, design for Cisco reporting
    #
    # @param port       Report port number
    # @param proto      Sets the reporting protocol, defaults to tcp
    # @param severity   Report severity (note, warning, hole)
    # @param override   override sate for cisco_caveat
    # @param version    Detected device version
    # @param extra      Any extra text to include in the report output (optional)
    # @param bug_id     Cisco Bug ID (optional)
    # @param fix        Fixed version (optional)
    # @param cmds       List of commands used for confirming that the host is vulnerable (optional)
    # @param pie        Missing IOS XR patch (optional)
    # @param sqli       If TRUE, sets SQLInjection KB item
    # @param xss        If TRUE, sets XSS KB item
    # @param xsrf       If TRUE, sets XSRF KB item
    ##
    var port = reporting['port'];
    var proto = reporting['proto'];
    var severity = reporting['severity'];
    var override = reporting['override'];
    var version = reporting['version'];
    var extra = reporting['extra'];
    var bug_id = reporting['bug_id'];
    var fix = reporting['fix'];
    var cmds = reporting['cmds'];
    var pie = reporting['pie'];
    var sqli = reporting['sqli'];
    var xss = reporting['xss'];
    var xsrf = reporting['xsrf'];
    var disable_caveat = reporting['disable_caveat'];


    # Port, severity, version are all mandatory
    if(isnull(port)) port = 0;
    if(isnull(severity)) exit(1, "security_report_cisco_v2(): parameter severity cannot be null");
    if(isnull(version)) exit(1, "security_report_cisco_v2(): parameter version cannot be null");

    security_report_cisco(
      port:port,
      proto:proto,
      severity:severity,
      override:override,
      version:version,
      extra:extra,
      bug_id:bug_id,
      fix:fix,
      cmds:cmds,
      pie:pie,
      sqli:sqli,
      xss:xss,
      xsrf:xsrf,
      disable_caveat:disable_caveat
    );


    return NULL;
  }

  ##
  # Performs the vulnerability checks for Cisco products
  #
  # @param [product_info:array] array      containing the information of the product being scanned. Required
  # @param [vuln_versions:list]      list of vulnerably versions. Required
  # @param [patched_versions:list]   list of patched versions. Can be NULL.
  # @param [workarounds:array]        array of functions to execute for workaround checks
  # @param [workaround_params:array]
  # @param [models:list]             list of affected models. If NULL, all models are assumed to be affected.
  # @param [required_patch:string]     required patch level
  # @param [reporting:array]          array of reporting info to be passed to security_report_cisco()
  # @param [vuln_ranges:list]          list of arrays of vulnerable ranges with min_ver and fix_ver
  # @param [switch_only:boolean]        vulnerability only applies to switches
  # @param [router_only:boolean]        vulnerability only applies to routers
  # @param [smus:array]              an array with version number keys and values that are smu or service pack names as a list or string
  # @param [require_all_workarounds:boolean]        workarounds should be chained by an and instead of an or
  # @param [firepower_hotfixes:array]   an array with releases like 6.5.0, 6.2.3 as keys and values that are also arrays containing keys of hotfix (with value a string like 'Hotfix_DT-6.2.3.16-3') and ver_compare (with value TRUE or FALSE depending on whether "and later" is specified in the advisory for this hotfix.
  #
  # @return NULL
  ##
  function check_and_report(product_info, vuln_versions, patched_versions, workarounds, workaround_params, models, reporting, vuln_ranges, required_patch, switch_only, router_only, smus, require_all_workarounds, firepower_hotfixes)
  {
    if(isnull(product_info)) exit(1, "cisco_vuln_check(): product_info parameter is required");
    if(isnull(product_info['version'])) exit(1, "cisco_vuln_check(): product_info parameter is missing Version");
    if(isnull(vuln_versions) && isnull(vuln_ranges)) exit(1, "cisco_vuln_check(): vuln_versions or vuln_ranges parameter is required");

    var vuln = FALSE;
    var model_is_vuln = FALSE;

    # we are not a router yet this is a router only check
    if(cisco_is_switch() && router_only)
      audit(AUDIT_HOST_NOT, "affected");
    # we are not a switch yet this is a switch only check 
    else if(cisco_is_router() && switch_only)
      audit(AUDIT_HOST_NOT, "affected");

    # If there is a model parameter, need to check if they match. If no model parameter, all models are assumed to be affected
    if(!isnull(models))
    {
      if(product_info['model'] == '')
        exit(1, 'The model of the device could not be determined');
      var vuln_model = '';
      foreach vuln_model (models)
      {
        if(vuln_model == product_info['model'])
        {
          model_is_vuln = TRUE;
          break;
        }
      }
    }

    var version = product_info['version'];
    var patches = product_info['patches'];

    if(isnull(models) || model_is_vuln)
    {
      if(!isnull(vuln_versions))
      {
        var vuln_ver = '';
        foreach vuln_ver (vuln_versions)
        {
          if(vuln_ver == version)
          {
            vuln = TRUE;
            break;
          }
        }
      }
      if(!isnull(vuln_ranges))
      {
        var range;
        foreach range (vuln_ranges)
        {
          if(isnull(range['min_ver']) || isnull(range['fix_ver'])) exit(1, "cisco_check_and_report():"+
              "vuln_ranges is not properly formatted, it must be a list containing 'min_ver' and 'fix_ver'");

          # check if model param has been passed
          if (!empty_or_null(range['model']))
          {
            if (empty_or_null(product_info['model'])) continue;
            var model_match = pregmatch(string:product_info['model'], pattern:range['model']);
            if (empty_or_null(model_match))
            {
              continue;
            }
          }

          # check that the version is greater than or equal to the min ver
          # and less than the fixed version
          if( cisco_gen_ver_compare(a:version, b:range['min_ver']) >= 0 &&
              cisco_gen_ver_compare(a:version, b:range['fix_ver']) < 0
            )
          {
            vuln = TRUE;
            if (isnull(reporting['fix'])) reporting['fix'] = range['fix_ver'];
            break;
          }
          # if required patch passed and version equals fix_ver, check patches
          else if (!empty_or_null(required_patch) &&
            cisco_gen_ver_compare(a:version, b:range['fix_ver']) == 0)
          {
            var patch_missing = TRUE;
            var patch = '';
            patches = split(product_info['patches'], sep:', ', keep:FALSE);

            foreach patch (patches)
            {
              patch = str_replace(string:patch, find:'"', replace:"");
              if(patch >= required_patch)
              {
                patch_missing = FALSE;
                break;
              }
            }
            if (patch_missing)
            {
              vuln = TRUE;
              break;
            }
          }
        }
      }
    }

    if(vuln)
    {
      # We should check SMU patches here
      if(smus)
      {
        var smu_list= get_kb_item('Host/Cisco/SMU');
        if (isnull(smu_list))
        {
          if (empty_or_null(reporting['extra']))
            reporting['extra'] = 'Note: We were unable to get the SMU list and thus SMU testing was disabled.';
          else
            reporting['extra'] += 'Note: We were unable to get the SMU list and thus SMU testing was disabled.';
        }

        var smu = smus[version];
        if (!empty_or_null(smu) && is_list(smu))
        {
          var one_smu;
          foreach one_smu (smu)
            if (one_smu >< smu_list)
              audit(AUDIT_HOST_NOT, 'affected');
        }
        else if (!empty_or_null(smu) && (smu >< smu_list))
        {
          audit(AUDIT_HOST_NOT, "affected");
        }
      }

      # Check for Firepower hotfixes here
      if (firepower_hotfixes)
      {
        var release_ver = pregmatch(string:version, pattern:"^((?:[0-9]+\.){2}[0-9]+)");
        if (!empty_or_null(release_ver))
        {
          release_ver = release_ver[1];
          var hotfix = firepower_hotfixes[release_ver];
          # If "and later" isn't specified in the advisory for this hotfix, search for the hotfix in the output of rpm -qa --last
          if (!hotfix['ver_compare'])
          {
            if (!empty_or_null(hotfix['hotfix']) && hotfix['hotfix'] >< get_kb_item("Host/Cisco/FTD_CLI/1/rpm -qa --last"))
              audit(AUDIT_HOST_NOT, 'vulnerable as a relevant hotfix has been applied');
          }
          # Otherwise, "and later" is present so compare hotfix versions
          else
          {
            var fixed_hotfix_version = pregmatch(string:hotfix['hotfix'], pattern:"Hotfix_[A-Za-z]+-(.*)");
            if (!empty_or_null(fixed_hotfix_version))
            {
              fixed_hotfix_version = fixed_hotfix_version[1];
              fixed_hotfix_version = ereg_replace(string:fixed_hotfix_version, pattern:'-', replace:'.');
              var installed_hotfixes = get_kb_item('Host/Cisco/FTD_CLI/1/hotfix_versions');
              var hotfix_version;
              foreach hotfix_version (split(installed_hotfixes, sep:',', keep:FALSE))
              {
                hotfix_version = ereg_replace(string:hotfix_version, pattern:'-', replace:'.');

                if (ver_compare(ver:hotfix_version, fix:fixed_hotfix_version, strict:FALSE) >= 0)
                  audit(AUDIT_HOST_NOT, 'vulnerable as a relevant hotfix has been applied');
              }
            }
          }
        }
      }

      var result = make_array('flag', vuln, 'override', 0);

      if(get_kb_item('Host/local_checks_enabled'))
      {
        foreach var workaround (workarounds)
        {
          result = workaround(workaround_params);
          # If require_all_workarounds is set to TRUE, chain workarounds with an and. In other words, if even one
          # workaround comes back with a not vulnerable configuration, the host is not vulnerable.
          if (require_all_workarounds)
          {
            if(!result['flag'] && !result['override']) break;
          }
          # By default, workarounds are considered chained by an or
          # Meaning if one workaround comes back with a vulnerable config the host is vulnerable.
          # We do not treat override as a break condition
          else
          {
            if(result['flag'] && !result['override']) break;
          }
        }
        if(!result['flag'] && !result['override']) audit(AUDIT_OS_CONF_NOT_VULN, product_info['name'], version);
      }
      else
      {
        reporting['cmds'] = NULL;
      }

      reporting['override'] = result['override'];
      security_report_cisco_v2(reporting:reporting);
      exit(0);
    }
    else
    {
      audit(AUDIT_HOST_NOT, "affected");
    }
  }

}

##
# Compare line card from show platform KB
##
function cisco_line_card(card_list)
{
  local_var ret = '';
    
  if (isnull(card_list))
  {
    return ret;
  }

  var buf = get_kb_item('Host/Cisco/IOSXR/line_cards');
  buf = split(buf, sep:",", keep:FALSE);

  if (isnull(buf))
  {
    return ret;
  }
    
  foreach var line_card (keys(card_list)) 
  {
    foreach var kb_p (keys(buf)) 
    {
        
      if (tolower(buf[kb_p]) == tolower(card_list[line_card]))
      {
        return 1;
      }
    }
  }
  return ret;
}

