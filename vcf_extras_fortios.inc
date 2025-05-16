#TRUSTED 2f2cb1195a1e409b88b21a2af36e9afc8525924b5d013e270e1d0cd3177bbd5167096e928274b74a6101d5c9ccd00ea0952973d4d46a478441bde605b67be27be44b4c1225db4fe0b87e939795e47f4fe4605eb076f35130e37c16a85e0db26e46b11041ffe6cedb06459c4eaec7e0148e195e4e7fc686cda8478c9dc5ad7cd6f49df23790d2552526abe80705fd8cd9f0e9bf5a8f9b6fd5018169bca7297d121d7e348f9c0b8fed08a61e0d00d5f578f4d5fb344de39fa8e93255e9010081c2464a26ef7d784aab969fe2255ec239eb775fd8f72c8561bb1d84828d056b49bae879b57d91e8bc680f05f279ec2bf6594f1afaad59e28de88236041521e0147756e8d1d87c6130b301245ca4ed98d53174fc809aa76c345aa26a83fe92f430ef8b95d33d8442aa5edaa20683443c3a4fa817402a4505e87e5d9f9836e0767e5d8d866ca60b20bae6b6fe02fa780e669b571332c2c397c802824731f875099e8dea8c3e9c4aa6d7fc071b5fb46a4958eb4042799cb9364899966442c403eb2b61e9a2f2ace756539438ea6023d676423b1c585ca8d9b0eaf1817e5e0af8934d9d42b4ae3d5a41e26074f9f6539372a6415c287a02260c3a98b7d5d34cc751abe353b99d8a23d35d98b41d93d61847b9e11394a921c3193f1d8147114d8b711b2bc9ece9f16af1817e956859cb7b31252b1698d9fc2b50a63a4b73876e66229f73
#TRUST-RSA-SHA256 898fdd77b55eaad3da523d75f31e1d8f81b5d14c80705e8f7b3f54e1d895f5cfd66973f3d8e90d3d119e26d33e74be1a5bf003b57f0a79c4aef73ffcea9eac89bda4c5f7fd38976ae1ffb02cb46a680ca057422bcee3bc4e681b7c44748a492009391f1d767f93ab61f717b3772e3a0a465f2c4b17a036dd938798d64dce39539c69d4909c1da44930965b491167dab68e80081714796f8c6e1396f19092122ab4baba5238faca7a358f8f34a06a5c49a8f6255dd23c11ff43fddba5c3dc8f07b6d73c73625ec9ce0bdc95b059280bcff5a61824057feca200f668eedd9600f2646dd770e97e592a670cafb4ef2fa38650c06290cd30ea437b2bf65ba57e24d24900fd1476053bff147f6c3b8573ab94d4a54a2d2f52971b4245fadc8c169c1cc40f50859356d24e452b433cc811d0fca134b30a8d72dfb3dc5c1a07c6c3f83ad50349476daea061767893a61f0fc45fa846bae6ab73b4d37699150c7c1f7fe42f110d2a153198f36fdb9c4fe070ea0bbd6bdc46477674b916c0d9583c6c448412cf6f137084206f3459dc808e68a982357408f16623b395608d909c7aa498a4541d9cf05864be188c9aef8b203fccb3554015805d6c9ff427241159a9c5391b2b5d0f23142201e5979aa7b2da4ee0aeacc3eadbc664598bd408e3ea034ac775694953ae509ca995957b00933034162782070a11cf459f42d9ea3934808f53cc
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_fortios.inc
#
# Revision: 1.23

include('compat_shared.inc');
include('ssh_globals.inc');
include('ssh_func.inc');
include('hostlevel_funcs.inc');
include('vcf.inc');
include('debug.inc');

namespace vcf
{
  ##
  # Global Detection Variables based on forti types to be detected
  #
  # If new versions are found, add to the appropriate variable.
  #
  # Forti products are experimenting with two or three letter prefixes with the Fortigate series, 
  # and will likely start doing so for the other forti products shortly. 
  #
  # Additionally, some products like Fortigate could be referred to as 'FortiOs' or 'Original FortiOS'
  ##

  var FORTIGATE = "fortigate|fg-|fortios|fortiwifi";
  var FORTIWEB = "fortiweb";
  var FORTIMANAGER = "fortimanager";
  var FORTIANALYZER = "fortianalyzer";
  var FORTIPROXY = "fortiproxy";

  namespace fortios
  {
    ##
    # Checks a fortiOS configuration based on several factors
    # WARNING: Passing untrusted input to this function may result in unexpected command execution
    #
    # @param test_array    array array of config commands to run and config_value to check for.
    # @param regex         bool that determines whether or not to run full regex on the check
    # @param all_required  bool that determines whether or not the configuration needs all conditions.
    # @param not_equal     bool that determines whether or not to use >< or >!< for config value.	   
    ##

    function fortiOS_config_check (app_info, test_array, show_check, regex, all_required, not_equal, severity, flags, config_optional)
    {
      local_var test, tester, config_command_formatted, buf, report, port, returned_results, buffer_list, admin_readonly, entry, usecase_found, key, line, sign_of_life, line_never_found;
      port = 0;
      report = '';
      buffer_list = make_array();
      admin_readonly = FALSE;

      foreach (test in test_array)
      {
        config_command_formatted = str_replace(string:test.config_command,find:" ", replace:"_");
        if (test.misc_cmd)
          config_command_formatted = 'cmd_' + config_command_formatted;
        buf = get_kb_item('Secret/Host/Fortigate/'+ config_command_formatted);
        admin_readonly = get_kb_item('Secret/Host/Fortigate/admin_readonly');
        if (empty_or_null(buf))
        {
          dbg::log(src:SCRIPT_NAME ,msg:'KB entry for Secret/Host/Fortigate/' + config_command_formatted + 'was not found. Checking Host');
  
          if (!get_kb_item("Host/local_checks_enabled")) ::audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
          if ( islocalhost())
          {
            if ( ! defined_func('pread') ) ::audit(AUDIT_FN_UNDEF, 'pread');
            info_t = INFO_LOCAL;
          }
          else
          { 
            sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
            if (! sock_g) ::audit(AUDIT_SOCK_FAIL, app_info.port, 'SSH');
            info_t = INFO_SSH;
          }
          if (empty_or_null(admin_readonly))
          {
            dbg::log(src:SCRIPT_NAME ,msg:'Setting Admin_Readonly');
            buf = ssh_cmd(cmd: 'show full-configuration | grep admin_readonly', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
            if ('admin_readonly' >< buf)
            {
              admin_readonly = TRUE;
              dbg::log(src:SCRIPT_NAME ,msg:'Admin_Readonly Found');
            }
            else
            {
              admin_readonly = FALSE;
              dbg::log(src:SCRIPT_NAME ,msg:'Admin_Readonly Not Found');
            }
            set_kb_item(name: 'Secret/Host/Fortigate/admin_readonly', value:admin_readonly);
          }
          if (test.misc_cmd)
            buf = ssh_cmd(cmd:test.config_command , nosh:TRUE, nosudo:TRUE, noexec:TRUE);
          else
            buf = ssh_cmd(cmd:'show '+ test.config_command , nosh:TRUE, nosudo:TRUE, noexec:TRUE);
          # misc_cmd commands should never check global config
          if (!test.misc_cmd)
          {
            # For the sake of liability, NEVER run this check without confirming admin_readonly.
            if (show_check >!< buf && admin_readonly)
            {
              dbg::log(src:SCRIPT_NAME ,msg:'Show Check not found, doing config dive (*IF ADMIN READONLY WASNT CONFIRMED SOMETHING WENT HORRIBLY WRONG*)');
              buf = ssh_cmd(cmd: 'config global', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
              buf = ssh_cmd(cmd: 'show '+ test.config_command , nosh:TRUE, nosudo:TRUE, noexec:TRUE);  
              dbg::log(src:SCRIPT_NAME ,msg:'Config was pulled for ' + test.config_command + ' using an admin_readonly command for safety sake.');
            }
            else
              dbg::log(src:SCRIPT_NAME ,msg:'Config was not pulled for ' + test.config_command + ' as admin_readonly could not be confirmed.');
          }
          if (info_t == INFO_SSH) ssh_close_connection();
          {
            set_kb_item(name: 'Secret/Host/Fortigate/' + config_command_formatted, value:buf);
            dbg::log(src:SCRIPT_NAME ,msg:'Secret item Secret/Host/Fortigate/' + config_command_formatted +' was set');
          }
        }
        if (empty_or_null(buffer_list[config_command_formatted]))
        {
          buffer_list[config_command_formatted] = buf;
          dbg::log(src:SCRIPT_NAME ,msg: config_command_formatted +' was added to buffer');
        }
        else
          dbg::log(src:SCRIPT_NAME ,msg: config_command_formatted +' was already found in buffer');
      }
      #If a non-existant config indicates that it is not vuln, we check to see if we got director missing / non existant codes or anything at all in return.
      if (config_optional)
      {
        sign_of_life = TRUE;
        if (!empty_or_null(buffer_list)) 
        {
          foreach(buf in buffer_list)
          {
            if ('Return code -6' >!< buf && 'Return code -16'  >!< buf) 
            {
              #If we have a buffer and no error, we bail on loop because it's clear we have settings to check.
              sign_of_life = TRUE;
              break;
            }
            else sign_of_life = FALSE;
          }
        }
        else sign_of_life = FALSE;
        if (sign_of_life == FALSE) return FALSE;
      }
      #After collecting all scans, we see if we find any signs of life with showcheck
      sign_of_life = FALSE;
      if (!empty_or_null(buffer_list))
      {
        foreach(buf in buffer_list)
        {
          if (show_check >< buf) 
          {
            sign_of_life = TRUE;
            break;
          }
        }
      }
      if (!sign_of_life)
      {
        if (admin_readonly == TRUE)
        {
          report +=
          '\n  Nessus could not confirm system interface config\n'
          +'  Please ensure the policy settings are correct,\n'
          +'  Including the new "Automatically accept detected SSH disclaimer prompts"\n\n'
          +'  Configuration scan aborted as the appropriate configuration groups was not visible to Nessus.';
        }
        else
        {
          report +=
          'Check halted due to inability to access configuration via show command,\n'+
          'And FortiOS account in use by Nessus not in admin_readonly mode.\n'+
          '\n'+
          'Ensure that either that the \'show\' command can be viewed by the Nessus FortiOS account\n,'+
          'Or set admin_readonly for the Nessus FortiOS account to ensure safe and secure access to your data.';
        }
        fortiOS_config_report(app_info:app_info, report:report, severity:severity, flags:flags);
      }
      foreach (tester in test_array)
      {
        usecase_found = FALSE;
        config_command_formatted = str_replace(string:tester.config_command,find:" ", replace:"_");
        if (tester.misc_cmd)
          config_command_formatted = 'cmd_' + config_command_formatted;
        buf = get_kb_item('Secret/Host/Fortigate/'+ config_command_formatted);
        if (empty_or_null(buf)) # If the config doesn't exist at all, it should be ignored
          continue;
        if (regex)
        {
          if (!not_equal && !empty_or_null(pregmatch(string:buf, pattern:tester.config_value, multiline:TRUE)) 
            || not_equal && empty_or_null(pregmatch(string:buf, pattern:tester.config_value)))
          {
            usecase_found = TRUE;
            dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' found, setting next step true.');
          }
        }
        else
        {
          if ((not_equal == FALSE && tester.config_value >< buf) || (not_equal == TRUE && tester.config_value >!< buf))
          {
            usecase_found = TRUE;
            dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' found, setting next step true.');
          }
        }
        if (usecase_found)
        {
          if (!all_required) 
	        {
            dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' condition met. Not All Required. Not Equal was set to:' + not_equal);
            return TRUE;
          }
        }
        else if (all_required) 
        {
          dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' fail condition met. All Required. Not Equal was set to:' + not_equal);
          return FALSE;
        }
      }
    if (all_required)
      { 
        dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ config_command_formatted + ' condition met. All Required. Not Equal was set to:' + not_equal);
        return TRUE;
      }
    dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ config_command_formatted + ' condition not met. Not All Required. Not Equal was set to:' + not_equal);
    return FALSE;
    }
      ##
      # Reports a configuration based failure relating to FortiOS, so version is currently not included.
      #
      # @param app_info    array containing application info
      # @param report      string consisting config report generated by fortiOS_config_check
      # @param severity    severity used in reporting
      # @param flags       array of reporting flags (xss, sqli, xsrf)
      #
      # @remark This function exits.
      ##

    function fortiOS_config_report(app_info, report, severity, flags)
    {
      local_var version, port;
      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(report)) return arg_error(arg:"report", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      port = app_info.port;
      if (isnull(port)) port = 0;

      security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      return vcf_exit(0);
    }

      ##
      # Checks a FortiOS app_info array version/build and reports results
      #
      # @param app_info          array containing application info
      # @param constraints       list of constraint arrays
      # @param severity          severity used in reporting
      # @param strict            bool that determines whether or not version/fix should
      #                          require the same number of fields
      # @param flags             array of reporting flags (xss, sqli, xsrf)
      #    
      # @param vuln_settings     array of vulnerable configs to check (after passing version check)
      # @param workarounds       array of workarounds to check for (after failing version check)
      #    
      # @param show_check        string the is checked against ot confirm proper config read if not checked against full-configuration
      # @param report            string that included additional item to add to any fail report,
      #                          describing vuln settings that either does or could exist.
      #    
      # @param regex             bool that determines whether or not to run full regex on the check
      # @param all_required      bool that determines whether or not the configuration needs all conditions.
      # @param not_equal         bool that determines whether or not to use >< or >!< for config value.
      # @param config_optional   bool that determines if no configuration matches is acceptable.
      #
      # @remark This function exits.
      ##
    function check_version_and_report(app_info, severity, constraints, workarounds, vuln_settings, show_check, report, regex, all_required, not_equal, strict, config_optional, check_config, flags)
    {
      local_var matching_constraint, workaround_check, vuln_config_check;
      local_var fix = '';
      if (empty_or_null(check_config['config_paranoid'])) check_config['config_paranoid'] = FALSE; # Will begin moving over all other setting in larger ticket
      if (empty_or_null(regex)) regex = FALSE;
      if (empty_or_null(all_required)) all_required = FALSE;
      if (empty_or_null(not_equal)) not_equal = FALSE;
      if (empty_or_null(report)) report = "";
      if (empty_or_null(config_optional)) config_optional = FALSE;
      if (empty_or_null(show_check)) show_check = "config system";
      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      var isSNMP = FALSE;
      if ('SNMP' >< get_kb_item('Host/Fortigate/system_status_source'))
        isSNMP = TRUE;
      if (!isSNMP)
      {
        if(empty_or_null(matching_constraint))
        {
          if (!empty_or_null(vuln_settings) && check_config['config_paranoid'] && report_paranoia < 2) ::audit (AUDIT_PARANOID);
  
          if(!empty_or_null(vuln_settings)) 
          {
            vuln_config_check = vcf::fortios::fortiOS_config_check(app_info:app_info, test_array:vuln_settings, show_check: show_check, regex:regex, all_required:all_required, not_equal:not_equal, severity:severity, config_optional: config_optional, flags:flags); 
	          if (vuln_config_check == TRUE)
              fortiOS_config_report(app_info:app_info, report:report, severity:severity, flags:flags);
          }
          ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app);
        }
      }
      if (is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);
      if(!empty_or_null(matching_constraint.fixed_display))
        fix = matching_constraint.fixed_display;
      else
        fix = matching_constraint.fixed_version;
      if (!empty_or_null(matching_constraint.fixed_build) &&
        !empty_or_null(matching_constraint.max_version) &&
        vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict) == 0)
      {
        if (empty_or_null(app_info.build) && report_paranoia < 2) vcf::vcf_exit(1, 'Unable to determine FortiOS build.');
        ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app);
      }
      if(!empty_or_null(workarounds) && !isSNMP)
      {
          workaround_check = vcf::fortios::fortiOS_config_check(app_info:app_info, test_array:workarounds, show_check: show_check, regex:regex, all_required:all_required, not_equal:not_equal, severity:severity, config_optional: config_optional, flags:flags);
          if (workaround_check == TRUE)   ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app);
      }
      vcf::report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity, flags:flags);
    }

    ##
    # Check if the model indicates type of forti machines and any model checks as needed.
    #
    # This is a advanced version of the work originally done by Ben Smith under the now depreciated Verify_Model function
    #
    # But forces a declaration of Fortitype which is then confirmed based on regex at the top of this include.
    # This function does not return a value, but audits if the model doesn't check out.
    #
    # @param product_name specifies fortiproduct check is for. Should be passed in as the app.info value, there is no default to ensure proper target info. 
    # @param check_model  defaults to fortigate, but specify model you're looking for if it's something else
    # @param model_kb     kb that holds the model, defaults for fortigate
    #
    # @return value of next segment (string)
    ##

    function verify_product_and_model(product_name, model_check, model_kb)
    {
      # This may change in future and may need to be adjusted slightly with future detection.
      if (empty_or_null(product_name)) ::audit(1,"Empty Forti Product Declaration");
      if (empty_or_null(model_check)) model_check = NULL;
      if (empty_or_null(model_kb)) model_kb = "Host/Fortigate/model"; 
      var product_model = get_kb_item_or_exit(model_kb);
      var product_type = get_product_pattern(product:product_name);

      # Run first and seperately, as devices can be configured in other flavors of forti.
      var audit_str;
      if (!preg(string:product_model, pattern:product_type, icase:TRUE)) 
      {
        if (TAP) return vcf::vcf_exit(0);
        audit_str = 'a ' + product_name + ' product';
        ::audit(AUDIT_HOST_NOT, audit_str);
      }
      
      # checks the hardware if needed
      if (!isnull(model_check))
      {
        if (!preg(string:product_model, pattern:model_check, icase:TRUE))
        {
          if (TAP) return vcf::vcf_exit(0);
          audit_str = 'a ' + model_check + ' model';
          ::audit(AUDIT_HOST_NOT, audit_str);
        }
      }
    }

    function get_product_pattern(product)
    { 
      if ('fortiweb' >< tolower(product))
        return FORTIWEB;
      else if ('fortigate' >< tolower(product) || 'fortios' >< tolower(product)) # two are used interchangably by forti.
        return FORTIGATE;
      else if ('fortimanager' >< tolower(product))
        return FORTIMANAGER;
      else if ('fortianalyzer' >< tolower(product))
        return FORTIANALYZER;
      else if ('fortiproxy' >< tolower(product))
        return FORTIPROXY;
      else
        ::audit(1,"Unknown Forti Product Declaration");
    }
  }
}
