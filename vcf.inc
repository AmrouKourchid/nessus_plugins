#TRUSTED 4149b6330926f0dcfdca2a13e8d58bdf4f98ddf5a90c612a944ccd0219fbaedce6a6db7b1885595d9ce0cd777d3416d148968367d53e753ddf024ed443a63eb5fa32961a388c71be7374b325cb99de5eef4a62dfa1be78a557ebdb2e0a886bce57b8f6e5f57ab5a08ebf02f5dad375e0db1d52c5dd9e3eb59d98e7e703ec5b8484d0a644335f86a7d856c871a3b640f87a795deccaaf5ecaafb02aa05dd7b56182296631954caa7dd86b91c8743ce374dfe66da1b4e33af1bdc782396a0c81debc36fd3ee6c5677dbe49b5fdd13cf033a22e4994a03dd30a6aa60c7232d6d85bdfcb668fd69c69a545b0f7e3e98277741fae32b8dafb559e42b9b7446d7cf2d478471b6d8abafe88bd2e09c4fbf3730ca2296c291ac30274593964805f81f09a5d57e0c11eba7579c67b45dce096dc8a2da1c59cb68bc749fc275b6bd7e5925fc0f49c416d8c81ea7157fc49f32a5c4715e2c51a194bb74c1dfa0d0bc51cd5c3d3c34e7f5c240506a660024918b86c48e4dc5005a5ba715a75e034a69f03b74a29da2207b8354141b690a4f9b1a534d79f68b0beea2f211ec9fa1f88aa7b3ae76d2f50a0db1ddac9cf0d9ddeb22b69f10df19c35eb216ea1e7fec050a3587027d1b9979cca4ed8b60e08341e90bfb141e08aa22b97e702446d1f98d6675cbb1334bf6a0b7c11100e371f37537bdd04f5123112fb2b973e99ffb7f4b164b307b5
#TRUST-RSA-SHA256 4a01969609baeec71a710228b1d862b9ef774de15389fc3eff6d351baed9b443bf13400c47e9708d5c42e45d9ac553fa519bf2f5eedbb7d95b97924d07ea927d9375efabd0b4d5d9f3886e0811951631daece37c337372cf836d9c02a3ce9c4b4e22543301f4624988b79663dd63606c931106c7dc1ba01667c93334d6d228d4e7f7ce8c74753a6440d268f11aa5f0807982c80b4d663daeb97ba72212b3396015b24074c862fbd768114512c45709f02cc7fb0ee7f9280fe95007f2d216bf27ef915d8d0ee308ccacdc133f521c1414cfce6c82dbd4934c4d8ddc85fe10d0e44b09b630ab951b3533342460964c06c871bcc642b38597a7969541b957d78b6626e763d96c4247c6e410a621ac68e9d361229aac0387d692c9b4c76bdc2611d29a6a4d285b40b5d1b2b801dd5cbf3405a51106c046bcd447f8f627bbf3086c2ab67f7a8dbe85da2f900d38f0d6b84855d84f21697a8804c6a044c0ed5fb6854bcb72ccb6a9a0621eb02cee4714407631de92bcd02234a6e315977596c36b37e923e20595a3d88c8035959d49426db2e03ebc5125078b395173dcefd37c03f119bd2251fbd08a7c8be41bcdd1e3e5c55c52fd282cc9e1ffa3a773273984cd1179099a83317083f670b2d071551ef6ff1c961b2e625a0db818a0b787da97dff1b6d757fb2567d1b68883674ab4904e70d335b74d9d39206251fb53c54d24e9138a
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf.inc
#
# Revision: 1.23
###

include('compat_shared.inc');
include('install_func.inc');
include('hardware_registration.inc');
include('structured_data.inc');

namespace vcf
{
  var TAP = 0;
  var DEBUG = 0;
  var AUDIT_CALL_COUNT = 0;

  ##
  # Displays debug message to console if the DEBUG global is TRUE.
  #
  # @anonparam [first:string] The message to display
  ##
  function dbg() { if (vcf::DEBUG) display(_FCT_ANON_ARGS[0] + '\n'); }

  ####################
  # Parser variables #
  ####################

  # Pre-release conversion values
  var conversions = { "rc" : -50, "beta" : -75, "alpha" : -100 };

  ##
  # Add values to the conversion array. This also overwrites existing conversion values.
  #
  # @anonparam [1st:array] array of intended additions
  ##
  function add_conversions() # Pass this an array of intended additions
  {
    local_var conversion, additions;
    additions = _FCT_ANON_ARGS[0];
    foreach conversion (keys(additions))
      conversions[conversion] = additions[conversion];
  }

  # Valid version segment separators
  var separators = ['.'];

  ##
  # Add values to the separators list
  #
  # @anonparam [1st:list] list of separators to include
  ##
  function add_separator() { separators[max_index(separators)] = _FCT_ANON_ARGS[0]; }

  ############################
  # Custom version parser    #
  ############################
  
  var custom_parse_version = NULL;
  var use_custom_parse_version = FALSE;

  ##
  # Sets the custom parsing function
  #
  # @param [func:function]        function reference to set, may also be anonymous
  # @param [use_custom:boolean]   boolean to enable/disable the custom parser,
  #                               defaults to True
  # @return [boolean] result
  ##
  function set_custom_parse_version(func, use_custom)
  {
    if (typeof_ex(func) == 'function')
      vcf::custom_parse_version = func;
    else if (typeof_ex(_FCT_ANON_ARGS[0]) == 'function' && isnull(func))
      vcf::custom_parse_version = _FCT_ANON_ARGS[0];
    else
      return FALSE;

    if (isnull(use_custom) || use_custom == TRUE)
      enable_custom_parse_version();

    return TRUE;
  }

  ##
  # Unsets the custom parsing and disables it
  #
  # @return [boolean] True
  ##
  function unset_custom_parse_version()
  {
    vcf::use_custom_parse_version = FALSE;
    vcf::custom_parse_version = NULL;
    return TRUE;
  }

  ##
  # Enables custom parsing
  #
  # @return [boolean] True
  ##
  function enable_custom_parse_version()
  {
    vcf::use_custom_parse_version = TRUE;
    return TRUE;
  }

  ##
  # Disables custom parsing
  #
  # @return [boolean] True
  ##
  function disable_custom_parse_version()
  {
    vcf::use_custom_parse_version = FALSE;
    return TRUE;
  }
  ##
  # Returns if custom parsing is enabled or disabled
  #
  # @return [boolean] boolean status of custom parsing
  ##
  function check_custom_parse_version()
  {
    return vcf::use_custom_parse_version;
  }

  ##################
  # Error handling #
  ##################
  # NOTE: Top level functions in this framework (those called by plugins) will
  #       exit upon error

  # Used when storing errors in the KB
  # This might limit some back-and-forth with customers in the future
  var ERROR_ID = 0;

  ##
  # Saves the error to the KB. Also calls display() if debugging enabled
  #
  # @anonparam [1st:string] Error message
  ##
  function print_error()
  {
    dbg(_FCT_ANON_ARGS[0]);
    set_kb_item(name:"Errors/" + SCRIPT_NAME + "/" + string(ERROR_ID++), value:_FCT_ANON_ARGS[0]);
  }

  # Dedicated error type
  object Error
  {
    var message = "An unknown error occurred.";
    ##
    # Constructs an error object
    #
    # @anonparam [first:string] The error message.
    ##
    function Error()
    {
      this.message = _FCT_ANON_ARGS[0];
      print_error(message);
    }
  }

  ##
  # Standardized message for a parsing error
  #
  # @param [str:string]   string that caused the error
  # @param [index:string] index being parsed when error occurred
  # @param [msg:string]   additional information
  #
  # @return [object] An error object
  ##
  function parse_error(str, index, msg)
  {
    return new('vcf::Error', 'Error parsing version: "' + str + '" at index: ' + index + ': ' + msg);
  }

  ##
  # Standardized message for a missing or invalid argument
  #
  # @param [arg:string]  The missing or invalid argument
  # @param [func:string] The function the error occurred in
  #
  # @return [object] An Error object
  #
  # @remark
  #  "func" will generally be passed FUNCTION_NAME, which indicates the calling function
  ##
  function arg_error(arg, func)
  {
    return new("vcf::Error", "Missing or invalid '" + arg + "' argument in call to '" + func + "'.");
  }

  ##
  # Determines if the passed variable is an Error
  #
  # @anonparam [1st:object] variable to check
  #
  # @return [boolean] TRUE/FALSE
  ##
  function is_error() { return (typeof_ex(_FCT_ANON_ARGS[0]) == 'vcf::Error'); }

  #####################
  # Primary Functions #
  #####################

  ##
  # Calls both check_version() and report_results()
  #
  # @param [app_info:array]           array containing application info. requires, at minimum, a
  #                                   key/value pair for 'version'
  # @param [constraints:list]         list of constraint arrays
  # @param [severity:int]             severity used in reporting
  # @param [strict:boolean]           bool that determines whether or not version/fix should
  #                                   require the same number of fields
  # @param [flags:array]              array of reporting flags (xss, sqli, xsrf)
  # @param [require_paranoia:boolean] optional bool that, if TRUE, audits rather than flagging if the scan is not
  #                                   paranoid
  # @param [use_returns:boolean]      Flag to indicate being run in a unit test setup, suppresses audits and reports,
  #                                   returns instead
  #
  # @remark
  #   This function exits.
  ##
  function check_version_and_report(app_info, constraints, severity, strict, flags, require_paranoia, use_returns)
  {
    local_var matching_constraint, fix, report_ver;

    if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
    if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
    if (empty_or_null(require_paranoia)) require_paranoia = FALSE;

    matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
    if (is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

    if (!isnull(matching_constraint))
    {
      if ((require_paranoia || matching_constraint.require_paranoia) && report_paranoia < 2)
      {
        if (empty_or_null(app_info.app))
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN';
          else
            ::audit(AUDIT_POTENTIAL_VULN);
        else if (empty_or_null(app_info.version) && empty_or_null(app_info.display_version))
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN: ' + app_info.app;
          else
            ::audit(AUDIT_POTENTIAL_VULN, app_info.app);
        else if (!empty_or_null(app_info.display_version) && !(empty_or_null(app_info.port)))
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.display_version + ', ' + app_info.port;
          else
            ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.display_version, app_info.port);
        else if (!empty_or_null(app_info.version) && !(empty_or_null(app_info.port)))
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.version + ', ' + app_info.port;
          else
            ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.version, app_info.port);
        else if (!empty_or_null(app_info.display_version))
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.display_version;
          else
            ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.display_version);
        else if (!empty_or_null(app_info.version))
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.version;
          else
            ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.version);
        else
          if (use_returns)
            return 'AUDIT_POTENTIAL_VULN';
          else
            ::audit(AUDIT_POTENTIAL_VULN);
      }

      fix = matching_constraint.fixed_display;
      if(isnull(fix))
        fix = matching_constraint.fixed_version;

      if(matching_constraint.cves && typeof_ex(matching_constraint.cves) == "list")
        app_info.cves = matching_constraint.cves;

      report_results(app_info:app_info,
                     fix:fix,
                     fix_version:matching_constraint.fixed_version,
                     severity:severity,
                     flags:flags);
    }
    else if (use_returns)
      return 'AUDIT: target not vuln';
    # Audit
    else
      return vcf::audit(app_info);

    return vcf_exit(0);
  }

  ##
  # like get_app_info but it figures out the win_local and webapp flags for you
  # this is not suitable for services or protocols
  #
  # @param [app:string] An application name.
  #
  # @return [array] Returns an application info array.
  ##
  function combined_get_app_info(app)
  {
    local_var install, win_port, os, parsed_version;

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

    parsed_version = parse_version(install.version);
    if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

    install.parsed_version = parsed_version;

    install.app = app;
    return install;
  }

  ##
  # Obtains information for the given application. If provided with
  # just an app name, get_single_install() will be used. KB paths
  # will override the default behavior.
  #
  # @param [app:string]         application name
  # @param [port:int]           port to check for application with
  # @param [kb_ver:string]      kb path to use to obtain version information
  # @param [kb_backport:string] kb path to use to obtain backport information
  # @param [win_local:boolean]  sets port to 445 after obtaining version info
  # @param [webapp:boolean]     sets a value in app_info to determine path report output later
  # @param [service:boolean]    sets a value in app_info that affects audit messages
  # @param [proto:string]       protocol to use for reporting/audit outputs
  #
  # @return [array] array with relevant application info, typically version
  #         information, path information, a preferred display variant
  #         of the version, etc.
  #
  # @remark
  #   This function can exit when a backported kb path is supplied
  ##
  function get_app_info(app, port, kb_ver, kb_backport, kb_source,  win_local, webapp, service, proto)
  {
    local_var install = {};
    local_var win_port, parsed_version;

    if (isnull(app)) return arg_error(arg:"app", func:FUNCTION_NAME);

    # Check against backported software
    if (!isnull(kb_backport))
    {
      local_var backported = get_kb_item_or_exit(kb_backport, exit_code:1);
      if (report_paranoia < 2 && backported) ::audit(AUDIT_BACKPORT_SERVICE, port, app);
    }

    // If a kb value containing version information is not supplied,
    // default to using get_single_install()
    if (isnull(kb_ver))
    {
      if (port)
      {
        install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
        install.port = port;
      }
      else
      {
        install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
        if (win_local)
        {
          win_port = get_kb_item("SMB/transport");
          if (!win_port) install.port = 445;
          else install.port = win_port;
        }
      }
    }
    else
    {
      install.version = get_kb_item_or_exit(kb_ver);
      if (install.version == UNKNOWN_VER) ::audit(AUDIT_UNKNOWN_APP_VER, app);
      if (port) install.port = port;
    }

    if (kb_source) install.source = get_kb_item_or_exit(kb_source);
    if (webapp) install.webapp = TRUE;
    if (service) install.service = TRUE;
    if (proto) install.proto = proto;

    # Go ahead and parse the app's version here and store it
    parsed_version = parse_version(install.version);
    if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

    install.parsed_version = parsed_version;

    install.app = app;
    return install;
  }

  ##
  # Check that the given version contains the appropriate
  # number of segments. Audit if necessary.
  #
  # @param [app_info:array]   the associated app_info array
  # @param [sig_segments:int] minimum number of segments the version should have
  #
  # @return [NULL] NULL. Exits when appropriate.
  ##
  function check_granularity(app_info, sig_segments)
  {
    if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (isnull(sig_segments)) return arg_error(arg:"sig_segments", func:FUNCTION_NAME);

    local_var num_segments = 0;
    local_var segment;

    # Increment sig_segments to account for default length of pre-release segment
    if (app_info.parsed_version[1][0] == 0) sig_segments++;

    foreach segment (app_info.parsed_version)
      num_segments += max_index(segment);

    if (num_segments < sig_segments)
    {
      if (TAP) return vcf_exit(0);
      else
      {
        if (app_info.port)
          ::audit(AUDIT_VER_NOT_GRANULAR, app_info.app, app_info.port, app_info.version);
        else
          ::audit(AUDIT_VER_NOT_GRANULAR, app_info.app, app_info.version);
      }
    }
  }

  ##
  # Check if the app is managed OR backported and the for the appropriate
  # paranoia level. Audits if necessary.
  # Individual functions for managed or backported are available, this simply calls both.
  #
  # @param [app_info:array] the associated app_info array
  #
  # @return [NULL] NULL. Exits when appropriate.
  ##
  function check_all_backporting(app_info)
  {
    vcf::check_managed(app_info:app_info);
    vcf::check_backported(app_info:app_info);
  }

  ##
  # Check if the app is managed and the for the appropriate
  # paranoia level. Audit if necessary.
  # Use vcf::check_all_backporting() unless you need specificity.
  #
  # @param [app_info:array] the associated app_info array
  #
  # @return [NULL] NULL. Exits when appropriate.
  ##
  function check_managed(app_info)
  {
    if (report_paranoia < 2 && (app_info['Managed'] == 1 || app_info['Managed by OS'] == 'True' || app_info['Method'] == 'Package manager'))
    {
      vcf::audit(app_info, AUDIT_MANAGED_INSTALL);
    }
  }

  ##
  # Check if the app is backported and the for the appropriate
  # paranoia level. Audit if necessary.
  # Use vcf::check_all_backporting() unless you need specificity.
  #
  # @param [app_info:array] the associated app_info array
  #
  # @return [NULL] NULL. Exits when appropriate.
  ##
  function check_backported(app_info)
  {
    if (report_paranoia < 2 && app_info['backported'] == 1)
    {
      vcf::audit(app_info, AUDIT_BACKPORT_SERVICE);
    }
  }


  ##
  # Check if the target is one of the given hardware in the passed list of hardware.
  #
  # @param  [cpes:list]  list of arrays of CPE attributes (e.g. [{ vendor: 'dell', product: 'rx7000' }, { vendor: 'dell', product: 'precision_7910' }])
  #
  # @return [bool] true - if the installed OS matches one of the passed CPEs
  #                false - if the installed OS does not match one of the passed CPEs
  ##
  function check_for_hardware(cpes)
  {
    local_var cpe, hw, i;

    if (empty_or_null(cpes) || typeof_ex(cpes) != 'list')
      return arg_error(arg:'cpes', func:FUNCTION_NAME);
  
    foreach cpe (cpes)
    {
      if (empty_or_null(cpe.category))
        cpe.category = 'system';

      if (empty_or_null(cpe.type))
        cpe.type = 'combined';

      hw = get_hardware_cpe(
        part       : 'h',
        vendor     : cpe.vendor,
        product    : cpe.product,
        version    : cpe.version,
        update     : cpe.update,
        language   : cpe.language,
        sw_edition : cpe.sw_edition,

        category   : cpe.category, 
        type       : cpe.type,

        exit_if_not_found : false
      );
  
      if (!empty_or_null(hw)) return true;
    }
     
    return false;
  }

  #############
  # Reporting #
  #############

  ##
  # Call security_report_v4() with given severity and flags
  #
  # @param [app_info:array]     app info to use in report
  # @param [fix:string]         the fixed version to include in report
  # @param [fix_version:string] the fixed version to include in structured report
  # @param [severity:int]       SECURITY_(NOTE|HOLE|WARNING)
  # @param [flags:int]          xss, xsrf, and sqli
  # @param [webapp:boolean]     converts path to a URL
  ##
  function report_results(app_info, fix, fix_version, severity, flags)
  {
    local_var report, version, port;

    if(isnull(app_info))
      return arg_error(arg:"app_info", func:FUNCTION_NAME);
    if(isnull(fix))
      return arg_error(arg:"fix", func:FUNCTION_NAME);
    if(isnull(severity))
      return arg_error(arg:"severity", func:FUNCTION_NAME);

    if(isnull(app_info.display_version))
      version = app_info.version;
    else version = app_info.display_version;

    port = app_info.port;
    if(isnull(port))
      port = 0;

    report = build_report(version:version,
                          fix:fix,
                          path:app_info.path,
                          source:app_info.source,
                          webapp:app_info.webapp,
                          port:port);

    if(is_error(report))
      return vcf_exit(1, report.message);

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
  # Builds vulnerability reporting structured data object and stores the report.
  #
  # @param [app_info:array]     An array of application info.
  # @param [fix:string]         The fixed version possibly human readable. (optional)
  # @param [fix_version:string] The fixed version as a comparable string. (optional)
  # @param [bulletin:string]    A Microsoft KB Bulletin containing the fix. (optional)
  # @param [port:int]           Fixed up port number for reporting.
  ##
  function store_structured_data(app_info, fix, fix_version, bulletin, port)
  {
    var proto;
    if(!empty_or_null(app_info.proto))
      proto = app_info.proto;
    else
      proto = "tcp";

    var structured_data = new structured_data_vuln_reporting(port, proto);

    var fix_available = FALSE;
    var fixes = [];
    var fix_elem;
    if(!empty_or_null(fix_version) || !empty_or_null(fix) || !empty_or_null(bulletin))
    {
      fix_available = TRUE;
      if(fix_version)
        fix_elem = {"fix_type": "version", "value": fix_version};
      else if(bulletin)
        fix_elem = {"fix_type": "MSKB", "value": bulletin};
      else if(fix)
        fix_elem = {"fix_type": "version", "fix_display": fix};

      if(fix && fix_elem && (fix_version || bulletin))
        fix_elem.fix_display = fix;

      if(fix_elem)
        append_element(var:fixes, value:fix_elem);
    }

    var vuln = {
      "fix_available": fix_available,
      "identifier": app_info["cpe/v23"]
    };

    vuln.all_vulnerabilities = TRUE;
    if(!empty_or_null(app_info.version))
      vuln.version = app_info.version;
    else
      vuln.version = "";

    vuln.fixes = fixes;
    if(!empty_or_null( app_info.path))
      vuln.path = app_info.path;

    if(!empty_or_null(app_info.cves))
    {
      vuln.all_vulnerabilities = FALSE;

      #validate CVEs
      foreach var cve(app_info.cves)
      {
        if(preg(pattern:"^CVE-\d{4}-\d{4,}$", string:cve))
        {
          if(empty_or_null(vuln.vulnerabilities))
            vuln.vulnerabilities = [cve];
          else
            append_element(var:vuln.vulnerabilities, value:cve);
        }
      }
    }

    structured_data.append("vulnerability", vuln);

    #An identifier is the minimal information required to report a vuln (unpatched)
    if(!empty_or_null(app_info) && !empty_or_null(app_info["cpe/v23"]))
      structured_data.report_internal();
  }

  ##
  # Builds the report used in reporting output
  #
  # @param [version:string] reports as "Installed version"
  # @param [path:string]    reports as "Path" or "URL" (dep on webapp flag)
  # @param [fix:string]     reports as "Fixed version"
  # @param [webapp:boolean] TRUE/FALSE (or NULL) to determine path format
  # @param [port:int]       Only used when building URLs
  # @param [source:boolean] reports as "Source"
  #
  # @return [string] The appropriate report string (extra)
  ##
  function build_report(version, path, fix, webapp, port, source)
  {
    local_var order, report, report_items;

    report_items = {
      "Installed version" : version,
      "Fixed version" : fix
    };
    order = ["Installed version", "Fixed version"];

    if (webapp)
    {
      if (isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);
      report_items["URL"] = build_url2(qs:path, port:port);
      order = ["URL", "Installed version", "Fixed version"];
    }
    else if (!empty_or_null(source))
    {
      report_items["Source"] = source;
      order = ["Source", "Installed version", "Fixed version"];
    }
    else if(!empty_or_null(path))
    {
      report_items["Path"] = path;
      order = ["Path", "Installed version", "Fixed version"];
    }

    return report_items_str(report_items:report_items, ordered_fields:order);
  }

  ##
  # Calls the global audit function with the appropriate audit trail
  #
  # @anonparam [1st:array] The app_info variable we're dealing with
  # @anonparam [2nd:int]   The audit type IFF managed or backported
  #
  # @remark
  #    This function exits
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

  ###################################
  # Version checking and comparison #
  ###################################

  ##
  # Used to check whether or not an application
  # version meets any of the given constraints
  #
  # @param [version:string]   version to be checked against constraints (already parsed)
  # @param [constraints:list] a list of constraint arrays
  # @param [strict:boolean]   if set, versions MUST have the same number of fields (segments)
  #
  # @return [list|object|NULL] a matching constraint
  #         Error object
  #         NULL - no matching constraints
  #
  # @remark
  #    Possible constraint values:
  #      min_version - operates as >=
  #      max_version - operates as <=
  #      fixed_version - operates as <
  #      equal - operates as ==. no other checks performed within this same constraint
  #      fixed_display purely a display value and nothing more
  ##
  function check_version(version, constraints, strict)
  {
    local_var meets_constraint, constraint;

    if (isnull(version) || typeof(version) != "array") return arg_error(arg:"version", func:FUNCTION_NAME);
    if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
    if (isnull(strict)) strict = FALSE;

    # [[],[0]] should not be handled as [[0],[0]] and should not match constraint {'min_version':'0.0',...}
    if (max_index(version) < 1 || max_index(version[0]) < 1) return NULL;

    foreach constraint (constraints)
    {
      meets_constraint = check_version_against_constraint(version:version, constraint:constraint, strict:strict);
      if (is_error(meets_constraint)) return meets_constraint;

      if (meets_constraint) return constraint;
    }

    return NULL;
  }

  ##
  # Determines whether or not the provided version falls within the
  # given constraint or not
  #
  # @param [version:string]   Version being checked
  # @param [constraint:array] Array with possible key/values for equal,
  #                           min_version, max_version, fixed_version
  # @param [strict:boolean]   Bool that determines strictness of check
  #
  # @return [boolean|object] TRUE if version within constraint
  #         FALSE otherwise
  #         Error if an error occurred
  ##
  function check_version_against_constraint(version, constraint, strict)
  {
    local_var cmp_result;

    # If an equality check is specified, nothing else is taken
    # into account. Check for an exact match.
    if (constraint.equal)
    {
      return compare_version_to_check(version:version, comparator:'=', cmp_ver:constraint.equal, strict:strict);
    }

    # Check that we meet a minimum version (if specified)
    if (constraint.min_version)
    {
      cmp_result = compare_version_to_check(version:version, comparator:'>=', cmp_ver:constraint.min_version, strict:strict);
      if (is_error(cmp_result)) return cmp_result;

      if (!cmp_result) return FALSE;
    }

    # Check that we don't exceed maximum version (if specified)
    if (constraint.max_version)
      return compare_version_to_check(version:version, comparator:'<=', cmp_ver:constraint.max_version, strict:strict);
    # Check that we're below the fixed version
    else if (constraint.fixed_version)
      return compare_version_to_check(version:version, comparator:'<', cmp_ver:constraint.fixed_version, strict:strict);

    # If we've made it this far, all of the above constraints were met
    return TRUE;
  }

  ##
  # Do comparison and check if given condition is met
  #
  # @param [version:string]    Version being checked (already parsed)
  # @param [comparator:string] Operator being used for comparison (<, <=, >, >=, =)
  # @param [cmp_ver:string]    Version being compared to
  # @param [strict:boolean]    Bool determining strictness of check
  #
  # @return [boolean|object] TRUE/FALSE/Error
  ##
  function compare_version_to_check(version, comparator, cmp_ver, strict)
  {
    local_var comparison_result, i, seg, lengths_differ, pad_result, tmp_v, tmp_c;

    if (isnull(version)) return arg_error(arg:'version', func:FUNCTION_NAME);
    if (isnull(comparator)) return arg_error(arg:'comparator', func:FUNCTION_NAME);
    if (isnull(cmp_ver)) return arg_error(arg:'cmp_ver', func:FUNCTION_NAME);

    cmp_ver = parse_version(cmp_ver);
    if (is_error(cmp_ver)) return cmp_ver;

    lengths_differ = version_lengths_differ(version, cmp_ver);

    # If strict and lengths don't match, constraint is not met
    if (strict && lengths_differ)
      return FALSE;

    # Pad version segments as needed
    if (lengths_differ)
    {
      for (i=0; i<max_index(version); i++)
      {
        tmp_v = version[i];
        tmp_c = cmp_ver[i];

        pad_result = pad_segments(a:tmp_v, b:tmp_c);
        if (is_error(pad_result)) return pad_result;

        version[i] = tmp_v;
        cmp_ver[i] = tmp_c;
      }
    }

    # Compare version segments (release and pre-release segments)
    # in order.
    for (i=0; i<max_index(version); i++)
    {
      for (seg=0; seg<max_index(version[i]); seg++)
      {
        comparison_result = compare_version_segments(version[i][seg], cmp_ver[i][seg]);
        if (comparison_result != 0) break;
      }
      if (comparison_result != 0) break;
    }

    switch (comparator)
    {
      case '=':
        return comparison_result == 0;
      case '<':
        return comparison_result < 0;
      case '>':
        return comparison_result > 0;
      case '<=':
        return comparison_result <= 0;
      case '>=':
        return comparison_result >= 0;
      default:
        return new("vcf::Error", "An invalid comparator '" + comparator + "' was passed to " + FUNCTION_NAME + ".");
    }
  }

  ##
  # Check if the length of the given [parsed] versions differ
  #
  # @anonparam [1st:list] 1st version (parsed)
  # @anonparam [2nd:list] 2nd version (parsed)
  #
  # return [boolean] TRUE/FALSE
  ##
  function version_lengths_differ()
  {
    local_var version_a = _FCT_ANON_ARGS[0];
    local_var version_b = _FCT_ANON_ARGS[1];
    local_var i;

    if (max_index(version_a) != max_index(version_b))
      return TRUE;

    for (i=0; i<max_index(version_a); i++)
    {
      if (max_index(version_a[i]) != max_index(version_b[i]))
        return TRUE;
    }

    return FALSE;
  }

  ##
  # Compare the two version segments
  #
  # @anonparam [1st:string] segment (a)
  # @anonparam [2nd:string] segment (b)
  #
  # @return [int] -1 if a is lower than b; 0 if a is equal to b; 1 if a is higher than b
  ##
  function compare_version_segments()
  {
    local_var version_a = _FCT_ANON_ARGS[0];
    local_var version_b = _FCT_ANON_ARGS[1];

    if (is_alpha(version_a)) version_a = ord(version_a);
    if (is_alpha(version_b)) version_b = ord(version_b);

    if (version_a < version_b)
      return -1;
    else if (version_a > version_b)
      return 1;
    else return 0;
  }

  ###########
  # Parsing #
  ###########

  ##
  # Parses the given version
  # Output format: [[release segments], [pre-release segments]]
  #
  # @anonparam [1st:list]           version to be parsed
  # @param     [use_custom:boolean] manually disables custom version parsing if enabled
  #
  # @return [list] a nested list of version segs in the appropriate output format
  ##
  function parse_version(use_custom)
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var release_segment, pre_release_seg;

    if (empty_or_null(use_custom))
      use_custom = TRUE;

    # Apply custom parser, if appropriate
    if (use_custom && vcf::use_custom_parse_version)
      return vcf::custom_parse_version(check_string);

    check_string = separate_version_segments(check_string);
    release_segment = check_string[0];
    pre_release_seg = check_string[1];

    # Parse release segment
    release_segment = parse_release_segment(release_segment);
    if (is_error(release_segment)) return release_segment;

    # Parse pre-release segment
    if (!empty(pre_release_seg))
    {
      pre_release_seg = parse_pre_release_segments(pre_release_seg);
      if (is_error(pre_release_seg)) return pre_release_seg;
    }
    else pre_release_seg = [0];

    return [release_segment, pre_release_seg];
  }

  ##
  # Split the version into two segments, a release segment and
  # a pre-release segment. This verbiage is taken from the semver spec
  #
  # @anonparam [1st:string] version to be split
  #
  # @return [list] [release_segment, pre_release_segment]
  ##
  function separate_version_segments()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var i, hyphen_index, conversion;

    foreach conversion (keys(conversions))
    {
      i = stridx(check_string, conversion);

      # conversion string not found
      if (i < 1) continue;

      # Many pre-release values are separated with a '-'
      # Account for this when necessary
      if (check_string[i-1] == '-') hyphen_index = i-1;
      else hyphen_index = i;

      # found something, split here
      return [substr(check_string, 0, hyphen_index-1), substr(check_string, i)];
    }

    # No pre-release segment
    return [check_string, ''];
  }

  ##
  # Parse the given release segment
  #
  # @anonparam [1st:string] string to parse
  #
  # @return [list] a list of version segments in the overall release segment
  #                or an error
  ##
  function parse_release_segment()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var segments = [];
    local_var i;

    for (i=0; i<strlen(check_string); i++)
    {
      # Whitespace not allowed in versions. If we see it, error.
      if (is_whitespace(check_string[i]))
        return parse_error(str:check_string, index:i, msg:'invalid whitespace in version string');

      if (is_digit(check_string[i]) || is_alpha(check_string[i]))
        segments[max_index(segments)] = get_next_segment(str:check_string, i:i); # i passed by ref and modified
      else if (is_separator(check_string[i]))
        continue;
      else return parse_error(str:check_string, index:i, msg:"invalid character in version string");
    }

    return segments;
  }

  ##
  # Obtain the next segment
  #
  # @param [str:string] string we're iterating over
  # @param [i:int]      index to start at (passed by reference an modified within this function)
  #
  # @return [string] value of next segment (string)
  ##
  function get_next_segment(str, &i)
  {
    local_var segment = '';

    if (is_digit(str[i]))
    {
      while ( i<strlen(str) && !is_separator(str[i]) && !is_alpha(str[i]) )
        segment += str[i++];
      i--; # We're 1 too far now, move back so we don't skip anything
      segment = int(segment);
    }
    else if (is_alpha(str[i]))
      segment = str[i];

    return segment;
  }

  ##
  # Parse the given pre-release segment
  #
  # @anonparam [1st:string] string to parse
  #
  # @return [list] a list of version segments in the overall pre-release segment
  #         including converted values or an error
  ##
  function parse_pre_release_segments()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var segments = [];
    local_var i, c;

    # We know this segment starts with a value that needs converting
    foreach c (keys(conversions))
    {
      if (c == substr(check_string, 0, strlen(c)-1))
      {
        segments[max_index(segments)] = conversions[c];
        break;
      }
    }

    for (i=strlen(c); i<strlen(check_string); i++)
    {
      # Whitespace not allowed in versions. If we see it, error.
      if (is_whitespace(check_string[i]))
        return parse_error(str:check_string, index:i, msg:'invalid whitespace in version string');

      if (is_digit(check_string[i]) || is_alpha(check_string[i]))
        segments[max_index(segments)] = get_next_segment(str:check_string, i:i); # i passed by ref and modified
      else if (is_separator(check_string[i]))
        continue;
      else return parse_error(str:check_string, index:i, msg:"invalid character in version string");
    }

    return segments;
  }

  ###########
  # Padding #
  ###########

  ##
  # Pad version lists so that they are the same length
  # Pads number segments that precede alpha if necessary
  # Segments are modified via pass-by-ref
  #
  # @param [a:list]   first version list
  # @param [b:list]   second version list
  #
  # @return [NULL|object] NULL or Error
  ##
  function pad_segments(&a, &b)
  {
    local_var i, desired_length;

    # Start from the beginning of each segment and account for padding
    # that is needed between a number portion and letter portion
    for (i=0; (i<max_index(a) && i<max_index(b)); i++)
    {
      if ( (is_number(a[i]) && is_number(b[i])) || (is_alpha(a[i]) && is_alpha(b[i])) )
        continue;
      else if (is_alpha(a[i]))
        insert_element(idx:i, value:0, var:a);
      else if (is_alpha(b[i]))
        insert_element(idx:i, value:0, var:b);
    }

    a = pad_segments_list(segments:a, length:max_index(b));
    b = pad_segments_list(segments:b, length:max_index(a));

    if (max_index(a) != max_index(b))
      return new("vcf::Error", "An error occurred while attempting to pad the version segments.");
  }

  ##
  # Pad end of version segments list with 0s to meet given length
  #
  # @param [segments:list] list of segments to pad
  # @param [length:int]    desired length of list
  #
  # @return [list] list padded with 0s (if necessary)
  ##
  function pad_segments_list(segments, length)
  {
   local_var length_difference = length - max_index(segments);
   local_var i;

    if (length_difference <= 0) return segments;

    for (i = 0; i < length_difference; i++)
      segments[max_index(segments)] = 0;

    return segments;
  }

  ##################
  # Helper / Other #
  ##################

  ##
  # Is the argument a digit?
  #
  # @anonparam [first:string] A potential digit.
  #
  # @return [boolean] Return TRUE if the argument is a digit, FALSE otherwise.
  ##
  function is_digit()
  { return _FCT_ANON_ARGS[0] =~ '^[0-9]$'; }

  ##
  # Is the argument a number?
  #
  # @anonparam [first:string] A potential number.
  #
  # @return [boolean] Return TRUE if the argument is a number, FALSE otherwise.
  ##
  function is_number()
  { return _FCT_ANON_ARGS[0] =~ '^[0-9]+$'; }

  ##
  # Is the argument strictly alphabetical?
  #
  # @anonparam [first:string] A potential alpha string.
  #
  # @return [boolean] Return TRUE if the argument is purely alphabetical, FALSE otherwise.
  ##
  function is_alpha()
  { return _FCT_ANON_ARGS[0] =~ '^[a-zA-Z]$'; }


  ##
  # Is the argument a whitespace character?
  #
  # @anonparam [first:string] A potential whitespace char.
  #
  # @return [boolean] Return TRUE if the argument is whitespace char, FALSE otherwise.
  ##
  function is_whitespace()
  {
    switch (_FCT_ANON_ARGS[0])
    {
      case ' ', '\n', '\t', '\r':
        return TRUE;
      default:
        return FALSE;
    }
  }


  ##
  # Is the argument a version separator character?
  #
  # @anonparam [first:string] A potential version separator char.
  #
  # @return [boolean] Return TRUE if the argument is version separator char, FALSE otherwise.
  ##
  function is_separator()
  {
    local_var separator;
    foreach separator (separators)
      if (_FCT_ANON_ARGS[0] == separator)
        return TRUE;

    return FALSE;
  }

  ##
  # Prevents unwanted exits during unit testing
  #
  # @anonparam [1st:int]    status code
  # @anonparam [2nd:string] message
  #
  # @return [string] string or exits
  ##
  function vcf_exit()
  {
    local_var status_code = _FCT_ANON_ARGS[0];
    local_var message = _FCT_ANON_ARGS[1];

    if (TAP)
    {
      AUDIT_CALL_COUNT = 1;
      if (status_code == 0) return "Exit successful";
      else return "Fatal error";
    }

    exit(status_code, message);
  };
}
