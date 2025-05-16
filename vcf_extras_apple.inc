#TRUSTED 46057782c656613f5b6cc871c40ab6832b4b4e40e90e2cdf5cf66fce8691b3ad63568b0dafc6aacc54777add1d3273b7d98339781d6c05cb230f04061de6903b63b03a9ef357b6f6f2693d81b6e6cf6fb62699a7dbe878ef4810fe932dacdc9e4350fd7ed31f8f22f402abf459e9a2966d1cf05fcf9753ac4d07b909450c37c3a1baf3ef54502924a0a7f2a8341c4f22875114ad4256d968398438a10b198f0dcf74717bd7b57d26faaf788696f245f07f8083226532ad00dfb60293ecf53533bb70b64d344c51072792a9ebabfce8f290c20660d299adc16b3df797d0372c09c4b3e3afdedbbbdbaa1841763a5b49e3089bdaf449fb5f1bc2dc79623114bfa9fdcea9df2bec9fd5becf6227f355434d1c9f0a3fc885fe50942f688012dacfc80cf078571c61596862e12ef5f426b90140ffcd8aebbef8cb44bf027c7a37693cdbc137990c261008fddf5c12d65b4279c91f9b1d202428c3ee4b1221d12dd0186c31d7d72cf26b434d8506abc9ca588a39a331277f3d8cce3d6b25f80e3db2ee11ad3a9a09f5533445fa1ea3b7be17d232b036399802a439f34ddc3d7829b60c8322e7ba8ad72d12a934c237c623db7c55bec9e05d2695f8a83391534d3a1ee18bb22f805ed3d0ccedd1e7b57317d3bd16e031a7303afbff953aa3eca23fd8521bd3559a35dc089d007bab447af05d8159fe575282fe32df725840fe183122cf
#TRUST-RSA-SHA256 5d1badc501d8a005c329997530bb626402226f2c90dab908f6477b610429a74fa135a5900e7bd1f82076fa26e190eb5dac9fb0c84d437750550ca81bb81448348ee8593a61451684b4a43bedb7caa5893c402b63ff6a9a72b8ace675bb6fa08ab374c850b1d9b4acde27589141a42dbeacf924ce4bf24861e097e4a93e5431a11e33ef1a525211727871db227fdb53b38f17d03a655162d2eaa5620c161a4cdaa7396f6d9e8effc589833bfbfc2cd881c5e323777c116f30596976ac8eb96a040f1a06215d0f25ec90bbd7faa56a4614afe58711f6218afeb2b4a35f4c6590348aae7d27e922a64a59b825d823bbf92623033e9220e031705ee908aee964f1732dd9dce37c7502c6c761bb9ec869c206723ad46f230b4a119a6cf7ed2669e6948c1ec0ce49216caf9a01c061accd30c137559457f74fce7d20c594e94b1c331f8edc7313eed38d5c4823f9fb64f5399f7fc7951f74674d637193b29487d8c07e8c3a42cf812c3a82aaf60085849d607618553211f5c90acab75b8d26f06241f39e94b8ca25dd6a66f1e9d8e75666e2a10b3e629270c65bf7c796e8c1f870b66af5f04989d66ee8d007e0c116676d5f3685ee480c7324479315ca0c8c35acc3f3c1dbf2cd35b4a2c69276955f3256f66262a64d72656b360b1554a177beee1c4a1ce81d016afbf0339f888955002e0ba4e883478bcaf1651b5a2d50211242f096
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_apple.inc
#
# Revision: 1.4
###

include("compat_shared.inc");
include("lists.inc");
include("vcf.inc");

namespace vcf
{
  namespace apple
  {
    ##
    # Get info for Apple Safari
    # @return [array] an app_info array for Apple Safari
    ##
    function get_safari_info()
    {
      local_var app_info = {"app" : "Safari"};

      get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
      app_info.path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
      app_info.version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);
      app_info.parsed_version = parse_version(app_info.version);

      return app_info;
    }

    ##
    # Get info for macOS or OS X
    # @return [array] an app_info array for macOS
    ##
    function get_macos_info()
    {
      var os, c, matches, version, cpe;
      os = get_kb_item("Host/MacOSX/Version");
      if (!os)
      {
        os = get_kb_item_or_exit("Host/OS");
        if ("Mac OS X" >!< os) ::audit(AUDIT_OS_NOT, "macOS / Mac OS X");

        c = get_kb_item("Host/OS/Confidence");
        if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
      }
      if (!os) ::audit(AUDIT_OS_NOT, "macOS / Mac OS X");

      matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
      if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

      version = matches[1];

      cpe = "cpe:2.3:o:apple:macos";
      if("Server" >< os)
        cpe += "_server";

      return { "version":version, "parsed_version":parse_version(version), "cpe/v23":cpe };
    }

    ##
    # Check if the macOS version of the host meets the required version
    #
    # @param [restrictions:list]  a list of macOS version that the host is required to be
    # @remark
    # This assumes OS version values have 2 or 3 segments. Another other amount
    #         of segments will raise an error.
    ##
    function check_macos_restrictions(restrictions)
    {
      local_var restriction, tmp, upper_bound;
      local_var os = get_macos_info();
      local_var constraints = {};
      local_var i = 0;

      foreach restriction (restrictions)
      {
        # Build fixed_version (used to set upper bounds for the constraint)
        tmp = parse_version(restriction);
        upper_bound = string(tmp[0][0]) + "." + string(int(tmp[0][1]) + 1);

        # Add constraint
        constraints[i++] = { min_version : restriction, fixed_version : upper_bound};
      }

      if (!check_version(version:os.parsed_version, constraints:constraints))
        return vcf_exit(0, "The remote host's OS (macOS " + os.version +
                           ") is not an affected macOS / Mac OS X version (" +
                           join(restrictions, sep:", ") + ").");
    }

    ##
    # Converts apple builds to easy to compare versions
    #
    # @anonparam [1st:string] a string matching a build pattern
    # @return [string] a converted version string or '0'
    # @remark
    # Builds look like '17G8037' and '18G103'
    ##
    function parse_build()
    {
      local_var matches;

      if (!isnull(_FCT_ANON_ARGS[0]))
      {
        matches = pregmatch(string:_FCT_ANON_ARGS[0], pattern:"^([0-9]+)([A-Z])([0-9]+)");
        if (!isnull(matches))
          return matches[1] + '.' + ord(matches[2]) + '.' + matches[3];
      }
      return '0';
    }

    ##
    # Extracts a single letter 'extra version' from Apple product info.
    #
    # @return [string] An extra version.
    #
    # @remark
    #   This function exits on error.
    ##
    function parse_extra_version()
    {
      var matches = pregmatch(string:tolower(_FCT_ANON_ARGS[0]), pattern:"^\(([a-z])\)$");
      if (!empty_or_null(matches))
        return ord(matches[1]);
      vcf::vcf_exit(1, 'Unexpected extra version format: ' + _FCT_ANON_ARGS[0]);
    }

    namespace macos
    {
      ##
      # Builds app_info for macOS & Mac OS X
      # @return [array] an array containing application info
      ##
      function get_app_info()
      {
        local_var app_info, pbuild, boms, sec_bom, matches;
        local_var eff_build = '';
        # get_macos_info() returns an array or exits
        app_info = vcf::apple::get_macos_info();
        app_info.app = 'macOS / Mac OS X';
        app_info.extra_version = get_kb_item('Host/MacOSX/ProductExtraVersion');
        if (!empty_or_null(app_info.extra_version))
          app_info.display_version = app_info.version + ' ' + app_info.extra_version;

        pbuild = get_kb_item("Host/MacOSX/ProductBuildVersion");
        boms = split(get_kb_item("Host/MacOSX/packages/boms"));

        if (!empty_or_null(pbuild))
        {
          app_info.build = pbuild;
        }
        else if (!empty_or_null(boms) && max_index(boms) > 0)
        {
          foreach sec_bom (collib::filter(boms, f: function () { return _FCT_ANON_ARGS[0] =~ "^com\.apple\.pkg\.update\.(security\.|os\.SecUpd|os\.[0-9.]+?Supplemental).*bom$"; }))
          {
            matches = pregmatch(string:sec_bom, pattern:"([0-9]+[A-Z][0-9]+)\.bom$");
            if (!isnull(matches) && !isnull(matches[1]))
              if (ver_compare(ver: vcf::apple::parse_build(eff_build), fix: vcf::apple::parse_build(matches[1]), strict:FALSE) < 0)
                eff_build = matches[1];
          }
          if (!empty_or_null(eff_build))
            app_info.build = eff_build;
        }
        return app_info;
      }

      ##
      # Checks a macOS or Mac OS X app_info array version/build and reports results
      #
      # @param [app_info:array]   array containing application info
      # @param [constraints:list] list of constraint arrays
      # @param [severity:int]     severity used in reporting
      # @param [strict:boolean]   bool that determines whether or not version/fix should
      #                           require the same number of fields
      # @param [flags:array]      array of reporting flags (xss, sqli, xsrf)
      #
      # @remark
      # This function exits.
      ##
      function check_version_and_report(app_info, severity, constraints, strict, flags)
      {
        local_var matching_constraint;
        local_var fix = '';

        if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
        if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
        if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

        # One of these are expected:
        # {'min_version': '10.13', 'max_version': '10.13.6', 'fixed_build': '17G8037', 'fixed_display': '10.13.6 Security Update 2019-005' }
        # {'min_version': '10.14', 'max_version': '10.14.6', 'fixed_build': '18G103', 'fixed_display': '10.14.6 Supplemental Update 2' }
        # {'min_version': '10.15', 'fixed_version': '10.15.1' }
        # {'min_version': '13.0', 'max_version': '13.4.1', 'fixed_rsr': '(a)', 'fixed_display': '13.4.1 (a)'}
        matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
        if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

        if(empty_or_null(matching_constraint))
            vcf::audit(app_info);

        if(!empty_or_null(matching_constraint.fixed_display))
          fix = matching_constraint.fixed_display;
        else
          fix = matching_constraint.fixed_version;

        if (!empty_or_null(matching_constraint.fixed_build) &&
            !empty_or_null(matching_constraint.max_version) &&
            ver_compare(ver: app_info.version, fix:matching_constraint.max_version, strict:strict) == 0)
        {
          if (empty_or_null(app_info.build) && report_paranoia < 2)
            vcf::vcf_exit(1, 'Unable to determine macOS / Mac OS X build.');

          if (ver_compare(ver: vcf::apple::parse_build(app_info.build), fix: vcf::apple::parse_build(matching_constraint.fixed_build), strict:FALSE) >= 0)
            vcf::audit(app_info);
        }
        if (!empty_or_null(matching_constraint.fixed_rsr) &&
            !empty_or_null(matching_constraint.max_version) &&
            ver_compare(ver: app_info.version, fix:matching_constraint.max_version, strict:strict) == 0 &&
            !empty_or_null(app_info.extra_version) &&
            parse_extra_version(app_info.extra_version) >= parse_extra_version(matching_constraint.fixed_rsr))
          vcf::audit(app_info);

        vcf::report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity, flags:flags);
      }
    }
  }
}
