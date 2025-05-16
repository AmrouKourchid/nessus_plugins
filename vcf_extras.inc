#TRUSTED b304a5f598b7c3617a94e3708f1e5921c023516ae891401947fa5a8d88546764258e77670e40d8cfa9a4318a53f639f8d2c8e83e82a7576477e5a32a4e6442b0c0fbfb8097115bd7e414c397ba66f7fabf70ecade01905cf874488fa37367a09a5f8f9b71272b19f12f65491772445db1fc7ef3a227c16842817ce6e492261c7b8e08cec851b20dbb3bde9dd2092870b6e364eb91f6d5f1a53e601f28a4e9b04bf708db409de7e9b506afb90e39912d3686f37af66ce5eea61842f2f53622d3ffe8d64027270009f31fa75df7ac488d714a300261c08f163fa0c85a08699dce1a06cf2ee0bd850b52797fd6cd8d345a0d8f9de1c981dd1f3b5ee0dfb211ce21d642e721cae3b4cff739c396810c287c8269dc3c0a51a7fc2e434340dbe2fa5e64f524c5ecc816a773c22206c82f30f7e7ed767b0e20fd904b6d850c748408b7a0c1ce87b25d40f34f5f287a42b6d995c3c0203b055b6ebc95ad54c4d1feca13e99277e51f9aa8573b4cddb501c058cc5e139cf45e2c65f8d0c95e94cadeaa95311bf54091a575a00e5f7a6365f7946e97e6a9c5336e52f147ae3bc6d591a2a2dc8af92856380a8998da0c5db95370c4637e6b59bd7199352dd171f05f08693a645e63fcac8f02ee8e9ca49380e6b67a8e4b3d0aecbdd6f872d3805d9d8cb8e9c6028aff4057887c52afeeadaebb697d90225cc8fe6fb79c0de432220ae643b55
#TRUST-RSA-SHA256 5a38c838cbc57ace4e9965312e503bc4610a0eb342b0c2d38b0dfb49addacf72bb0b42bec21987a1fce66c7eb0aa2fba2c2e05ec3fea0e92a4182ea2980ef5688edd2db13281a224110d30fbed31d7eed29c0fcbe1fc63119290301bdb1ea1dd5b5891bcdfa5ed73d33238aafcb1abee42134a92136a44423c077b4b96fa94e292b7646e190fd782818d98b9a7d9a8c6eac66ad8e56b81aec3753110ad9695bb3c07c93e08ecffbafffb686342977c65f9c74aa2382d25dd9b645729fabf69a7f6e242ba0a014b92ff72e8ea04a11e6fca2ee913eded30157ac01239f8769eb53d028193a4f123baa26b3f95d0d984012a3e5ad9bf17d1fecd07964c641e508593874cc57ac6119d1e1b2554c5206cbe9418b95532e7b1c66c01efc9f8955d35a3d1ee7fe449dd2c511122ca8b665a5950282d497f3bf45d5e252463daa24b5dbf97b225089e81031a4b0cc94d676e9e98bcff3505ea361274de53e44b84b4216c7a2a8facd8e9bf60cd46602b8ee5aa2b95aa8bc8f0133a8ecf3c030f2c9b92c9dfa03f5c7465276aff5e1ab176a12502bee4f2251febd7a485078acf5411de502519f9359962e099720b9c993c548b4b92c55bf6959f5a3dca9cc94d697cbf6db84f49b82e54445904765c87eb76de4a32f462626928bb21966dd6fd2bf54bb4ad517e3ac1f1081e1c70531be4b84c71b6e1ca3cf8306920530a770dc9b181
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras.inc
#
# Revision: 1.201
###

include('compat_shared.inc');
include('install_func.inc');
include('spad_log_func.inc');
include('webapp_func.inc');
include('vcf.inc');
include('lists.inc');
include('http.inc');
include('debug.inc');
include('string.inc');

namespace vcf
{
  ######################
  # Special Snowflakes #
  ######################
  # Items implemented within this file are due to products/vendors/plugin groups
  # that require special implementations of certain features. These are typically
  # re-implementations of the get_app_info() when detections for certain plugins
  # groups do not store the necessary information in one of the usual ways.
  # The primary purpose of this include is to keep things out of the core vcf
  # library and avoid extra bloat and tacked on functionality that is only used
  # in certain, specific scenarios.

  namespace zyxel_router
  {
      ##
      # Get the absolute value
      #
      # @anonparam [1st:integer] The value to examine
      #
      # @return [integer] The absolute value of ``1st``.
      ##
      function abs()
      {
        if(_FCT_ANON_ARGS[0] > 0) return _FCT_ANON_ARGS[0]; else return - _FCT_ANON_ARGS[0];
      }

      ##
      # Convert version to a '.'-seprated version with letters converted to their numerical value.
      #
      # @param [ver:string] The version string to convert.
      #
      # @return [string] The new version string.
      ##
      function convert_ver(ver)
      {
        local_var new_ver = NULL;
        dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][=> start ][' + obj_rep(ver) + '][strlen(ver)]' + strlen(ver) + ']');

        # copy/pasta logic (w/ slight updates && debugging) from abb::ver_compare_custom in tenable_ot_cve_funcs.inc
        for (var i=0; i<strlen(ver); i++)
        {
          var current_char = toupper(ver[i]);
          dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> current_char ][' + obj_rep(current_char) + ']');

          # If the character is a letter, convert it to its numerical value and append it to the converted string
          if(pregmatch(string:current_char, pattern:"[a-zA-Z]"))
          {
            var converted_value = ord(current_char) - ord('A');
            dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> current_char ][' + obj_rep(current_char) + '][==> current_char_converted ][' + obj_rep(converted_value) + ']');

            # Add a period before and after the converted value if the letter is surrounded by numerical values
            if(i > 0 && i < strlen(ver) - 1 && pregmatch(string:ver[i-1], pattern:"[0-9]") && pregmatch(string: ver[i+1], pattern: "[0-9]"))
            {
              new_ver += "." + converted_value + ".";
            }
            else
            {
              dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> add new_ver ][' + obj_rep(converted_value) + '][new_ver_before][' + new_ver + ']');
              new_ver += converted_value;
              dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> add new_ver ][' + obj_rep(converted_value) + '][new_ver_after][' + new_ver + ']');
              # Add a period after the letter if it's not at the end of the string
              if(i < strlen(ver) - 1)
              {
                dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> add new_ver ][' + obj_rep(converted_value) + '][new_ver_before][' + new_ver + ']');
                new_ver += ".";
                dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> add new_ver ][' + obj_rep(converted_value) + '][new_ver_after][' + new_ver + ']');
              }
            }
          }
          # If the character is a number, append it directly to the converted string
          else
          {
            dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> add new_ver ][' + obj_rep(converted_value) + '][new_ver_before][' + new_ver + ']');
            new_ver += current_char;
            dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> current_char ][' + obj_rep(current_char) + '][new_ver_after][' + new_ver + ']');
          }
        }
        dbg::detailed_log(lvl:3, msg:'[zyxel_router::convert_ver][==> return new_ver ][' + obj_rep(new_ver) + '][return new_ver]');

        return new_ver;
      }

      ##
      # Convert version to a '.'-seprated version with letters converted to their numerical value.
      #
      # @param [ver:string] The version string to convert.
      #
      # @return [string] The new version string.
      #
      # @remark
      # This function is exclusively for versions that have format ``^V(\d+\.\d+)\([A-Za-z]+\.[0-9]+\)[A-Za-z][0-9]+$``
      # (e.g. V1.00(ABZE.1)b1) replace char A with a numeric equivalent (e.g. ord('A')-ord('A') = V1.00(ABZE.1)b1).
      ##
      function transform_ver(firmware)
      {
        dbg::detailed_log(lvl:1, msg:'[zyxel_router::transform_ver][START][firmware][' + firmware + ']');

        # if it's some other format/structure, we'll need investigate it via customer feedback
        local_var regex = "^V\d+\.\d+(\([A-Za-z]+\.[0-9]+\))[A-Za-z]+[0-9]+$";

        if( firmware =~ regex )
        {

          firmware = ereg_replace(pattern:"([()])", string:firmware, replace:"."); # replace paran w/ decimal

          var parts = split(firmware, sep:'.', keep:FALSE);
          dbg::detailed_log(lvl:3, msg:'[zyxel_router::transform_ver][parts][' + obj_rep(parts) + ']');
          var version = NULL;
          foreach var seg (parts)
          {
            version += convert_ver(ver:seg);
            dbg::detailed_log(lvl:3, msg:'[zyxel_router::transform_ver][==> obj_rep(building...version)][' + obj_rep(seg) + '][version][' + version + ']' );
          }

          dbg::detailed_log(lvl:3, msg:'[zyxel_router::transform_ver][====> obj_rep(built_version)][' + obj_rep(version) + ']');
          return version;
        }
        else
          dbg::detailed_log(lvl:3, msg:'[zyxel_router::transform_firmware_ver][FAILED]');
      }

      ##
      # Gather the "Zyxel Router" installs info and puts them into an array.
      #
      # @return [array] The app info array containing: port, version, raw version, parsed version and model.
      ##
      function get_app_info()
      {
        local_var app_info = {};
        local_var installs, install, pref_install, i;

        installs = get_combined_installs(app_name:"Zyxel Router", exit_if_not_found:TRUE);
        installs = installs[1];

        dbg::detailed_log(lvl:3, msg:'[zyxel_router::installs][' + obj_rep(installs) + ']');
        #exit(0);

        pref_install = 0;
        for (i = 0; i < max_index(installs); i++)
        {
          if(installs[i]['confidence'] > installs[pref_install]['confidence'])
            pref_install = i;
        }
        install = installs[pref_install];

        app_info.version = install['version'];
        app_info.raw_version = transform_ver(firmware:app_info.version);
        app_info.parsed_version = parse_version(app_info.raw_version);
        app_info.port = install['port'];
        app_info.model = install['model'];
        app_info["cpe/v23"] = install["cpe/v23"];

        dbg::detailed_log(lvl:2, msg:'[zyxel_router::get_app_info][' + obj_rep(app_info.raw_version) + ']');
        return app_info;
      }

      ##
      # Check the version against the constraints and only report versions matching those constraints.
      #
      # @param [app_info:array] The app information to check.
      # @param [constraints:list] The list of array making up the constraints.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
      #
      # @remark
      # An example of contraint goes as follows:
      # constraints = [{
      #   models:['NR7103'], fix: 'V1.00(ABZF.1)C1'}
      # ]
      #
      # @remark
      # If the model doesn't match, the function audits out. If model matches,
      # rebuild the constraint using the firmware_fix value (which was already sent to transform_ver)
      ##
      function check_version_and_report(app_info, constraints, severity, flags)
      {
        local_var i;
        local_var filtered_constraints, fixed_version;
        filtered_constraints = make_list();

        var target_model = app_info.model;
        var affected = FALSE;

        for (i=0; i<max_index(constraints); i++)
        {
          # the transformed firmware fix is passed in as a semantic version
          # check models
          # then compare versions, trigger report if vuln

          fixed_version = constraints[i]['fixed_version'];
          dbg::detailed_log(lvl:3, msg:'[zyxel_router::check_version_and_report][constraints[i]][' + obj_rep(constraints[i]) + '][models][' + obj_rep(constraints[i]['models']) + ']');


          foreach (var models in constraints[i]['models'])
          {
            if(target_model == models)
            {
              dbg::detailed_log(lvl:2, msg:'[found_affected_model][breaking-to-perform-constraint-checks]');
              affected = TRUE;
              filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
              dbg::detailed_log(lvl:3, msg:'[filtered_constraints][' + obj_rep(filtered_constraints) + ']');
              break;
            }
          }
        }

        if(max_index(filtered_constraints) == 0 || !affected )
        {
          # not affected
          vcf::audit();
        }
        else
        {
          dbg::detailed_log(lvl:3, msg:'[zyxel_router::check_version_and_report][app_info_dump][' + obj_rep(app_info) + ']');

          vcf::check_version_and_report(
            app_info:app_info,
            constraints:filtered_constraints,
            severity:severity,
            flags:flags
          );
        }
      }
  }

  namespace hp_laserjet
  {
      ##
      # Get the absolute value
      #
      # @anonparam [1st:integer] The value to examine
      #
      # @return [integer] The absolute value of ``1st``.
      ##
      function abs()
      {
      if(_FCT_ANON_ARGS[0] > 0) return _FCT_ANON_ARGS[0]; else return - _FCT_ANON_ARGS[0];
      }

      ##
      # Convert version to a '.'-seprated version with letters converted to their numerical value.
      #
      # @param [firmware:string] The version string to convert.
      #
      # @return [string] The new version string.
      #
      # @remark
      # This function is exclusively for versions that have format ``^(\d+_\d+)[A-Za-z]$`` or 001.2323A or 2405129_000047
      # (e.g. 002_2310A or 2309081_001323) replace char A with a numeric equivalent (e.g. ord('A')-ord('A') = 002.2310.0).
      #  For new firmware version, only look at the first part of the firmware revision (e.g. 2307497 of 2307497_543950).
      #  The last part of the firmware revision changes for each model
      ##
      function transform_fw_rev_ver(firmware)
      {
        dbg::detailed_log(lvl:2, msg:'[hp_laserjet::transform_firmware_ver][START][firmware][' + firmware + ']');
        local_var new_ver;
        local_var regex = "^\d+(?:_|\.)\d+[A-Za-z]$";         # sample 002_2000A, 001.2323A
        local_var regex2 = "^(\d{7})_\d+";                       # sample 2405129_000047

        if( firmware =~ regex ) # 002_2000A ->  2.0300.0
        {
          new_ver = ereg_replace(pattern:"(_)", string:firmware, replace:".");
          dbg::detailed_log(lvl:3, msg:'[hp_laserjet::transform_firmware_ver][' + firmware + ']' +
                                       '[new_ver][' + new_ver + ']' +
                                       '[ord(\'A\')]][' + ord(new_ver[strlen(new_ver)-1]) - ord('A') + ']');

          var fw = (new_ver - new_ver[strlen(new_ver)-1]) + '.' + abs( ord(new_ver[strlen(new_ver)-1]) - ord('A') );
          dbg::detailed_log(lvl:3, msg:'[hp_laserjet::transform_firmware_ver][' + firmware + '][fw][' + fw + ']');
          return fw;
        }
        else
        {
          firmware = pregmatch(pattern:regex2, string:firmware);
          if(!empty_or_null(firmware) && !empty_or_null(firmware[1]))
          {
            return firmware[1] + '.0'; # Add .0 for vcf::parse_version()
          }
          else
          {
            dbg::detailed_log(lvl:1, msg:'[hp_laserjet::transform_firmware_ver][FAILED]');
          }
        }
      }

      var hp_cpes = {
        "W1A32A":"cpe:2.3:h:hp:w1a32a:*:*:*:*:*:*:*:*",
        "1PV49A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1pv49a:*:*:*:*:*:*:*:*",
        "A2W75A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m880zm_a2w75a:*:*:*:*:*:*:*:*",
        "7ZU88A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_m578_7zu88a:*:*:*:*:*:*:*:*",
        "M0P32A":"cpe:2.3:h:hp:m0p32a:*:*:*:*:*:*:*:*",
        "CZ184A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz184a:*:*:*:*:*:*:*:*",
        "T3U66A":"cpe:2.3:h:hp:laserjet_managed_e85055_t3u66a:*:*:*:*:*:*:*:*",
        "W1A53A":"cpe:2.3:h:hp:w1a53a:*:*:*:*:*:*:*:*",
        "49K96AV":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_5800zf_49k96av:*:*:*:*:*:*:*:*",
        "T3U52A":"cpe:2.3:h:hp:laserjet_managed_e85055_t3u52a:*:*:*:*:*:*:*:*",
        "L3U65A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m830_l3u65a:*:*:*:*:*:*:*:*",
        "CZ182A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz182a:*:*:*:*:*:*:*:*",
        "J7Z06A":"cpe:2.3:h:hp:pagewide_managed_e75160_j7z06a:*:*:*:*:*:*:*:*",
        "3GN19A":"cpe:2.3:h:hp:laserjet_managed_e50045_3gn19a:*:*:*:*:*:*:*:*",
        "X3A59A":"cpe:2.3:h:hp:x3a59a:*:*:*:*:*:*:*:*",
        "F2A69A":"cpe:2.3:h:hp:laserjet_managed_m506_f2a69a:*:*:*:*:*:*:*:*",
        "49K84A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_6800zfw\\+_49k84a:*:*:*:*:*:*:*:*",
        "J8J67A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62565_j8j67a:*:*:*:*:*:*:*:*",
        "1PV86A":"cpe:2.3:h:hp:laserjet_managed_e50145_1pv86a:*:*:*:*:*:*:*:*",
        "3GY17A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62675_3gy17a:*:*:*:*:*:*:*:*",
        "W1A48A":"cpe:2.3:h:hp:w1a48a:*:*:*:*:*:*:*:*",
        "8GS43A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs43a:*:*:*:*:*:*:*:*",
        "17F27AW":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_17f27aw:*:*:*:*:*:*:*:*",
        "J7Z99A":"cpe:2.3:h:hp:laserjet_enterprise_m652_j7z99a:*:*:*:*:*:*:*:*",
        "6QN30A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_5800zf_6qn30a:*:*:*:*:*:*:*:*",
        "2GP22A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_2gp22a:*:*:*:*:*:*:*:*",
        "Z8Z19":"cpe:2.3:h:hp:laserjet_managed_mfp_e82560_z8z19a:*:*:*:*:*:*:*:*",
        "Z8Z011A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_z8z011a:*:*:*:*:*:*:*:*",
        "X3A75A":"cpe:2.3:h:hp:x3a75a:*:*:*:*:*:*:*:*",
        "8GS37A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs37a:*:*:*:*:*:*:*:*",
        "Z8Z0A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_e77830_z8z0a:*:*:*:*:*:*:*:*",
        "8GS13A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs13a:*:*:*:*:*:*:*:*",
        "5QJ81A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e785dn_5qj81a:*:*:*:*:*:*:*:*",
        "3SJ03A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73030_3sj03a:*:*:*:*:*:*:*:*",
        "L2763A":"cpe:2.3:h:hp:scanjet_enterprise_flow_n9120_fn2_document_scanner_l2763a:*:*:*:*:*:*:*:*",
        "6QN38A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_6800zfw\\+_6qn38a:*:*:*:*:*:*:*:*",
        "6QN29A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_5800zf_6qn29a:*:*:*:*:*:*:*:*",
        "3SJ12A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_3sj12a:*:*:*:*:*:*:*:*",
        "L3U51A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m880zm_l3u51a:*:*:*:*:*:*:*:*",
        "D7P70A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m880zm_d7p70a:*:*:*:*:*:*:*:*",
        "W1Y45A":"cpe:2.3:h:hp:w1y45a:*:*:*:*:*:*:*:*",
        "3SJ11A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_3sj11a:*:*:*:*:*:*:*:*",
        "B5L50A":"cpe:2.3:h:hp:laserjet_managed_mfp_m577_b5l50a:*:*:*:*:*:*:*:*",
        "5CM78A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5cm78a:*:*:*:*:*:*:*:*",
        "J8A17A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m682_j8a17a:*:*:*:*:*:*:*:*",
        "M0P39A":"cpe:2.3:h:hp:m0p39a:*:*:*:*:*:*:*:*",
        "F2A70A":"cpe:2.3:h:hp:laserjet_managed_m506_f2a70a:*:*:*:*:*:*:*:*",
        "3SJ04A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73030_3sj04a:*:*:*:*:*:*:*:*",
        "X3A86A":"cpe:2.3:h:hp:x3a86a:*:*:*:*:*:*:*:*",
        "3SJ13A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_3sj13a:*:*:*:*:*:*:*:*",
        "5QK08A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_5qk08a:*:*:*:*:*:*:*:*",
        "J8J78A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m633_j8j78a:*:*:*:*:*:*:*:*",
        "J8J76A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m633_j8j76a:*:*:*:*:*:*:*:*",
        "5QJ83A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e785dn_5qj83a:*:*:*:*:*:*:*:*",
        "A2W76A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m880zm_a2w76a:*:*:*:*:*:*:*:*",
        "5FM77A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5fm77a:*:*:*:*:*:*:*:*",
        "G1W39A":"cpe:2.3:h:hp:pagewide_enterprise_mfp_586_g1w39a:*:*:*:*:*:*:*:*",
        "W1A82A":"cpe:2.3:h:hp:w1a82a:*:*:*:*:*:*:*:*",
        "J8A11A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m681_j8a11a_:*:*:*:*:*:*:*:*",
        "W1A59A":"cpe:2.3:h:hp:w1a59a:*:*:*:*:*:*:*:*",
        "F2A81A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m527_f2a81a:*:*:*:*:*:*:*:*",
        "J8A16A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m682_j8a16a:*:*:*:*:*:*:*:*",
        "L3U69A":"cpe:2.3:h:hp:laserjet_managed_mfp_e67560_l3u69a:*:*:*:*:*:*:*:*",
        "5QK03A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_5qk03a:*:*:*:*:*:*:*:*",
        "AZ8Z20A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82560_az8z20a:*:*:*:*:*:*:*:*",
        "W1A79A":"cpe:2.3:h:hp:w1a79a:*:*:*:*:*:*:*:*",
        "K0Q15A":"cpe:2.3:h:hp:laserjet_enterprise_m607_k0q15a:*:*:*:*:*:*:*:*",
        "3SJ01A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_3sj01a:*:*:*:*:*:*:*:*",
        "3SJ33A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_3sj33a:*:*:*:*:*:*:*:*",
        "5QK13A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_5qk13a:*:*:*:*:*:*:*:*",
        "7ZU86A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_m578_7zu86a:*:*:*:*:*:*:*:*",
        "J7Z09A":"cpe:2.3:h:hp:pagewide_enterprise_mfp_780_j7z09a:*:*:*:*:*:*:*:*",
        "Z8Z05A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_e77830_z8z05a:*:*:*:*:*:*:*:*",
        "Z8Z010A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_z8z010a:*:*:*:*:*:*:*:*",
        "2GP25A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_2gp25a:*:*:*:*:*:*:*:*",
        "CF067A":"cpe:2.3:h:hp:laserjet_managed_mfp_m725_cf067a:*:*:*:*:*:*:*:*",
        "J7Z13A":"cpe:2.3:h:hp:pagewide_managed_mfp_e77650_j7z13a:*:*:*:*:*:*:*:*",
        "X3A89A":"cpe:2.3:h:hp:x3a89a:*:*:*:*:*:*:*:*",
        "W1Y40A":"cpe:2.3:h:hp:w1y40a:*:*:*:*:*:*:*:*",
        "3GY16A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62675_3gy16a:*:*:*:*:*:*:*:*",
        "5FM80A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5fm80a:*:*:*:*:*:*:*:*",
        "B5L26A":"cpe:2.3:h:hp:laserjet_managed_m553_b5l26a:*:*:*:*:*:*:*:*",
        "3SJ02A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_3sj02a:*:*:*:*:*:*:*:*",
        "5CM63A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5cm63a:*:*:*:*:*:*:*:*",
        "3SJ08A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_3sj08a:*:*:*:*:*:*:*:*",
        "L3U67A":"cpe:2.3:h:hp:laserjet_managed_mfp_e67560_l3u67a:*:*:*:*:*:*:*:*",
        "5ZN98A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_5zn98a:*:*:*:*:*:*:*:*",
        "1PV87A":"cpe:2.3:h:hp:laserjet_managed_e50145_1pv87a:*:*:*:*:*:*:*:*",
        "3PZ95A":"cpe:2.3:h:hp:color_laserjet_enterprise_m455_3pz95a:*:*:*:*:*:*:*:*",
        "F2A67A":"cpe:2.3:h:hp:laserjet_managed_m506_f2a67a:*:*:*:*:*:*:*:*",
        "Y3Z65A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z65a:*:*:*:*:*:*:*:*",
        "3SJ36A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj36a:*:*:*:*:*:*:*:*",
        "CF068A":"cpe:2.3:h:hp:laserjet_managed_mfp_m725_cf068a:*:*:*:*:*:*:*:*",
        "3GY31A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e67650_3gy31a:*:*:*:*:*:*:*:*",
        "F2A77A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m527_f2a77a:*:*:*:*:*:*:*:*",
        "6BS59A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_6bs59a:*:*:*:*:*:*:*:*",
        "3GY26A":"cpe:2.3:h:hp:laserjet_managed_mfp_e57540_3gy26a:*:*:*:*:*:*:*:*",
        "1PV89A":"cpe:2.3:h:hp:laserjet_managed_e50145_1pv89a:*:*:*:*:*:*:*:*",
        "5CM65A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5cm65a:*:*:*:*:*:*:*:*",
        "W1A35A":"cpe:2.3:h:hp:w1a35a:*:*:*:*:*:*:*:*",
        "W1Y41A":"cpe:2.3:h:hp:w1y41a:*:*:*:*:*:*:*:*",
        "L3U44A":"cpe:2.3:h:hp:pagewide_managed_e55650_l3u44a:*:*:*:*:*:*:*:*",
        "F2A76A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m527_f2a76a:*:*:*:*:*:*:*:*",
        "4PZ45A":"cpe:2.3:h:hp:pagewide_mfp_779_4pz45a:*:*:*:*:*:*:*:*",
        "8GS44A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs44a:*:*:*:*:*:*:*:*",
        "3SJ35A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj35a:*:*:*:*:*:*:*:*",
        "W1Y44A":"cpe:2.3:h:hp:w1y44a:*:*:*:*:*:*:*:*",
        "3SJ28A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_3sj28a:*:*:*:*:*:*:*:*",
        "G1W46A":"cpe:2.3:h:hp:pagewide_enterprise_color_556_g1w46a:*:*:*:*:*:*:*:*",
        "6BS58A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_6bs58a:*:*:*:*:*:*:*:*",
        "W1A47A":"cpe:2.3:h:hp:w1a47a:*:*:*:*:*:*:*:*",
        "X3A69A":"cpe:2.3:h:hp:x3a69a:*:*:*:*:*:*:*:*",
        "Y3Z68A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z68a:*:*:*:*:*:*:*:*",
        "X3A93A":"cpe:2.3:h:hp:x3a93a:*:*:*:*:*:*:*:*",
        "Z8Z22A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82560_z8z22a:*:*:*:*:*:*:*:*",
        "E6B72A":"cpe:2.3:h:hp:laserjet_enterprise_m606_e6b72a:*:*:*:*:*:*:*:*",
        "5ZP01A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_5zp01a:*:*:*:*:*:*:*:*",
        "J7Z11A":"cpe:2.3:h:hp:pagewide_enterprise_flow_mfp_785_j7z11a:*:*:*:*:*:*:*:*",
        "F2A80A":"cpe:2.3:h:hp:laserjet_managed_mfp_m527_f2a80a:*:*:*:*:*:*:*:*",
        "K0Q18A":"cpe:2.3:h:hp:laserjet_enterprise_m608_k0q18a:*:*:*:*:*:*:*:*",
        "49K99A":"cpe:2.3:h:hp:color_laserjet_enterprise_x55745_49k99a:*:*:*:*:*:*:*:*",
        "Z8Z02A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77830_z8z02a:*:*:*:*:*:*:*:*",
        "X3A62A":"cpe:2.3:h:hp:x3a62a:*:*:*:*:*:*:*:*",
        "G1W46V":"cpe:2.3:h:hp:pagewide_enterprise_color_556_g1w46v:*:*:*:*:*:*:*:*",
        "5FM76A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5fm76a:*:*:*:*:*:*:*:*",
        "3SJ37A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj37a:*:*:*:*:*:*:*:*",
        "K0Q17A":"cpe:2.3:h:hp:laserjet_enterprise_m608_k0q17a:*:*:*:*:*:*:*:*",
        "5RC87A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5rc87a:*:*:*:*:*:*:*:*",
        "5QK02A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_5qk02a:*:*:*:*:*:*:*:*",
        "K0Q21A":"cpe:2.3:h:hp:laserjet_enterprise_m609_k0q21a:*:*:*:*:*:*:*:*",
        "L3U64A":"cpe:2.3:h:hp:laserjet_managed_mfp_m725_l3u64a:*:*:*:*:*:*:*:*",
        "3GY20A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52545_3gy20a:*:*:*:*:*:*:*:*",
        "L3U63A":"cpe:2.3:h:hp:laserjet_managed_mfp_m725_l3u63a:*:*:*:*:*:*:*:*",
        "J8J64A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m631_j8j64a:*:*:*:*:*:*:*:*",
        "X3A74A":"cpe:2.3:h:hp:x3a74a:*:*:*:*:*:*:*:*",
        "Z8Z18A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82560_z8z18a:*:*:*:*:*:*:*:*",
        "3GY18A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62675_3gy18a:*:*:*:*:*:*:*:*",
        "3QA35A":"cpe:2.3:h:hp:color_laserjet_managed_e45028_3qa35a:*:*:*:*:*:*:*:*",
        "J8J71A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m632_j8j71a:*:*:*:*:*:*:*:*",
        "1PS54A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1ps54a:*:*:*:*:*:*:*:*",
        "4PA44A":"cpe:2.3:h:hp:pagewide_mfp_774_4pa44a:*:*:*:*:*:*:*:*",
        "T3U51A":"cpe:2.3:h:hp:laserjet_managed_e85055_t3u51a:*:*:*:*:*:*:*:*",
        "X3A83A":"cpe:2.3:h:hp:x3a83a:*:*:*:*:*:*:*:*",
        "5CM71A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5cm71a:*:*:*:*:*:*:*:*",
        "J8J70A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m632_j8j70a:*:*:*:*:*:*:*:*",
        "B5L46A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m577_b5l46a:*:*:*:*:*:*:*:*",
        "CF236A":"cpe:2.3:h:hp:laserjet_enterprise_700_m712_cf236a:*:*:*:*:*:*:*:*",
        "CZ172A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz172a:*:*:*:*:*:*:*:*",
        "X3A90A":"cpe:2.3:h:hp:x3a90a:*:*:*:*:*:*:*:*",
        "4PZ47A":"cpe:2.3:h:hp:pagewide_color_755_4pz47a:*:*:*:*:*:*:*:*",
        "1PU52A":"cpe:2.3:h:hp:laserjet_managed_e50145_1pu52a:*:*:*:*:*:*:*:*",
        "CF238A":"cpe:2.3:h:hp:laserjet_enterprise_700_m712_cf238a:*:*:*:*:*:*:*:*",
        "5RC84A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5rc84a:*:*:*:*:*:*:*:*",
        "X3A81A":"cpe:2.3:h:hp:x3a81a:*:*:*:*:*:*:*:*",
        "W1A51A":"cpe:2.3:h:hp:w1a51a:*:*:*:*:*:*:*:*",
        "J8J66A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62565_j8j66a:*:*:*:*:*:*:*:*",
        "J8J65A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m631_j8j65a:*:*:*:*:*:*:*:*",
        "7ZU87A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_m578_7zu87a:*:*:*:*:*:*:*:*",
        "W1A66A":"cpe:2.3:h:hp:w1a66a:*:*:*:*:*:*:*:*",
        "4PZ43A":"cpe:2.3:h:hp:pagewide_mfp_774_4pz43a:*:*:*:*:*:*:*:*",
        "3SJ19A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj19a:*:*:*:*:*:*:*:*",
        "X3A92A":"cpe:2.3:h:hp:x3a92a:*:*:*:*:*:*:*:*",
        "1PV88A":"cpe:2.3:h:hp:laserjet_managed_e50145_1pv88a:*:*:*:*:*:*:*:*",
        "6QN31A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_5800zf_6qn31a:*:*:*:*:*:*:*:*",
        "X3A87A":"cpe:2.3:h:hp:x3a87a:*:*:*:*:*:*:*:*",
        "58R10A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_5800zf_58r10a:*:*:*:*:*:*:*:*",
        "Z8Z06A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_z8z06a:*:*:*:*:*:*:*:*",
        "3GX98A":"cpe:2.3:h:hp:laserjet_managed_e55040dw_3gx98a:*:*:*:*:*:*:*:*",
        "CZ185A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz185a:*:*:*:*:*:*:*:*",
        "5CM64A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5cm64a:*:*:*:*:*:*:*:*",
        "F2A71A":"cpe:2.3:h:hp:laserjet_managed_m506_f2a71a:*:*:*:*:*:*:*:*",
        "5CM69A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5cm69a:*:*:*:*:*:*:*:*",
        "5QJ94A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_5qj94a:*:*:*:*:*:*:*:*",
        "5QK18A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_5qk18a:*:*:*:*:*:*:*:*",
        "G1W47A":"cpe:2.3:h:hp:pagewide_enterprise_color_556_g1w47a:*:*:*:*:*:*:*:*",
        "CZ173A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz173a:*:*:*:*:*:*:*:*",
        "5CM59A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5cm59a:*:*:*:*:*:*:*:*",
        "5CM79A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5cm79a:*:*:*:*:*:*:*:*",
        "J7Z05A":"cpe:2.3:h:hp:pagewide_managed_mfp_e77650_j7z05a:*:*:*:*:*:*:*:*",
        "X3A78A":"cpe:2.3:h:hp:x3a78a:*:*:*:*:*:*:*:*",
        "8GS36A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs36a:*:*:*:*:*:*:*:*",
        "W1A60A":"cpe:2.3:h:hp:w1a60a:*:*:*:*:*:*:*:*",
        "L3U70A":"cpe:2.3:h:hp:laserjet_managed_mfp_e67560_l3u70a:*:*:*:*:*:*:*:*",
        "6QN36A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_6800zfw\\+_6qn36a:*:*:*:*:*:*:*:*",
        "W1A31A":"cpe:2.3:h:hp:w1a31a:*:*:*:*:*:*:*:*",
        "3SJ22A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj22a:*:*:*:*:*:*:*:*",
        "6QP99A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_x57945_6qp99a:*:*:*:*:*:*:*:*",
        "Z5G77A":"cpe:2.3:h:hp:z5g77a:*:*:*:*:*:*:*:*",
        "3SJ07A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_3sj07a:*:*:*:*:*:*:*:*",
        "W1A38A":"cpe:2.3:h:hp:w1a38a:*:*:*:*:*:*:*:*",
        "3GY19A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52545_3gy19a:*:*:*:*:*:*:*:*",
        "Z8Z12A":"cpe:2.3:h:hp:laserjet_managed_mfp_e87660_z8z12a:*:*:*:*:*:*:*:*",
        "58M42A":"cpe:2.3:h:hp:color_laserjet_enterprise_6701_58m42a:*:*:*:*:*:*:*:*",
        "Y3Z61A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z61a:*:*:*:*:*:*:*:*",
        "5CM61A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5cm61a:*:*:*:*:*:*:*:*",
        "W1A78A":"cpe:2.3:h:hp:w1a78a:*:*:*:*:*:*:*:*",
        "B5L54A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m577_b5l54a:*:*:*:*:*:*:*:*",
        "X3A60A":"cpe:2.3:h:hp:x3a60a:*:*:*:*:*:*:*:*",
        "6QN37A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_6800zfw\\+_6qn37a:*:*:*:*:*:*:*:*",
        "1PV65A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1pv65a:*:*:*:*:*:*:*:*",
        "L3U66A":"cpe:2.3:h:hp:laserjet_managed_mfp_e67560_l3u66a:*:*:*:*:*:*:*:*",
        "J8J74A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62565_j8j74a:*:*:*:*:*:*:*:*",
        "CF367A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m830_cf367a:*:*:*:*:*:*:*:*",
        "J8A12A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m681_j8a12a:*:*:*:*:*:*:*:*",
        "X3A79A":"cpe:2.3:h:hp:x3a79a:*:*:*:*:*:*:*:*",
        "X3A68A":"cpe:2.3:h:hp:x3a68a:*:*:*:*:*:*:*:*",
        "T3U55A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m776_t3u55a:*:*:*:*:*:*:*:*",
        "X3A82A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82560_x3a82a:*:*:*:*:*:*:*:*",
        "Z8Z04A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77830_z8z04a:*:*:*:*:*:*:*:*",
        "T3U43A":"cpe:2.3:h:hp:laserjet_managed_e75245_t3u43a:*:*:*:*:*:*:*:*",
        "7ZU85A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_m578_7zu85a:*:*:*:*:*:*:*:*",
        "5CM76A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5cm76a:*:*:*:*:*:*:*:*",
        "B5L23A":"cpe:2.3:h:hp:laserjet_enterprise_m552_b5l23a:*:*:*:*:*:*:*:*",
        "X3A80A":"cpe:2.3:h:hp:x3a80a:*:*:*:*:*:*:*:*",
        "Z8Z17A":"cpe:2.3:h:hp:laserjet_managed_mfp_e87660_z8z17a:*:*:*:*:*:*:*:*",
        "X3A63A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_x3a63a:*:*:*:*:*:*:*:*",
        "6BS57A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_6bs57a:*:*:*:*:*:*:*:*",
        "5QJ98A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_5qj98a:*:*:*:*:*:*:*:*",
        "M0P35A":"cpe:2.3:h:hp:m0p35a:*:*:*:*:*:*:*:*",
        "J7Z14A":"cpe:2.3:h:hp:pagewide_managed_mfp_e77650_j7z14a:*:*:*:*:*:*:*:*",
        "Z8Z23A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82560_z8z23a:*:*:*:*:*:*:*:*",
        "F2A66A":"cpe:2.3:h:hp:laserjet_managed_m506_f2a66a:*:*:*:*:*:*:*:*",
        "5RC88A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5rc88a:*:*:*:*:*:*:*:*",
        "3GY25A":"cpe:2.3:h:hp:laserjet_managed_mfp_e57540_3gy25a:*:*:*:*:*:*:*:*",
        "J8A06A":"cpe:2.3:h:hp:laserjet_enterprise_m653_j8a06a:*:*:*:*:*:*:*:*",
        "W1A46A":"cpe:2.3:h:hp:w1a46a:*:*:*:*:*:*:*:*",
        "5RC89A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5rc89a:*:*:*:*:*:*:*:*",
        "6QP97A":"cpe:2.3:h:hp:color_laserjet_enterprise_x55745_6qp97a:*:*:*:*:*:*:*:*",
        "5CM66A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5cm66a:*:*:*:*:*:*:*:*",
        "3SJ30A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_3sj30a:*:*:*:*:*:*:*:*",
        "4Y280A":"cpe:2.3:h:hp:color_laserjet_enterprise_6701_4y280a:*:*:*:*:*:*:*:*",
        "K0Q14A":"cpe:2.3:h:hp:laserjet_enterprise_m607_k0q14a:*:*:*:*:*:*:*:*",
        "CF069A":"cpe:2.3:h:hp:laserjet_managed_mfp_m725_cf069a:*:*:*:*:*:*:*:*",
        "W1A63A":"cpe:2.3:h:hp:w1a63a:*:*:*:*:*:*:*:*",
        "J7Z03A":"cpe:2.3:h:hp:pagewide_managed_flow_mfp_e77660z_j7z03a:*:*:*:*:*:*:*:*",
        "5FM82A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5fm82a:*:*:*:*:*:*:*:*",
        "3SJ29A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_3sj29a:*:*:*:*:*:*:*:*",
        "3SJ00A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73140_3sj00a:*:*:*:*:*:*:*:*",
        "Z8Z16A":"cpe:2.3:h:hp:laserjet_managed_mfp_e87660_z8z16a:*:*:*:*:*:*:*:*",
        "49K97AV":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_x57945_49k97av:*:*:*:*:*:*:*:*",
        "CF066A":"cpe:2.3:h:hp:laserjet_managed_mfp_m725_cf066a:*:*:*:*:*:*:*:*",
        "5CM77A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5cm77a:*:*:*:*:*:*:*:*",
        "CZ175A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz175a:*:*:*:*:*:*:*:*",
        "J8A04A":"cpe:2.3:h:hp:laserjet_enterprise_m653_j8a04a:*:*:*:*:*:*:*:*",
        "F2A68A":"cpe:2.3:h:hp:laserjet_managed_m506_f2a68a:*:*:*:*:*:*:*:*",
        "W1A80A":"cpe:2.3:h:hp:w1a80a:*:*:*:*:*:*:*:*",
        "3GY32A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e67650_3gy32a:*:*:*:*:*:*:*:*",
        "F2A79A":"cpe:2.3:h:hp:laserjet_managed_mfp_m527_f2a79a:*:*:*:*:*:*:*:*",
        "W1A75A":"cpe:2.3:h:hp:w1a75a:*:*:*:*:*:*:*:*",
        "Z8Z14A":"cpe:2.3:h:hp:laserjet_managed_mfp_e87660_z8z14a:*:*:*:*:*:*:*:*",
        "CZ174A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz174a:*:*:*:*:*:*:*:*",
        "W1A52A":"cpe:2.3:h:hp:w1a52a:*:*:*:*:*:*:*:*",
        "1PV67A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1pv67a:*:*:*:*:*:*:*:*",
        "5RC83A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5rc83a:*:*:*:*:*:*:*:*",
        "L3U56A":"cpe:2.3:h:hp:laserjet_managed_e65060_l3u56a:*:*:*:*:*:*:*:*",
        "3QA55A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_m480_3qa55a:*:*:*:*:*:*:*:*",
        "T3U44A":"cpe:2.3:h:hp:laserjet_managed_e75245_t3u44a:*:*:*:*:*:*:*:*",
        "X3A72A":"cpe:2.3:h:hp:x3a72a:*:*:*:*:*:*:*:*",
        "X3A71A":"cpe:2.3:h:hp:x3a71a:*:*:*:*:*:*:*:*",
        "W1A29A":"cpe:2.3:h:hp:w1a29a:*:*:*:*:*:*:*:*",
        "M0P36A":"cpe:2.3:h:hp:m0p36a:*:*:*:*:*:*:*:*",
        "M0P40A":"cpe:2.3:h:hp:m0p40a:*:*:*:*:*:*:*:*",
        "J7Z12A":"cpe:2.3:h:hp:pagewide_enterprise_flow_mfp_785_j7z12a:*:*:*:*:*:*:*:*",
        "W1A28A":"cpe:2.3:h:hp:w1a28a:*:*:*:*:*:*:*:*",
        "L2762A":"cpe:2.3:h:hp:l2762a:*:*:*:*:*:*:*:*",
        "J8J79A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62565_j8j79a:*:*:*:*:*:*:*:*",
        "X3A84A":"cpe:2.3:h:hp:x3a84a:*:*:*:*:*:*:*:*",
        "8GS50A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs50a:*:*:*:*:*:*:*:*",
        "J7Z04A":"cpe:2.3:h:hp:pagewide_enterprise_765_j7z04a:*:*:*:*:*:*:*:*",
        "T3U64A":"cpe:2.3:h:hp:laserjet_managed_e75245_t3u64a:*:*:*:*:*:*:*:*",
        "6QN33A":"cpe:2.3:h:hp:color_laserjet_enterprise_6701_6qn33a:*:*:*:*:*:*:*:*",
        "Z8Z13A":"cpe:2.3:h:hp:laserjet_managed_mfp_e87660_z8z13a:*:*:*:*:*:*:*:*",
        "4PZ46A":"cpe:2.3:h:hp:pagewide_mfp_779_4pz46a:*:*:*:*:*:*:*:*",
        "3SJ21A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj21a:*:*:*:*:*:*:*:*",
        "J8A13A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m681_j8a13a:*:*:*:*:*:*:*:*",
        "BL27A":"cpe:2.3:h:hp:laserjet_managed_m553_bl27a:*:*:*:*:*:*:*:*",
        "W1A57A":"cpe:2.3:h:hp:w1a57a:*:*:*:*:*:*:*:*",
        "W1A56A":"cpe:2.3:h:hp:w1a56a:*:*:*:*:*:*:*:*",
        "Y3Z60A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77440_y3z60a:*:*:*:*:*:*:*:*",
        "8GS14A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs14a:*:*:*:*:*:*:*:*",
        "5CM72A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5cm72a:*:*:*:*:*:*:*:*",
        "M0P33A":"cpe:2.3:h:hp:m0p33a:*:*:*:*:*:*:*:*",
        "W1A77A":"cpe:2.3:h:hp:w1a77a:*:*:*:*:*:*:*:*",
        "5CM70A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5cm70a:*:*:*:*:*:*:*:*",
        "B5L49A":"cpe:2.3:h:hp:laserjet_managed_mfp_m577_b5l49a:*:*:*:*:*:*:*:*",
        "Z8Z15A":"cpe:2.3:h:hp:laserjet_managed_mfp_e87660_z8z15a:*:*:*:*:*:*:*:*",
        "5CM75A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5cm75a:*:*:*:*:*:*:*:*",
        "J8A10A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m681_j8a10a:*:*:*:*:*:*:*:*",
        "W1A30A":"cpe:2.3:h:hp:w1a30a:*:*:*:*:*:*:*:*",
        "G1W47V":"cpe:2.3:h:hp:pagewide_enterprise_color_556_g1w47v:*:*:*:*:*:*:*:*",
        "X3A65A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_x3a65a:*:*:*:*:*:*:*:*",
        "K0Q19A":"cpe:2.3:h:hp:laserjet_enterprise_m608_k0q19a:*:*:*:*:*:*:*:*",
        "3PZ16A":"cpe:2.3:h:hp:laserjet_enterprise_m407_3pz16a:*:*:*:*:*:*:*:*",
        "W1A76A":"cpe:2.3:h:hp:w1a76a:*:*:*:*:*:*:*:*",
        "4Y279A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_6800zfw\\+_4y279a:*:*:*:*:*:*:*:*",
        "X3A66A":"cpe:2.3:h:hp:x3a66a:*:*:*:*:*:*:*:*",
        "Z5G79A":"cpe:2.3:h:hp:z5g79a:*:*:*:*:*:*:*:*",
        "3GY15A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62675_3gy15a:*:*:*:*:*:*:*:*",
        "J8J63A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m631_j8j63a:*:*:*:*:*:*:*:*",
        "19GSAW":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_19gsaw:*:*:*:*:*:*:*:*",
        "5RC90A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5rc90a:*:*:*:*:*:*:*:*",
        "W1A58A":"cpe:2.3:h:hp:w1a58a:*:*:*:*:*:*:*:*",
        "X3A77A":"cpe:2.3:h:hp:x3a77a:*:*:*:*:*:*:*:*",
        "5FM81A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5fm81a:*:*:*:*:*:*:*:*",
        "3SJ38A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj38a:*:*:*:*:*:*:*:*",
        "Z8Z07A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_z8z07a:*:*:*:*:*:*:*:*",
        "5QJ87A":"cpe:2.3:h:hp:laserjet_managed_mfp_e73030_5qj87a:*:*:*:*:*:*:*:*",
        "W1Y46A":"cpe:2.3:h:hp:w1y46a:*:*:*:*:*:*:*:*",
        "8GS15A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs15a:*:*:*:*:*:*:*:*",
        "5ZP00A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_5zp00a:*:*:*:*:*:*:*:*",
        "J7Z10A":"cpe:2.3:h:hp:pagewide_enterprise_mfp_780_j7z10a:*:*:*:*:*:*:*:*",
        "Z8Z09A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_z8z09a:*:*:*:*:*:*:*:*",
        "W1Y47A":"cpe:2.3:h:hp:w1y47a:*:*:*:*:*:*:*:*",
        "T3U56A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m776_t3u56a:*:*:*:*:*:*:*:*",
        "W1A81A":"cpe:2.3:h:hp:w1a81a:*:*:*:*:*:*:*:*",
        "B5L47A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m577_b5l47a:*:*:*:*:*:*:*:*",
        "5QJ90A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_5qj90a:*:*:*:*:*:*:*:*",
        "L3U42A":"cpe:2.3:h:hp:pagewide_managed_mfp_e58650dn_l3u42a:*:*:*:*:*:*:*:*",
        "1PV66A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1pv66a:*:*:*:*:*:*:*:*",
        "Z8Z00A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77830_z8z00a:*:*:*:*:*:*:*:*",
        "49L00A":"cpe:2.3:h:hp:color_laserjet_enterprise_6701_49l00a:*:*:*:*:*:*:*:*",
        "5FM78A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5fm78a:*:*:*:*:*:*:*:*",
        "5RC85A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5rc85a:*:*:*:*:*:*:*:*",
        "Z8Z01A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_e77830_z8z01a:*:*:*:*:*:*:*:*",
        "6QN35A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_6800zfw\\+_6qn35a:*:*:*:*:*:*:*:*",
        "5CM58A":"cpe:2.3:h:hp:laserjet_managed_mfp_e82550_5cm58a:*:*:*:*:*:*:*:*",
        "L3U43A":"cpe:2.3:h:hp:pagewide_managed_mfp_e58650dn_l3u43a:*:*:*:*:*:*:*:*",
        "5CM68A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72430_5cm68a:*:*:*:*:*:*:*:*",
        "6QP98A":"cpe:2.3:h:hp:color_laserjet_enterprise_mfp_x57945_6qp98a:*:*:*:*:*:*:*:*",
        "1PV64A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1pv64a:*:*:*:*:*:*:*:*",
        "J7Z08A":"cpe:2.3:h:hp:pagewide_managed_mfp_e77650_j7z08a:*:*:*:*:*:*:*:*",
        "5QK15A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e785dn_5qk15a:*:*:*:*:*:*:*:*",
        "B5L24A":"cpe:2.3:h:hp:laserjet_managed_m553_b5l24a:*:*:*:*:*:*:*:*",
        "B5L48A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m577_b5l48a:*:*:*:*:*:*:*:*",
        "J8J73A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62565_j8j73a:*:*:*:*:*:*:*:*",
        "Y3Z66A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z66a:*:*:*:*:*:*:*:*",
        "B5L25A":"cpe:2.3:h:hp:laserjet_managed_m553_b5l25a:*:*:*:*:*:*:*:*",
        "3SJ09A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_3sj09a:*:*:*:*:*:*:*:*",
        "L3U57A":"cpe:2.3:h:hp:laserjet_managed_e65060_l3u57a:*:*:*:*:*:*:*:*",
        "K0Q20A":"cpe:2.3:h:hp:laserjet_enterprise_m609_k0q20a:*:*:*:*:*:*:*:*",
        "W1Y43A":"cpe:2.3:h:hp:w1y43a:*:*:*:*:*:*:*:*",
        "5RC91A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5rc91a:*:*:*:*:*:*:*:*",
        "93M22A":"cpe:2.3:h:hp:laserjet_pro_m404-m405_93m22a:*:*:*:*:*:*:*:*",
        "K0Q22A":"cpe:2.3:h:hp:laserjet_enterprise_m609_k0q22a:*:*:*:*:*:*:*:*",
        "1PS55A":"cpe:2.3:h:hp:laserjet_managed_mfp_e52645_1ps55a:*:*:*:*:*:*:*:*",
        "G1W41A":"cpe:2.3:h:hp:pagewide_enterprise_mfp_586_g1w41a:*:*:*:*:*:*:*:*",
        "J7Z07A":"cpe:2.3:h:hp:pagewide_managed_flow_mfp_e77660z_j7z07a:*:*:*:*:*:*:*:*",
        "5QK20A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_5qk20a:*:*:*:*:*:*:*:*",
        "3PZ15A":"cpe:2.3:h:hp:laserjet_enterprise_m406_3pz15a:*:*:*:*:*:*:*:*",
        "5ZN99A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_5zn99a:*:*:*:*:*:*:*:*",
        "F2A78A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m527_f2a78a:*:*:*:*:*:*:*:*",
        "Y3Z49A":"cpe:2.3:h:hp:pagewide_managed_p75250_y3z49a:*:*:*:*:*:*:*:*",
        "L3U52A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m880zm_l3u52a:*:*:*:*:*:*:*:*",
        "5QK09A":"cpe:2.3:h:hp:laserjet_managed_mfp_e826dn_5qk09a:*:*:*:*:*:*:*:*",
        "8GS12A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78223-e78228_8gs12a:*:*:*:*:*:*:*:*",
        "5RC92A":"cpe:2.3:h:hp:laserjet_managed_mfp_e77428_5rc92a:*:*:*:*:*:*:*:*",
        "2GP26A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_2gp26a:*:*:*:*:*:*:*:*",
        "Y3Z64A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z64a:*:*:*:*:*:*:*:*",
        "49K98A":"cpe:2.3:h:hp:color_laserjet_enterprise_5700_49k98a:*:*:*:*:*:*:*:*",
        "6QN28A":"cpe:2.3:h:hp:color_laserjet_enterprise_5700_6qn28a:*:*:*:*:*:*:*:*",
        "J8A05A":"cpe:2.3:h:hp:laserjet_enterprise_m653_j8a05a:*:*:*:*:*:*:*:*",
        "E6B73A":"cpe:2.3:h:hp:laserjet_enterprise_m606_e6b73a:*:*:*:*:*:*:*:*",
        "3SJ32A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_3sj32a:*:*:*:*:*:*:*:*",
        "J8J72A":"cpe:2.3:h:hp:laserjet_enterprise_mfp_m632_j8j72a:*:*:*:*:*:*:*:*",
        "5RC86A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87640du-e87660du_5rc86a:*:*:*:*:*:*:*:*",
        "3GY14A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62675_3gy14a:*:*:*:*:*:*:*:*",
        "CZ183A":"cpe:2.3:h:hp:laserjet_pro_mfp_m128_cz183a:*:*:*:*:*:*:*:*",
        "W1A33A":"cpe:2.3:h:hp:w1a33a:*:*:*:*:*:*:*:*",
        "B5L38A":"cpe:2.3:h:hp:laserjet_managed_m553_b5l38a:*:*:*:*:*:*:*:*",
        "Y3Z63A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z63a:*:*:*:*:*:*:*:*",
        "W1A34A":"cpe:2.3:h:hp:w1a34a:*:*:*:*:*:*:*:*",
        "1PU51A":"cpe:2.3:h:hp:laserjet_managed_e50145_1pu51a:*:*:*:*:*:*:*:*",
        "3SJ34A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e78635_3sj34a:*:*:*:*:*:*:*:*",
        "CZ244A":"cpe:2.3:h:hp:laserjet_enterprise_managed_e42540_cz244a:*:*:*:*:*:*:*:*",
        "L3U55A":"cpe:2.3:h:hp:laserjet_managed_e65060_l3u55a:*:*:*:*:*:*:*:*",
        "G1W40A":"cpe:2.3:h:hp:pagewide_enterprise_mfp_586_g1w40a:*:*:*:*:*:*:*:*",
        "Z8Z08A":"cpe:2.3:h:hp:laserjet_managed_mfp_e72535_z8z08a:*:*:*:*:*:*:*:*",
        "3SJ20A":"cpe:2.3:h:hp:color_laserjet_managed_mfp_e87770_3sj20a:*:*:*:*:*:*:*:*",
        "J7Z98A":"cpe:2.3:h:hp:laserjet_enterprise_m652_j7z98a:*:*:*:*:*:*:*:*",
        "2GP23A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_2gp23a:*:*:*:*:*:*:*:*",
        "D7P71A":"cpe:2.3:h:hp:laserjet_managed_flow_mfp_m880zm_d7p71a:*:*:*:*:*:*:*:*",
        "Y3Z62A":"cpe:2.3:h:hp:pagewide_managed_mfp_p77960_y3z62a:*:*:*:*:*:*:*:*",
        "J8J80A":"cpe:2.3:h:hp:laserjet_managed_mfp_e62565_j8j80a:*:*:*:*:*:*:*:*"
      };


      ##
      # Gather the HP Laserjet installs info and puts them into an array.
      #
      # @param [source:string] string that specifies either fw or fw_rev- which KB item to get the version from -
      #                        we use fw_bundle_ver by default
      # defaults to fw_bundle_version if not provided
      #
      # @return [array] The app info array containing:
      # product name, full product name, model, firmware, display version, parsed version, version, URL and serial number.
      ##
      function get_app_info(source)
      {
        var use_fw_rev = FALSE;
        var use_fw = FALSE;

        if (source == 'fw_rev')
          use_fw_rev = TRUE;
        else if (source == 'fw')
          use_fw = TRUE;
        else if (!empty_or_null(source))
          return arg_error(arg:"hp_laserjet get_app_info source parameter", func:FUNCTION_NAME);

        local_var app_info = {};
        local_var port, serial; #, firmware, semantic_version, product, model, url
        port = get_http_port(default:80, dont_break:TRUE, embedded:TRUE);
                                                                                                   # Examples:
        app_info.product                  = get_kb_item('www/hp_laserjet/'+port+'/pname');         # HP Color LaserJet MFP M478
        app_info.model                    = get_kb_item('www/hp_laserjet/'+port+'/modelnumber');   # W1A75A
        app_info.firmware_rev             = get_kb_item('www/hp_laserjet/'+port+'/fw_rev');        # 002_2310A or 2309081_001323
        app_info.firmware                 = get_kb_item('www/hp_laserjet/'+port+'/fw');            # 20220826
        app_info.url                      = get_kb_item('www/hp_laserjet/'+port+'/url');
        app_info.firmware_bundle_version  = get_kb_item('www/hp_laserjet/'+port+'/fw_bundle_ver'); # 3.9.10
        serial                            = get_kb_item('www/hp_laserjet/'+port+'/serial');

        if(empty_or_null(serial)) app_info.serial = "unknown";
        else app_info.serial = serial;

        if (use_fw) # e.g. 20220214
        {
          get_kb_item_or_exit('www/hp_laserjet/'+port+'/fw');
          app_info.display_version = app_info.firmware;
          if (app_info.firmware =~ "^[0-9]+ \S") # Some firmware seen in output as "20150130 08.260.1"  
          {
            var fw_version_list = split(app_info.firmware, sep:' ', keep:FALSE);
            app_info.version = fw_version_list[0] + '.0'; # add .0 for vcf::parse_version()
          }
          else
          {
            app_info.version = app_info.firmware + '.0'; # add .0 for vcf::parse_version()
          }
        }
        else if (use_fw_rev) # e.g. 002_2310A or 002.2310A or 2309081_001323
        {
          get_kb_item_or_exit('www/hp_laserjet/'+port+'/fw_rev');
          app_info.display_version = app_info.firmware_rev;
          app_info.version = transform_fw_rev_ver(firmware:app_info.firmware_rev);
        }
        else # use firmware bundle version as default
        {
          get_kb_item_or_exit('www/hp_laserjet/'+port+'/fw_bundle_ver');
          app_info.version = app_info.firmware_bundle_version;
        }

        app_info.parsed_version = vcf::parse_version(app_info.version);
        app_info["cpe/v23"] = hp_cpes[app_info.model];
        if(isnull(app_info["cpe/v23"]))
          app_info["cpe/v23"] = "cpe:2.3:h:hp:" + app_info.model + ":*:*:*:*:*:*:*:*";

        dbg::detailed_log(lvl:2, msg:'[hp_laserjet::get_app_info][' + obj_rep(app_info) + ']');
        return app_info;
      }

      ##
      # Check the version against the constraints and only report versions matching those constraints.
      #
      # @param [app_info:array] The app information to check.
      # @param [constraints:list] The list of array making up the constraints.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
      #
      # @remark
      # An example of contraint goes as follows:
      # constraints = [{
      #   models:['W1A75A','W1A76A'], fix: '002_2310A'},
      #   models:['W1B75A','W1B76A'], fix: '100_2310A'}
      # ]
      #
      # @remark
      # If the model doesn't match, the function audits out. If model matches,
      # rebuild the constraint using the firmware_fix value (which was already sent to transform_ver)
      ##
      function check_version_and_report(app_info, constraints, severity, flags)
      {
        local_var i;
        local_var filtered_constraints, fixed_version;
        filtered_constraints = make_list();

        var target_model = app_info.model;
        var affected = FALSE;

        for (i=0; i<max_index(constraints); i++)
        {
          # the transformed firmware fix is passed in as a semantic version
          # check models
          # then compare versions, trigger report if vuln

          fixed_version = constraints[i]['fixed_version'];
          dbg::detailed_log(lvl:2, msg:'[hp_laserjet::check_version_and_report][constraints[i]][' +
                                       obj_rep(constraints[i]) + '][models][' +
                                       obj_rep(constraints[i]['models']) + ']');


          foreach (var models in constraints[i]['models'])
          {
            if(target_model == models)
            {
              dbg::detailed_log(lvl:1, msg:'[found_affected_model][breaking]');
              affected = TRUE;
              filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
              break;
            }
          }
        }

        if(max_index(filtered_constraints) == 0 || !affected )
        {
          # not affected
          vcf::audit();
        }
        else
        {
          dbg::detailed_log(lvl:3, msg:'[hp_laserjet::check_version_and_report][app_info_dump][' +
                                        obj_rep(app_info.version) + ']');
          vcf::check_version_and_report(
            app_info:app_info,
            constraints:filtered_constraints,
            severity:severity,
            flags:flags
          );
        }
      }
  }

  # also known as vmware realize business cloud
  namespace vmware_vrealize
  {
    ##
    # Gather the VMware vRealize installs info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # version, parsed version and display version.
    ##
    function get_app_info()
    {
      local_var app_info = {};
      local_var version, display_version, build, patch, source;

      display_version = get_kb_item("Host/VMware vRealize Business for Cloud/VerUI");
      version = get_kb_item("Host/VMware vRealize Business for Cloud/Version");
      build   = get_kb_item("Host/VMware vRealize Business for Cloud/Build");

      if(empty_or_null(build))
        build = 0;


      if(empty_or_null(version) || version == UNKNOWN_VER)
        app_info.version = UNKNOWN_VER;
      else
        app_info.version = version + "." + build;

      app_info.parsed_version  = parse_version(app_info.version);
      app_info.display_version = display_version;
      app_info["cpe/v23"] = "cpe:2.3:a:vmware:vrealize_business_for_cloud";

      return app_info;
    }
  }

  # VMware Aria Automation (formerly vRealize Automation) updates
  namespace vmware_aria_auto
  {

    ##
    # Gather the VMware Aria Automation installs info and puts them into an array.
    #
    # @param [app:string] The app name for which to get the info.
    #
    # @return [array] The app info array containing:
    # app name, path, version, display version, parsed version and port.
    ##
    function get_app_info(app)
    {
      local_var install = vcf::combined_get_app_info(app:app);
      local_var app_info = install;

      app_info.display_version = install['version'] + " Build " + install["Build"];
      app_info.version = install['version'] + '.' + install['Build'];
      app_info.parsed_version = parse_version(app_info.version);
      app_info.path = install['path'];

      return app_info;
    }
  }

  namespace adobe_reader
  {
    ##
    # Gather the Adobe Reader installs info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # app name, path, version, display version, parsed version and port.
    ##
    function get_app_info()
    {
      local_var app_info = get_single_install(app_name:"Adobe Reader");
      local_var win_port;

      app_info.app = "Adobe Reader";

      # use DLL version if > app_info.version
      if(ver_compare(ver:app_info.DLL_Product_Version, fix:app_info.version, strict:FALSE) == 1)
      {
        app_info.version = app_info.DLL_Product_Version;
        app_info.display_version = app_info.DLL_Display_Version;
      }

      app_info.parsed_version = parse_version(app_info.version);

      win_port = get_kb_item("SMB/transport");
      if(!win_port) app_info.port = 445;
      else app_info.port = win_port;

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    # @param [max_segs:integer] Limits the number of segments of the detected version used to ``max_segs``.
    #
    # @remark
    # ``max_segs`` exists because reader/acrobat versions can have 4 segments, but
    # the listed affected / fixed versions only refer to 3.
    # So, affected 15.6.30355 effectively means < 15.6.30356 affected
    # but our current (Jan 2019) max_versions don't account for this.
    #
    # @remark
    # The constraints are sorted to match track.
    # x.y.2zzzz = DC Continuous
    # x.y.3zzzz = DC Classic
    #
    # As of August 2024, x.y.21zzzz and x.y.31zzzz are the top level values for Tracks.
    #
    # https://helpx.adobe.com/acrobat/kb/identify-product-version.html
    # https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/whatsnewdc.html
    ##
    function check_version_and_report(app_info, constraints, severity, flags, max_segs)
    {
      local_var filtered_constraints, constraint, split_ver, max_segs_parts, i;

      if(!isnull(max_segs))
      {
        max_segs_parts = make_list();
        split_ver = split(app_info.version, sep:'.', keep:FALSE);
        for (i = 0; i < max_segs; i++)
        {
          if(!isnull(split_ver[i]))
          {
            max_segs_parts[i] = int(split_ver[i]);
          }
        }
        app_info.version = join(max_segs_parts, sep:".");
        app_info.parsed_version = parse_version(app_info.version);
      }

      filtered_constraints = make_list();

      foreach constraint (constraints)
      {
        if(app_info.version =~ "^\d+\.\d+\.2[0-2]\d+" && constraint.fixed_version !~ "^\d+\.\d+\.2[0-2]\d+" ||
            app_info.version =~ "^\d+\.\d+\.3[0-2]\d+" && constraint.fixed_version !~ "^\d+\.\d+\.3[0-2]\d+" )
          continue;
        else
          filtered_constraints = make_list(filtered_constraints, make_list2(constraint));
      }

      if(max_index(filtered_constraints) == 0)
      {
        # not affected
        vcf::audit(app_info);
      }
      else
      {
        vcf::check_version_and_report(
          app_info:app_info,
          constraints:filtered_constraints,
          severity:severity,
          flags:flags
        );
      }
    }
  }

  namespace sitecore_xp
  {
    ##
    # Gather the Sitecore XP installs info and puts them into an array.
    #
    # @return [array] The app info array gathered by ``get_single_install()``.
    #
    # @remark
    # In the returned array, the function sets the version to x.y.z.a.revision for comparison, and a suitable display_version.
    ##
    function get_app_info()
    {
      var port = get_http_port(default:80, embedded: FALSE);
      var app_info = get_single_install(app_name:'sitecore_cms', port:port);
      app_info.display_version = app_info.version;

      # The versions are detected like:
      #   Version : 7.1.
      #      rev. 140324
      # or
      # Version : 6.2.0 rev. 100507
      # Or (not seen in Superset, but in Sitecore download file names only) 5.1.1.11 with no revision
      # So capture the 1st 2-4 parts, remove trailing ., padd with 0, and add revision at end if present
      var ver_match = pregmatch(string:app_info.version, pattern:"^\s*([0-9]+\.[0-9]+(\.[0-9]+)?(\.[0-9]+)?)");
      if(empty_or_null(ver_match))
        ::audit(AUDIT_UNKNOWN_APP_VER, 'Sitecore');
      var version = ver_match[1];
      # If version has only 2 parts, x.y, as is the case for versions 7+, add a .0.0 for compatibility with older vers
      if(empty_or_null(ver_match[2]))
        version += '.0.0';
      # If version has only 3 parts, x.y.z, as is the case for versions 5.3-7.0, add .0 for compatibility with older
      # vers
      else if(empty_or_null(ver_match[3]))
        version += '.0';
      var rev_match = pregmatch(string:app_info.version, pattern:"rev\.\s+([0-9]+)");
      if(!empty_or_null(rev_match))
        version += '.' + rev_match[1];

      app_info.version = version;
      app_info.parsed_version = vcf::parse_version(app_info.version);

      return app_info;
    }
  }

  namespace bind
  {
    ##
    # Adds appropriate conversion values and additional separator.
    #
    # @remark
    # This function uses ``add_conversions()`` and ``add_separator()``.
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta, 'P':1});
      add_separator('-');
    }

    ##
    # Filters out constraints based on version.
    # Basically, "-S" versions should only be checked
    # against each other since these versions, while
    # applicable to other releases, are paid releases
    # that not all customers have access to.
    #
    # @param [constraints:list] list of constraints to validate.
    # @param [version:string] the version of bind to validate with.
    #
    # @return [array] array of constraints
    ##
    function filter_constraints(constraints, version)
    {
      local_var i, value, filtered_constraints, matched_versions;
      filtered_constraints = make_list();
      # regex101.com test link matching 500+ isc bind releases: https://regex101.com/r/PYTeYo/4/tests
      matched_versions = pregmatch(pattern:"^[0-9]\.[0-9]+(\.[0-9]+($|-W[0-9]|rc[0-9]+|(((-(P|S)[0-9])(-W[0-9])*))$|(a|b|beta)[0-9]$)|-ESV(-R[0-9]+.*|b[0-9])*)$", string:version);
      if(!empty_or_null(matched_versions))
      {
        if("-S" >< version) # Remove non-subscriber-only constraints
        {
          for (i=0; i<max_index(constraints); i++)
            # some -S versions leverage patches which point to a non-S/Non-P solution - e.g. cve-2018-5738
            # so let's perform the -S check against the min/max versions only and allow the fixed version
            # to be displayed regardless
            if( "-S" >< constraints[i].min_version || "-S" >< constraints[i].max_version || "-S" >< constraints[i].equal)
              filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
        }
        else # Remove subscriber-only constraints
        {
          for (i=0; i<max_index(constraints); i++)
            if("-S" >!< constraints[i].fixed_version && "-S" >!< constraints[i].fixed_display)
              filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
        }
      }
      else if( report_paranoia >= 2 )
        {
          # we are paranoid, so let's perform a looser version check because backported packages have weird naming standards, e.g 9.10.2-P3-RedHat-9.10.2-P3.el6
          # regex101 url: https://regex101.com/r/PYTeYo/5
          matched_versions = pregmatch(pattern:"^[0-9]\.[0-9]+(\.[0-9]+($|-W[0-9]|rc[0-9]+|(((-(P|S)[0-9])(-W[0-9])*))|(a|b|beta)[0-9])|-ESV(-R[0-9]+.*|b[0-9])*)", string:version);

          # copy/pasta from above logic
          if("-S" >< version) # Remove non-subscriber-only constraints
          {
            for (i=0; i<max_index(constraints); i++)
              # some -S versions leverage patches which point to a non-S/Non-P solution - e.g. cve-2018-5738
              # so let's perform the -S check against the min/max versions only and allow the fixed version
              # to be displayed regardless
              if( "-S" >< constraints[i].min_version || "-S" >< constraints[i].max_version || "-S" >< constraints[i].equal)
                filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
          }
          else # Remove subscriber-only constraints
          {
            for (i=0; i<max_index(constraints); i++)
              if("-S" >!< constraints[i].fixed_version && "-S" >!< constraints[i].fixed_display)
                filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
          }
        }
      else
      {
        # we are not paranoid, and we are possibly backported
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "Auditing out - we are not paranoid, and we are possibly backported.",
          msg_details: {
            "version": {"lvl": 1, "value": version}});
        set_kb_item(name: 'bind/'+version+'/backported', value:TRUE);
	      ::audit(AUDIT_BACKPORT_SERVICE, 53, "Bind Server");
      }
      return filtered_constraints;
    }
  }

  namespace ibm
  {
    ##
    # Verify that the required websphere mq components are installed
    # and that the install is of the desired flavor.
    #
    # @param [app_info:array] an app_info structure for websphere mq
    # @param [required_flavor:string] the required application flavor
    # @param [required_component:string] a required component
    #
    # @remark
    # This function will audit out if ``required_flavor`` or ``required_component`` are not in the given app info.
    ##
    function verify_websphere_mq_component(app_info, required_flavor, required_component)
    {
      local_var installed_components, installed_component, required_component_is_present;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);

      if(!isnull(required_flavor))
        if(tolower(required_flavor) != tolower(app_info['Type']))
          ::audit(AUDIT_NOT_INST, "IBM WebSphere MQ type '" + required_flavor + "'");

      # Check or ignore components (explorer, javamsg, server, ...)
      if(!isnull(required_component))
      {
        installed_components = split(app_info['Components'], sep:",", keep:FALSE);

        foreach installed_component (installed_components)
        {
          installed_component = ereg_replace(
            string:installed_component,
            pattern:" ",
            replace:""
          );

          if(tolower(installed_component) == tolower(required_component))
            return;
        }

        ::audit(AUDIT_NOT_INST, "IBM WebSphere MQ component '" + required_component + "'");
      }
    }

    namespace spectrum_protect
    {
      ##
      # Gather the "IBM Spectrum Protect" installs info and puts them into an array.
      #
      # @param [port:integer] The port on which the install should be detected
      #
      # @remark
      # The ``port`` argument only applies to installs of "IBM Tivoli Storage Manager".
      #
      # @return [array] The consolidated app info array originally gathered by ``get_app_info()``.
      ##
      function get_app_info(port)
      {
        local_var win_local;
        local_var app_info;
        local_var packages, package_ver, new_ver, original_ver;

        if(get_install_count(app_name:"IBM Spectrum Protect") > 0)
        {
          if(get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;
          app_info = vcf::get_app_info(app:"IBM Spectrum Protect", win_local:win_local);
        }
        else if(get_install_count(app_name:"IBM Tivoli Storage Manager") > 0 && port > 0)
        {
          app_info = vcf::get_app_info(app:"IBM Tivoli Storage Manager", port:port, service:TRUE);
        }
        else
        {
          vcf::audit();
        }

        ##
        #  Remote plugin plugins/Service_detection/i/ibm_tsm_detect.nasl (plugin 25656)
        #   may not be able to get updated version information
        #  See if package data provides different info.
        ##
        packages = get_kb_item("Host/nix/packages");
        if(!empty_or_null(packages))
        {
          package_ver = pregmatch(string:packages, pattern:"tivoli.tsm.client.api.64bit:([\d\.]+): : :C: :IBMSP");
          if(!empty_or_null(package_ver) && !empty_or_null(package_ver[1]))
          {
            new_ver = package_ver[1];
            dbg::detailed_log(
              lvl: 2,
              src: FUNCTION_NAME,
              msg: "Spectrum Protect package version determined",
              msg_details: {
                "new_ver": {"lvl": 2, "value": new_ver}});
            dbg::detailed_log(
              lvl: 2,
              src: FUNCTION_NAME,
              msg: "Original app_info gathered",
              msg_details: {
                "app_info": {"lvl": 2, "value": obj_rep(app_info)}});
            original_ver = app_info["version"];

            if(ver_compare(ver:new_ver, fix:original_ver, strict:FALSE) > 0)
            {
              dbg::detailed_log(
                lvl: 3,
                src: FUNCTION_NAME,
                msg: "Replacing Spectrum Protect version from app_info with the version obtained from package data.",
                msg_details: {
                  "app_info['version']": {"lvl": 3, "value": app_info['version']},
                  "new_ver": {"lvl": 3, "value": new_ver},
                  "Package data": {"lvl": 3, "value": package_ver[0]}});
              app_info["version"] = new_ver;
              app_info["parsed_version"] = make_nested_list( split(new_ver, sep:'.', keep:FALSE), split("0.", sep:'.', keep:FALSE) );
              dbg::detailed_log(
                lvl: 2,
                src: FUNCTION_NAME,
                msg: "Updated app_info",
                msg_details: {
                  "app_info": {"lvl": 2, "value": obj_rep(app_info)}});
            }
            else if(ver_compare(ver:new_ver, fix:original_ver, strict:FALSE) == 0)
              dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Package version matches reported version");
            else
              dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Package version less than reported version");
          }
        }

        return app_info;
      }
    }
  }

  namespace idrac
  {
    ##
    # Gather the "iDRAC" installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install should be detected
    #
    # @return [array] The consolidated app info array originally gathered by ``get_single_install()``.
    ##
    function get_app_info(port)
    {
      local_var app_info = get_single_install(app_name:"iDRAC", port:port);

      app_info.idrac = app_info['version'];
      app_info.version = app_info['Firmware Version'];

      # Parnoid only if version is unkown
      # Using exit() here as we want to inform customers to enable
      # paranoid checks if they want to fire against unknown versions
      if(tolower(app_info.version) == 'unknown' && report_paranoia < 2)
        exit(0, 'The version of iDRAC' + app_info.idrac + ' could not be determined, but it may ' +
                'still be vulnerable. To report on unkown versions, please enable Parnoid scanning.');

      app_info.parsed_version = parse_version(app_info.version);
      app_info.display_version = "iDRAC" + app_info.idrac + " with firmware " + app_info.version;
      app_info.port = port;
      app_info.webapp = TRUE;

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If the function doesn't find matching constraints, it will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var i;
      local_var filtered_constraints;
      filtered_constraints = make_list();

      for (i=0; i<max_index(constraints); i++)
      {
        if(constraints[i]["idrac"] == app_info.idrac)
        {
          if(!empty_or_null(constraints[i]['fixed_display']))
          {
            constraints[i]['fixed_display'] = "iDRAC" + app_info.idrac + " with firmware " + constraints[i]['fixed_display'];
          }
          else
          {
            constraints[i]['fixed_display'] = "iDRAC" + app_info.idrac + " with firmware " + constraints[i]['fixed_version'];
          }
          filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
        }
      }

      if(max_index(filtered_constraints) == 0)
      {
        # not affected
        vcf::audit();
      }
      else
      {
        vcf::check_version_and_report(
          app_info:app_info,
          constraints:filtered_constraints,
          severity:severity,
          flags:flags
        );
      }
    }
  }

  namespace check_mk
  {
    ##
    # Adds additional conversions.
    #
    # @remark
    # This function uses ``add_conversions()``.
    ##
    function initialize()
    {
      add_conversions({'i':conversions.alpha, 'b':conversions.beta});
    }
  }

  namespace apache_storm
  {
    ##
    # Adds additional conversions.
    #
    # @remark
    # This function uses ``add_conversions()``.
    ##
    function initialize()
    {
      add_conversions({'incubating':-125, 'security':1});
    }
  }

  namespace agilebit_1password
  {
    ##
    # Adds appropriate conversion values and additional separator.
    #
    # @remark
    # This function uses ``add_conversions()`` and ``add_separator()``.
    ##
    function initialize()
    {
      add_conversions({'ALPHA':conversions.alpha, 'BETA':conversions.beta});
      add_separator('-');
    }
  }

  namespace atlassian_sourcetree
  {
    ##
    # Adds additional conversions.
    #
    # @remark
    # This function uses ``add_conversions()``.
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta});
    }
  }

  namespace pfsense_webui
  {
    ##
    # Adds appropriate conversion values and additional separator.
    #
    # @remark
    # This function uses ``add_conversions()`` and ``add_separator()``.
    ##
    function initialize()
    {
      add_conversions({'RC':conversions.rc});
      add_separator('-');
    }

    ##
    # Gather the "pfSense" installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install was found.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    ##
    function get_app_info(port)
    {
      local_var pfversion, pfbuild, pfpatch;
      local_var app_info = get_single_install(app_name:"pfSense", port:port);

      # version . build . patch
      # Where :
      # version - main product version, e.g., 2.3
      # build   - convert string 'RELEASE' to 0 or leave RC alone as integer (RC1 == 1 via VCF)
      # patch   - should just be an integer (p1 == 1 via VCF)
      #
      # 2.3-RELEASE      becomes 2.3
      # 2.4.2-RELEASE-p1 becomes 2.4.2.0.1
      # 2.4.2-RC1        becomes 2.4.2.-1.1.0
      # 2.0-RC1          becomes 2.0.-1.1.0

      pfversion = app_info.version;

      if(!empty_or_null(app_info.Build) && app_info.Build == 'RELEASE')
        pfbuild = "";
      else
        pfbuild = app_info.Build;

      if(!empty_or_null(app_info.Patch))
        pfpatch = app_info.Patch;
      else
        pfpatch = 0;

      app_info.version = pfversion + "." + pfbuild + "." + pfpatch;
      app_info.parsed_version = parse_version(app_info.version);
      app_info.webapp = TRUE;

      return app_info;
    }
  }

  namespace pfsense
  {
    ##
    # Adds appropriate conversion values and additional separator.
    #
    # @remark
    # This function uses ``add_conversions()`` and ``add_separator()``.
    ##
    function initialize()
    {
      add_conversions({'RC':conversions.rc});
      add_separator('-');
    }

    ##
    # Gather the "pfSense" installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install was found. UNUSED.
    #
    # @return [array] The app info array containing:
    # version, source, parsed version and display version.
    ##
    function get_app_info(port)
    {
      local_var app_info = {};
      local_var version, display_version, build, patch, source;

      # version . build . patch
      # Where :
      # version - main product version, e.g., 2.3
      # build   - convert string 'RELEASE' to 0 or leave RC alone as integer (RC1 == 1 via VCF)
      # patch   - should just be an integer (p1 == 1 via VCF)
      #
      # 2.3-RELEASE      becomes 2.3.0
      # 2.4.2-RELEASE-p1 becomes 2.4.2.0.1
      # 2.4.2-RC1        becomes 2.4.2.-1.1.0
      # 2.0-RC1          becomes 2.0.-1.1.0

      display_version = get_kb_item("Host/pfSense/Full Version");
      version = get_kb_item("Host/pfSense/Version");
      build   = get_kb_item("Host/pfSense/Build");
      patch   = get_kb_item("Host/pfSense/Patch");
      source  = get_kb_item("Host/pfSense/source");

      initialize();

      if(empty_or_null(build) || build == 'RELEASE')
        build = 0;

      if(empty_or_null(patch))
        patch = 0;

      if(empty_or_null(version) || version == UNKNOWN_VER)
        app_info.version = UNKNOWN_VER;
      else
        app_info.version = version + "." + build + "." + patch;

      app_info.source  = source;
      app_info.parsed_version  = parse_version(app_info.version);
      app_info.display_version = display_version;
      app_info["cpe/v23"] = "cpe:2.3:a:pfsense:pfsense";

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If the constraint contains a version with "-p" and the patch info was gathered over SNMP,
    # but the scan is not paranoid, the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var i, matches, ver_parts;

      if(empty_or_null(app_info.version) || app_info.version == UNKNOWN_VER)
        ::audit(AUDIT_UNKNOWN_DEVICE_VER, "pfSense");

      for (i=0; i<max_index(constraints); i++)
      {
        # Fixed versions with a patch need special handling
        if(constraints[i].fixed_version =~ "-p")
        {
          # SNMP banner does not include any patch info so, for same version, only flag if paranoid
          if(app_info.source == "SNMP" && report_paranoia < 2)
          {
            ver_parts = split(constraints[i]['fixed_version'], sep:"-", keep:FALSE);
            if(ver_compare(ver:app_info.version, fix:ver_parts[0], strict:FALSE) == 0)
            {
              ::audit(AUDIT_POTENTIAL_VULN, "pfSense", app_info.display_version);
            }
          }

          # Versions without a build but with a patch (e.g. 2.3.1-p1) need to be converted
          # to account for the omitted 'RELEASE' build (e.g. 2.3.1.0.1)
          matches = pregmatch(string:constraints[i].fixed_version, pattern:"^([0-9.]+)-p([0-9]+)$", icase:TRUE);
          if(!isnull(matches))
          {
            constraints[i]['fixed_display'] = constraints[i].fixed_version;
            constraints[i]['fixed_version'] = matches[1] + ".0." + matches[2];
          }
        }
      }

      vcf::check_version_and_report(
        app_info:app_info,
        constraints:constraints,
        severity:severity,
        flags:flags
      );
    }
  }

  namespace microsoft_appstore
  {
    ##
    # Function to assist with handling multiple windows appstore apps.
    # This branches for each app (packageIdentityName) and handles
    # reporting for multiple apps a little better
    #
    # @param [app:string] an application name string, optional; processes single app for compatibility
    # @param [app_list:list] a list of application name strings, optional
    #
    # @return [array] a vcf app_info array
    #
    # @remark
    # Either the 'app' or 'app_list' parameter must be used.
    ##
    function get_app_info(app, app_list)
    {
      local_var app_info, win_port, install, installs, parsed_version, app_iter;
      local_var app_info_list = [];
      local_var branched = 0;

      win_port = get_kb_item('SMB/transport');
      if(!win_port) win_port = 445;

      if(isnull(app))
      {
        if(isnull(app_list)) return arg_error(arg:"app_list", func:FUNCTION_NAME);
      }
      else
      {
        if(isnull(app_list)) app_list = [app];
        else return new("vcf::Error", "Parameters 'app' and 'app_list' were used together in the call to '" +
                                      FUNCTION_NAME + "'.");
      }

      foreach app_iter (app_list)
      {
        if(get_install_count(app_name:app_iter) > 0)
        {
          installs = get_installs(app_name:app_iter, port:win_port);
          if(installs[0] == IF_OK)
          {
            foreach install (installs[1])
            {
              parsed_version = parse_version(install.version);
              if(is_error(parsed_version)) continue;
              install.parsed_version = parsed_version;
              install.app = app_iter;

              append_element(var:app_info_list, value:install);
            }
          }
        }
      }

      if(max_index(app_info_list) > 0)
      {
        app_info = branch(app_info_list);
        return app_info;
      }
      else
        return vcf::audit();
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] UNUSED.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``. UNUSED.
    # @param [expected_patch:string] The patch to check for in the list of installed patches to determine if the
    # install is vulnerable.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags, expected_patch)
    {
      if(empty_or_null(app_info.path))
        vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:severity, require_paranoia:TRUE);
      else
        vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:severity);
    }
  }

  namespace microsoft_idm
  {
    ##
    # Gather the Microsoft IDM installs info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # path and version for: Service and Portal, Synchronization Service, Certificate Management, CM Client, CM Bulk Client and Add-ins and Extensions.
    ##
    function get_idm_info()
    {
      local_var app_info = {};

      get_kb_item_or_exit("SMB/Microsoft IDM/installed", exit_code:0);
      app_info["Service and Portal"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Service and Portal/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Service and Portal/path")
      };
      app_info["Synchronization Service"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Synchronization Service/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Synchronization Service/path")
      };
      app_info["Certificate Management"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Certificate Management/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Certificate Management/path")
      };
      app_info["CM Client"] = {
        'version': get_kb_item("SMB/Microsoft IDM/CM Client/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/CM Client/path")
      };
      app_info["CM Bulk Client"] = {
        'version': get_kb_item("SMB/Microsoft IDM/CM Bulk Client/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/CM Bulk Client/path")
      };
      app_info["Add-ins and Extensions"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Add-ins and Extensions/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Add-ins and Extensions/path")
      };

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] UNUSED.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly if the install is found vulnerable,
    # or audits out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver, checks, parsed_version;
      local_var component, port, report, vuln;

      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      report = '\nThe following Microsoft Identity Manager components are affected:\n';
      vuln = 0;
      foreach component (keys(app_info))
      {
        report_ver = app_info[component]['version'];
        checks = constraints[component];
        if(isnull(report_ver) || isnull(checks))
          continue;
        parsed_version = parse_version(report_ver);
        matching_constraint = vcf::check_version(version:parsed_version, constraints:checks, strict:FALSE);
        if(vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

        if(!isnull(matching_constraint))
        {
          vuln++;
          fix = matching_constraint.fixed_display;
          if(isnull(fix)) fix = matching_constraint.fixed_version;

          report += '\n  ' + component;
          report += '\n  Installed version : ' + report_ver;
          report += '\n  Fixed version     : ' + fix + '\n';
        }
      }
      port = get_kb_item("SMB/transport");
      if(isnull(port)) port = 445;

      if(vuln)
      {
        store_structured_data(app_info:app_info, fix:fix, fix_version:matching_constraint.fix_version, port:port);
        security_report_v4(severity:severity,
                           port:port,
                           extra:report,
                           xss:flags.xss,
                           xsrf:flags.xsrf,
                           sqli:flags.sqli,
                           proto:app_info.proto);
      }
      else
      {
        vcf::audit();
      }

      return vcf::vcf_exit(0);
    }

  }

  namespace axis
  {
    ##
    # Gather the "AXIS device" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_combined_installs()``.
    ##
    function get_app_info()
    {
      local_var app_info = {};
      local_var installs, pref_install, i;

      installs = get_combined_installs(app_name:"AXIS device", exit_if_not_found:TRUE);
      installs = installs[1];

      pref_install = 0;
      for (i = 0; i < max_index(installs); i++)
      {
        if(installs[i]['confidence'] > installs[pref_install]['confidence'])
          pref_install = i;
      }
      app_info = installs[pref_install];

      app_info.parsed_version = parse_version(app_info.version);

      return app_info;
    }

    ##
    # Generate a vcf constraint array from a per-model patch array.
    #
    # @param [app_info:array] The app information array.
    # @param [patch_array:array] The patch array containing the per-model-ordered patches.
    #
    # @return [array|NULL] The generated vcf constraint array, or NULL if an error occurred.
    ##
    function generate_constraints(app_info, patch_array)
    {
      local_var constraints = [];
      local_var version_list, min_ver, max_ver, last_ver, fix_ver, maj_ver, i;

      if(!app_info) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(!patch_array) return vcf::arg_error(arg:"patch_array", func:FUNCTION_NAME);

      version_list = patch_array[app_info.model];
      if(!version_list)
        vcf::audit();

      foreach fix_ver (version_list)
      {
        maj_ver = split(fix_ver, sep:'.', keep:FALSE);
        maj_ver = maj_ver[0];
        if(maj_ver > max_ver)
          max_ver = maj_ver;
      }

      for (i = 0; i <= max_ver; i++)
      {
        foreach fix_ver (version_list)
        {
          maj_ver = split(fix_ver, sep:'.', keep:FALSE);
          maj_ver = maj_ver[0];
          if(maj_ver == i)
          {
            if(last_ver == 0)
            {
              constraints = make_list(constraints, [{ "fixed_version" : fix_ver }]);
              last_ver = maj_ver;
            }
            else
            {
              constraints = make_list(constraints, [{ "min_version" : string(last_ver + 1), "fixed_version" : fix_ver }]);
              last_ver = maj_ver;
            }
          }
        }
      }
      return constraints;
    }
  }

  namespace xenserver
  {
    ##
    # Gather the "Citrix XenServer" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info()
    {
      local_var app_info, matching_constraint, fix;
      app_info = vcf::get_app_info(app:"Citrix XenServer", kb_ver:"Host/XenServer/version");
      app_info.patches = get_kb_item("Host/XenServer/patches");
      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly if the install is found vulnerable,
    # or audits out.
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags)
    {
      local_var matching_constraint, fix, patch, report_items, i, port;
      local_var missing = [];
      local_var ordered_fields = [];

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(!matching_constraint)
        return vcf::audit(app_info);

      if(matching_constraint.fixed_display)
        fix = matching_constraint.fixed_display;
      else if(matching_constraint.fixed_version)
        fix = matching_constraint.fixed_version;

      if(fix)
        vcf::report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity, flags:flags);

      if(matching_constraint.patches)
      {
        foreach patch (matching_constraint.patches)
        {
          if(patch >!< app_info.patches)
            missing = make_list(missing, patch);
        }
      }

      if(max_index(missing) > 0)
      {
        report_items['Installed Version'] = app_info.version;
        ordered_fields = make_list(ordered_fields, 'Installed Version');

        if(max_index(missing) == 1)
        {
          report_items['Missing Hotfix'] = missing[0];
          ordered_fields = make_list(ordered_fields, 'Missing Hotfix');
        }
        else
        {
          for (i = 0; i < max_index(missing); i++)
          {
            report_items['Missing Hotfix ' + string(i + 1)] = missing[i];
            ordered_fields = make_list(ordered_fields, 'Missing Hotfix ' + string(i + 1));
          }
        }
        port = app_info.port;
        if(isnull(port)) port = 0;

        store_structured_data(app_info:app_info, fix:"Hotfix", port:port);

        security_report_v4(severity:severity,
                           port:port,
                           extra:report_items_str(report_items:report_items, ordered_fields:ordered_fields),
                           xss:flags.xss,
                           xsrf:flags.xsrf,
                           sqli:flags.sqli,
                           proto:app_info.proto);
      }
      else
        vcf::audit(app_info);
    }
  }

  namespace ibm_doors_next
  {
    ##
    # Verify that the required IBM Engineering Requirements Management DOORS Next are installed
    # and parse the needed version info
    # original code by BenS
    # Note: this is different from IBM® Engineering Requirements Management DOORS
    ##
    function doors_parser(app_info)
    {
      app_info.display_version = app_info.version;
      var check_string = app_info.version;
      var new_check_string = '';
      check_string = pregmatch(pattern:"(\d+\.\d+\.\d+)( SR(\d+))?( i[fF]ix(\d+))?", string:check_string);

      # EX: Version : 7.0.2 SR1 iFix015
      if (len(check_string) > 1)
      {
        new_check_string = check_string[1];

        if (!empty_or_null(check_string[4]) && 'iFix' >< check_string[4] && !empty_or_null(check_string[5]))
        {
          new_check_string = new_check_string + '.' + check_string[5];
        }
        else
        {
          new_check_string = new_check_string + '.0';
        }
      }
      app_info.version = new_check_string;
      app_info.parsed_version = parse_version(app_info.version);
      return (app_info);
    }

    function get_appinfo()
    {
      var app_info = vcf::get_app_info(app:'IBM Engineering Requirements Management DOORS Next', win_local:TRUE);
      app_info = doors_parser(app_info:app_info);
      return app_info;
    }
  }

  namespace java
  {
    ##
    # Gather the "Java" installs info and puts them into an array.
    #
    # @param [app:list] List of Java flavors.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    #
    # @remark
    # This function will audit out if the detected Java flavour is not supported.
    ##
    function get_app_info(app)
    {
      var j;
      var found_sun = 0;

      foreach j (app)
      {
        if(j == 'Oracle Java')
          found_sun ++;
      }

      if(found_sun >= 1)
        append_element(var:app, value:'Sun Java');

      var appname = 'Java';
      var key;

      get_install_count(app_name:appname, exit_if_zero:TRUE);
      var app_info = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

      var win_local = FALSE;
      if(get_kb_item('SMB/Registry/Enumerated'))
        win_local = TRUE;

      if(win_local)
      {
        var win_port = get_kb_item("SMB/transport");
        if(!win_port) app_info.port = 445;
        else app_info.port = win_port;
      }

      if(app_info['managed'] == 1)
      {
        # Amazon Corretto can be installed on any distro via pkg mgr and will be enumerated as managed,
        # but only AL Local Sec checks would apply, so we want Misc family plugins to fire if
        # managed but os != Amazon Linux
        var al_release = get_kb_item('Host/AmazonLinux/release');
        if((app_info['Application']) == 'Amazon Corretto Java' && (al_release || !isnull(al_release)))
          ::audit(AUDIT_HOST_NOT, 'relevant to this plugin as Java was installed by a package manager');
      }

      # Check for app_info.['Application'], if null get the data from app_info.['Details']
      if(empty_or_null(app_info['Application']) || 'Unknown' >< app_info['Application'])
      {
        # note the first regex includes the string "installation path", just to prioritize the possible
        # Java flavor from app_info.Details
        var application_path = pregmatch(string:app_info['Details'], pattern:"This Java install may be ([A-Za-z].+),.*\s.+.*installation path \(low confidence\)");

        if(!empty_or_null(application_path) && !empty_or_null(application_path[1]))
        {
          app_info['Application'] = application_path[1];
        }
        else
        {
          application_path = pregmatch(string:app_info['Details'], pattern:"This Java install may be ([A-Za-z].+),.*\s.+.* \(low confidence\)");

          if(!empty_or_null(application_path) && !empty_or_null(application_path[1]))
          {
            app_info['Application'] = application_path[1];
          }
          else
          {
            ::audit(AUDIT_HOST_NOT, 'relevant to this plugin as Java installed cannot be identified');
          }
        }
      }

      # Get unique info for each Java flavors, including package_type and version formats

      # note: AdoptOpenJDK and OpenJDK Java have same formats
      if(app_info['Application'] == 'AdoptOpenJDK' || app_info['Application'] == 'OpenJDK Java')
        app_info = adopt_version(app_info:app_info);

      else if(app_info['Application'] == 'Amazon Corretto Java')
        app_info = corretto_version(app_info:app_info);

      else if(app_info['Application'] == 'IBM Java')
        app_info = ibm_version(app_info:app_info);

      else if(app_info['Application'] == 'Azul Zulu Java')
        app_info = zulu_version(app_info:app_info);

      else if(app_info['Application'] == 'Oracle Java' || app_info['Application'] == 'Sun Java')
        app_info = oracle_version(app_info:app_info);

      else
        ::audit(AUDIT_HOST_NOT, 'an affected Java flavor (' + app_info['Application'] + ' detected)');

      var app_key_flag = 0;
      foreach key (keys(app))
      {
        # check app list against the installed java application flavors
        if(app[key] == app_info['Application'])
        {
          app_key_flag = 1;
          if(app_info['display_version'] == 'Unknown')
            # Reported code will only be available for ZULU else its blank
            app_info['display_version'] = app_info['version'] + app_info['Reported Code'];

          app_info.parsed_version = parse_version(app_info.version);
          app_info.app = appname;
          break;
        }
      }
      if(!empty_or_null(app_info) && app_key_flag)
        return app_info;

      else
        ::audit(AUDIT_HOST_NOT, 'an affected Java flavor (' + app_info['Application'] + ' detected)');
    }

    ##
    # Consolidates the app information array for the "Zulu" flavour of Java.
    #
    # @param [app_info:array] The app information array to consolidate.
    #
    # @return [array] The consolidated app info array.
    ##
    function zulu_version(app_info)
    {
      # Version parsing is now handled in detection plugin, java_jre_installed_win.nasl
      # app_info['version'] for zulu is now like '11.47.18 (CA)'
      # this is an invalid 'version' argument in call to 'vcf::check_version', so,
      # need to use app_info['Reported Version']
      if((!app_info['Reported Version']) || (app_info['Reported Version'] == 'Unknown'))
      {
        if(!empty_or_null(app_info['version_without_one']))
          app_info['Reported Version'] = app_info['version_without_one'];
        else
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Reported version and version_without_one do not exist');
      }

      if(!empty_or_null(app_info['Reported Version']) && app_info['version'] =~ '[A-Za-z]')
        app_info['version'] = app_info['Reported Version'];

      if((empty_or_null(app_info['version'])) || (app_info['version'] == 'Unknown'))
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'app_info version is unknown or null');

      if(app_info['Reported Code'] !~ "^(CA|SA|NV)$")
      {
        # check version. if ends odd, add CA, if even add SA
        # https://docs.azul.com/core/zulu-openjdk/versioning-and-naming#:~:text=For%20Azul%20Zulu%208%20and,%3A%20XX.YY.BB.&text=For%20each%20quarterly%20release%2C%20the,version%20(first%20two%20numbers).

        var ld = pregmatch(string:app_info['version'], pattern:"\.(\d)*$");

        if(!empty_or_null(ld) && ld[1] % 2 == 0)
          app_info['Reported Code'] = 'SA';
        else
          app_info['Reported Code'] = 'CA';
      }

      return(app_info);
    }

    ##
    # Consolidates the app information array for the "IBM" flavour of Java.
    #
    # @param [app_info:array] The app information array to consolidate.
    #
    # @return [array] The consolidated app info array.
    ##
    function ibm_version(app_info)
    {
      # Fix display_version with this format 1.8.0_292 or 14.0.1 2020-04-14
      # ex. 'java version "1.8.0_261"\\nJava(TM) SE Runtime Environment (build 8.0.6.16 - pxi3280sr6fp16-20200902_01(SR6 FP16))\\nIBM J9 VM (
      var l_ver = pregmatch(string:app_info['Version Output'], pattern:"version.+(1\.[0-9.]+_[0-9]+)");

      # ex. IBM Semeru Runtime Certified Edition 11.0.12.0 (build 11.0.12+7) Eclipse OpenJ9
      var h_ver = pregmatch(string:app_info['Version Output'], pattern:"Edition (([0-9]+\.){3}[0-9]+) ");

      if(!empty_or_null(h_ver) && !empty_or_null(h_ver[1]))
        app_info['display_version'] = h_ver[1];

      else if(!empty_or_null(l_ver) && !empty_or_null(l_ver[1]))
        app_info['display_version'] = l_ver[1];

      else
        app_info['display_version'] = 'Unknown';


      if(empty_or_null(app_info['Reported Version']) || 'nknown' >< app_info['Reported Version'])
      {
        # for IBM Java with higher version format ex. IBM Semeru Runtime Certified Edition 11.0.12.0 (build 11.0.12+7) Eclipse OpenJ9
        var hrep_ver = pregmatch(string:app_info['Version Output'], pattern:"build (([0-9]+\.){2}[0-9]+\+[0-9]+)");

        if(!empty_or_null(hrep_ver) && !empty_or_null(hrep_ver[1]))
        {
          var hrep_fix = str_replace(string:hrep_ver[1], find:'+', replace:'.');
          app_info['Reported Version'] = hrep_fix;
        }

        # for IBM Javo Java with lower version format ex. (build 8.0.6.16 - pxi3280sr6fp16-20200902_01(SR6 FP16))\nIBM J9
        else if(!empty_or_null(app_info['Version Output']))
        {
          var lrep_ver = pregmatch(string:app_info['Version Output'], pattern:"build (([0-9]+\.){3}[0-9]+) -");

          if(!empty_or_null(lrep_ver) && !empty_or_null(lrep_ver[1]))
          {
            app_info['Reported Version'] = lrep_ver[1];
          }
        }
        # for IBM Java if we didn't retrieve Reported Version or Version Output, we can rely on version_without_one
        else if(!empty_or_null(app_info['version_without_one']) && empty_or_null(hrep_ver) && empty_or_null(lrep_ver))
        {
          # some Reported Versions may have an underscore so replace it with a dot
          var ver_wo_one_underscore = pregmatch(string:app_info['version_without_one'], pattern:"([1-9]+\.[0-9.]+_[0-9]+)");
          if(!empty_or_null(ver_wo_one_underscore) && !empty_or_null(ver_wo_one_underscore[1]))
          {
            var ver_wo_one_fixed = str_replace(string:ver_wo_one_underscore[1], find:'_', replace:'.');
            app_info['Reported Version'] = ver_wo_one_fixed;
          }
          else
            app_info['Reported Version'] = app_info['version_without_one'];
        }
        else
        {
          dbg::detailed_log(
            lvl: 1,
            src: FUNCTION_NAME,
            msg: "Java version package unknown",
            msg_details: {
              "Version": {"lvl": 1, "value": app_info['Version Output']}});
          ::audit(AUDIT_UNKNOWN_APP_VER, app_info['Application']);
        }
      }

      app_info['version'] = app_info['Reported Version'];
      if(!empty_or_null(app_info['display_version']) && app_info['display_version'] != 'Unknown')
        app_info['display_version'] = app_info['display_version'] + ' / build ' + app_info['version'];
      return(app_info);
    }

    ##
    # Consolidates the app information array for the "Corretto" flavour of Java.
    #
    # @param [app_info:array] The app information array to consolidate.
    #
    # @return [array] The consolidated app info array.
    ##
    function corretto_version(app_info)
    {
      # parse versions like 11.0.7.10.1-1 as 11.0.7.10.1.1
      vcf::add_separator('-');

      # Fix display_version with this format 1.8.0_292 or 14.0.1 2020-04-14
      # ex. openjdk version "1.8.0_302"\nOpenJDK Runtime Environment Corretto-8.302.08.1 (build 1.8.0_302-b08)
      var l_ver = pregmatch(string:app_info['Version Output'], pattern:'version.+(1\\.[0-9.]+_[0-9]+)["\\s]');

      # ex. openjdk 11.0.12 2021-07-20 LTS\nOpenJDK Runtime Environment Corretto-11.0.12.7.1 (build 11.0.12+7-LTS)
      var h_ver = pregmatch(string:app_info['Version Output'], pattern:"((([0-9.]+\.){2}[0-9.]+) [0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]))");

      if(!empty_or_null(h_ver) && !empty_or_null(h_ver[1]))
        app_info['display_version'] = h_ver[1];

      else if(!empty_or_null(l_ver) && !empty_or_null(l_ver[1]))
        app_info['display_version'] = l_ver[1];

      else
        app_info['display_version'] = 'Unknown';

      if(empty_or_null(app_info['Reported Version']) || 'Unknown' >< app_info['Reported Version'])
      {
        # for Amazon Corretto Java with higher version format ex. Corretto-11.0.12.7.1 (build 11.0.12+7-LTS)
        var hrep_ver = pregmatch(string:app_info['Version Output'], pattern:"Corretto-(([0-9]+\.){4}[0-9])");

        if(!empty_or_null(hrep_ver) && !empty_or_null(hrep_ver[1]))
          app_info['Reported Version'] = hrep_ver;

        # for Amazon Corretto Java with lower version format ex. Corretto-8.302.08.1 (build 1.8.0_302-b08)
        else
        {
          var lrep_ver = pregmatch(string:app_info['Version Output'], pattern:"Corretto-(([0-9]+\.){3}[0-9])");

          if(!empty_or_null(lrep_ver) && !empty_or_null(lrep_ver[1]))
          {
            app_info['Reported Version'] = lrep_ver[1];
          }
          else if(!empty_or_null(app_info['version_without_one']))
          {
            app_info['Reported Version'] = app_info['version_without_one'];
          }
          else
          {
            dbg::detailed_log(
              lvl: 1,
              src: FUNCTION_NAME,
              msg: "Java version package unknown",
              msg_details: {
                "Version": {"lvl": 1, "value": app_info['Version Output']}});
            ::audit(AUDIT_UNKNOWN_APP_VER, app_info['Application']);
          }
        }
      }
      # If Reported Version is missing the trailing digit, use version_without_one
      if(!empty_or_null(app_info['Reported Version']) && !empty_or_null(app_info['version_without_one']))
      {
        var ac_r_ver = str_replace(string:app_info['Reported Version'], find:'.', replace:'');
        var ac_ver_wo_one = str_replace(string:app_info['version_without_one'], find:'.', replace:'');
        if(ac_r_ver < ac_ver_wo_one)
          app_info['Reported Version'] = app_info['version_without_one'];
      }

      app_info['version'] = app_info['Reported Version'];
      if(!empty_or_null(app_info['display_version']) && app_info['display_version'] != 'Unknown')
        app_info['display_version'] = app_info['display_version'] + ' / build ' + app_info['version'];
      return(app_info);
    }

    ##
    # Consolidates the app information array for the "Adopt" flavour of Java.
    #
    # @param [app_info:array] The app information array to consolidate.
    #
    # @return [array] The consolidated app info array.
    ##
    function adopt_version(app_info)
    {
      # Fix display_version with this format 1.8.0_292 or 14.0.1 2020-04-14
      # ex. openjdk version "1.8.0_292"\nOpenJDK Runtime Environment (build 1.8.0_292-b10)
      var l_ver = pregmatch(string:app_info['Version Output'], pattern:"version.+(1\.[0-9.]+_[0-9]+)");

      # ex. openjdk 14.0.1 2020-04-14\nOpenJDK Runtime Environment AdoptOpenJDK (build 14.0.1+7)
      var h_ver = pregmatch(string:app_info['Version Output'], pattern:"((([0-9.]+\.){2}[0-9.]+) [0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]))");

      if(!empty_or_null(h_ver) && !empty_or_null(h_ver[1]))
        app_info['display_version'] = h_ver[1];

      else if(!empty_or_null(l_ver) && !empty_or_null(l_ver[1]))
        app_info['display_version'] = l_ver[1];

      else
        app_info = fix_default_version(app_info:app_info);

      if(!empty_or_null(app_info['version_without_one']))
      {
       # for Adopt or OpenJDK fix version_without_one to remove underscore, ex: 11.0_16 to 11.0.16
       var ver_wo_one = pregmatch(string:app_info['version_without_one'], pattern:"([1-9]+\.[0-9.]+_[0-9]+)");
       if(!empty_or_null(ver_wo_one))
       {
        var fix_ver_wo_one = str_replace(string:ver_wo_one[1], find:'_', replace:'.');
        app_info['version_without_one'] = fix_ver_wo_one;
       }
      }

      if(!empty_or_null(app_info['Reported Version']))
      {
       # for Adopt or OpenJDK fix Reported Version to remove underscore, ex: 11.0_16 to 11.0.16
       var ver_rep = pregmatch(string:app_info['Reported Version'], pattern:"^([1-9]+\.[0-9.]+_[0-9]+)$");
       if(!empty_or_null(ver_rep))
       {
        var fix_ver_rep = str_replace(string:ver_rep[1], find:'_', replace:'.');
        app_info['Reported Version'] = fix_ver_rep;
       }
      }

      # check for Reported Version
      if(empty_or_null(app_info['Reported Version']) || 'Unknown' >< app_info['Reported Version'])
      {
        # for AdoptOpenJDK and OpenJDK Java with higher version format ex. AdoptOpenJDK (build 14.0.1+7)
        var hrep_ver = pregmatch(string:app_info['Version Output'], pattern:"build ([0-9.]+\+[0-9]+)");
        # for AdoptOpenJDK and OpenJDK Java with high version format with leading '1.'
        var hver_w_one = pregmatch(string:app_info['version'], pattern:"1\.([0-9]{2}\.[0-9]{1,3}\.[0-9]{1,3})");

        if(!empty_or_null(hrep_ver) && !empty_or_null(hrep_ver[1]))
        {
          var fix_hrep = str_replace(string:hrep_ver[1], find:'+', replace:'.');
          app_info['Reported Version'] = fix_hrep;
        }
        # for higher vers (1.xx.x.x) of Adopt w. leading '1.' and no symbols (ex. 1.15.0.02), and no 'Reported Version' to use
        else if(!empty_or_null(hver_w_one) && !empty_or_null(hver_w_one[1]) && !empty_or_null(app_info['version_without_one']))
          app_info['Reported Version'] = app_info['version_without_one'];

        # for AdoptOpenJDK and OpenJDK Java with lower version format ex. (build 1.8.0_292-b10)
        else
        {
          var fix_lrep = '';
          var lrep_ver = pregmatch(string:app_info['Version Output'], pattern:"build ([0-9.]+_[0-9]+\-b[0-9]+)");

          if(!empty_or_null(lrep_ver) && !empty_or_null(lrep_ver[1]))
          {
            fix_lrep = str_replace(string:lrep_ver[1], find:'-b', replace:'.');
            fix_lrep = str_replace(string:fix_lrep, find:'_', replace:'.');
            fix_lrep = pregmatch(string:fix_lrep, pattern:"1\.(([0-9]+\.){3}[0-9]+)");
            if(empty_or_null(fix_lrep))
              ::audit(AUDIT_UNKNOWN_APP_VER, app_info['Application']);
            app_info['Reported Version'] = fix_lrep[1];
          }
          else
          {
            if(!empty_or_null(app_info['version']) && !empty_or_null(app_info['display_version']))
            {
              return(app_info);
            }
            else
            {
              dbg::detailed_log(
                lvl: 1,
                src: FUNCTION_NAME,
                msg: "Java version package unknown",
                msg_details: {
                  "Version": {"lvl": 1, "value": app_info['Version Output']}});
              ::audit(AUDIT_UNKNOWN_APP_VER, app_info['Application']);
            }
          }
        }
      }

      app_info = trim_version(app_info:app_info);
      return(app_info);
    }

    ##
    # Consolidates the app information array for the "Oracle" flavour of Java.
    #
    # @param [app_info:array] The app information array to consolidate.
    #
    # @return [array] The consolidated app info array.
    ##
    function oracle_version(app_info)
    {
      # Added if condition if display_version is epmty get value from Version Output
      if(empty_or_null(app_info['display_version']))
      {
        # Fix display_version with this format 1.8.0_292 or 14.0.1 2020-04-14
        # ex. java version "1.8.0_251"\nJava(TM) SE Runtime Environment (build 1.8.0_251-b08)\nJava HotSpot(TM) 64-Bit Server VM
        var l_ver = pregmatch(string:app_info['Version Output'], pattern:"version.+(1\.[0-9.]+_[0-9]+)");

        # ex. java version "14.0.1" 2020-04-14\nJava(TM) SE Runtime Environment (build 14.0.1+7)\nJava HotSpot(TM) 64-Bit Server VM
        var h_ver = pregmatch(string:app_info['Version Output'], pattern:"version.+((9|([0-9]{2}))\.[0-9]{1,2}\.[0-9]{1,2}.+)\\nJava\(TM\)");

        if(!empty_or_null(h_ver) && !empty_or_null(h_ver[1]))
        {
          var fix_hver = str_replace(string:h_ver[1], find:'"', replace:'');
          app_info['display_version'] = fix_hver;
        }

        else if(!empty_or_null(l_ver) && !empty_or_null(l_ver[1]))
          app_info['display_version'] = l_ver[1];

        else
          app_info = fix_default_version(app_info:app_info);
      }
      else
      {
        # double check display version for java 11 and above, must not contain 1.
        var display_ver_check = pregmatch(string:app_info['display_version'], pattern:"1\.(1[0-9.]+.[0-9]+)");
        if(!empty_or_null(display_ver_check) && !empty_or_null(display_ver_check[1]))
          app_info['display_version'] = display_ver_check[1];
      }

      # for Oracle and Sun Java fix version_without_one to remove underscore, ex: 17.0_04 to 17.0.04
      var ver_wo_one = pregmatch(string:app_info['version_without_one'], pattern:"([1-9]+\.[0-9.]+_[0-9]+)");
      if(!empty_or_null(ver_wo_one))
      {
        var fix_ver_wo_one = str_replace(string:ver_wo_one[1], find:'_', replace:'.');
        app_info['version_without_one'] = fix_ver_wo_one;
      }

      # check for Reported Version
      if(empty_or_null(app_info['Reported Version']) || 'Unknown' >< app_info['Reported Version'])
      {
        # for Oracle Java and  Sun Java with higher version format ex. AdoptOpenJDK (build 14.0.1+7)
        var hrep_ver = pregmatch(string:app_info['Version Output'], pattern:"build ([0-9.]+\+[0-9]+)");

        if(!empty_or_null(hrep_ver) && !empty_or_null(hrep_ver[1]))
        {
          var fix_hrep = str_replace(string:hrep_ver[1], find:'+', replace:'.');
          app_info['Reported Version'] = fix_hrep;
        }

        # for Oracle Java and  Sun Java with lower version format ex. (build 1.8.0_251-b08)
        else
        {
          var fix_lrep = '';
          var lrep_ver = pregmatch(string:app_info['Version Output'], pattern:"build ([0-9.]+_[0-9]+\-b[0-9]+)");

          if(!empty_or_null(lrep_ver) && !empty_or_null(lrep_ver[1]))
          {
            fix_lrep = str_replace(string:lrep_ver[1], find:'-b', replace:'.');
            fix_lrep = str_replace(string:fix_lrep, find:'_', replace:'.');
            fix_lrep = pregmatch(string:fix_lrep, pattern:"1\.(([0-9]+\.){3}[0-9]+)");
            if(empty_or_null(fix_lrep))
              ::audit(AUDIT_UNKNOWN_APP_VER, app_info['Application']);
            app_info['Reported Version'] = fix_lrep[1];
          }
          else
          {
            if(!empty_or_null(app_info['version']) && !empty_or_null(app_info['display_version']))
            {
              # Double check if app_info['version'] is not version with one, check first app_info['version_without_one']
              var ver_check = pregmatch(string:app_info['version'], pattern:"1\.([0-9.]+.[0-9]+)");
              if(!empty_or_null(ver_check) && !empty_or_null(ver_check[1]))
              {
                if(!empty_or_null(app_info['version_without_one']))
                {
                  app_info['version'] = app_info['version_without_one'];
                }
                else
                {
                  app_info['version'] = ver_check[1];
                }
              }

              app_info = trim_version(app_info:app_info);

              if(!empty_or_null(app_info['display_version']) && app_info['display_version'] != 'Unknown')
               app_info['display_version'] = app_info['display_version'] + ' / build ' + app_info['version'];
              return(app_info);
            }
            else
            {
              dbg::detailed_log(
                lvl: 1,
                src: FUNCTION_NAME,
                msg: "Java version package unknown",
                msg_details: {
                  "Version": {"lvl": 1, "value": app_info['Version Output']}});
              ::audit(AUDIT_UNKNOWN_APP_VER, app_info['Application']);
            }
          }
        }
      }

      app_info = trim_version(app_info:app_info);

      if(!empty_or_null(app_info['display_version']) && app_info['display_version'] != 'Unknown')
        app_info['display_version'] = app_info['display_version'] + ' / build ' + app_info['version'];
      return(app_info);

    }

    ##
    # Remove the underscore from the display version of certain Java versions.
    #
    # @param [app_info:array] The app information array to fix.
    #
    # @return [array] The fixed app info array.
    #
    # @remark
    # This function removes underscores from both the display version and version of Java installs with
    # version ``1.xx.yyy_zzz``.
    # But for versions like ``1.x.yyy_zzz`` it only removes underscore in the version, not the display version.
    ##
    function fix_default_version(app_info)
    {
      #check if display version a lower version format 1.8.0_292 or higher version format 1.11.0_292, if high we fix the higher version format
      if(!empty_or_null(app_info['display_version']))
      {
        var dis_ver_high = pregmatch(string:app_info['display_version'], pattern:"1\.([0-9]{2}\.[0-9]{1,3}_[0-9]{1,3})");

        if(!empty_or_null(dis_ver_high) && !empty_or_null(dis_ver_high[1]))
        {
          # we need to fix the display version for higher version format ex. 1.11.0_292
          var display_ver = str_replace(string:dis_ver_high[1], find:'_', replace:'.');
          app_info['display_version'] = display_ver;
          app_info['version'] = display_ver;
        }
        else
        {
          var dis_ver_low = pregmatch(string:app_info['display_version'], pattern:"1\.([0-9]\.[0-9]{1,3}_[0-9]{1,3})");

          if(!empty_or_null(dis_ver_low) && !empty_or_null(dis_ver_low[1]))
          {
            # we need to fix the version for lower version format ex. 1.8.0_292 to 8.0.292
            var display_ver_l = str_replace(string:dis_ver_low[1], find:'_', replace:'.');
            app_info['version'] = display_ver_l;
          }
          else
            app_info['display_version'] = 'Unknown';
        }
      }
      else
      {
        if(!empty_or_null(app_info['display_version']))
        {
          app_info['display_version'] = app_info['version'];
        }
        else
          app_info['display_version'] = 'Unknown';
      }

      return(app_info);
    }

    ##
    # Trim the Java version to only 3 segments.
    #
    # @param [app_info:array] The app information array to trim.
    #
    # @return [array] The app info array with the trimmed version.
    ##
    function trim_version(app_info)
    {
      #   - We do this because Adopt and openjdk versions can have 4 segments,
      #     Ex. 1.8.0_292-b10 actual version 8.0.292.10 but
      #     the listed affected / fixed versions only refer to 3.
      #     So, affected 8.0.292.10 actual version 8.0.292

      if(!empty_or_null(app_info['version_without_one']))
        app_info['Reported Version'] = app_info['version_without_one'];
      else
      {
        # Double checked if Reported Version is found it must not include prefix 1. Ex 1.8.0.123 should just be 8.0.123
        if(!empty_or_null(app_info['Reported Version']))
        {
          var rep_ver = pregmatch(string:app_info['Reported Version'], pattern:"^1\.(.*)");
          if(!empty_or_null(rep_ver) && !empty_or_null(rep_ver[1]))
            app_info['Reported Version'] = rep_ver[1];
        }
      }

      var max_segs = 3;
      var max_segs_parts = make_list();
      var split_ver = split(app_info['Reported Version'], sep:'.', keep:FALSE);
      var i;

      for (i = 0; i < max_segs; i++)
      {
        if(!empty_or_null(split_ver[i]))
        {
            max_segs_parts[i] = int(split_ver[i]);
        }
      }

      app_info.version = join(max_segs_parts, sep:".");
      return(app_info);
    }
  }

  namespace dell_bios_win
  {
    ##
    # Gather the Dell System BIOS installs info and puts them into an array.
    #
    # @param [app:string] The app name to check for.
    #
    # @return [array] The app info array containing:
    # app name, version, parsed version, display version, manufacturer, model, BIOSConnect status,
    # HTTPSBoot status, SecureBoot status.
    ##
    function get_app_info(app)
    {
      local_var app_info = {};

      local_var bios_name = get_kb_item_or_exit('BIOS/Vendor');

      # Alienware is detected as its own vendor but is Dell
      if(app != bios_name && 'Alienware' >!< bios_name)
      {
        ::audit(AUDIT_HOST_NOT, 'affected');
      }

      local_var bios_kb = get_kb_list('BIOS/*');

      app_info.app = bios_kb['BIOS/Vendor'];
      app_info.version = bios_kb['BIOS/Version'];
      if(empty_or_null(app_info.version) || app_info.version == UNKNOWN_VER)
        ::audit(AUDIT_UNKNOWN_APP_VER, "Dell System BIOS");
      app_info.parsed_version = vcf::parse_version(app_info.version);
      app_info.display_version = bios_kb['BIOS/Version'];
      app_info.manufacturer = bios_kb['BIOS/Manufacturer'];
      app_info.model = bios_kb['BIOS/Model'];
      app_info.bios_connect = bios_kb['BIOS/BIOSConnect_Status'];
      app_info.https_boot = bios_kb['BIOS/HttpsBoot_Status'];
      app_info.secure_boot = bios_kb['BIOS/SecureBoot'];
      app_info["cpe/v23"] = "cpe:2.3:o:dell:bios";

      return app_info;
    }
  }

  namespace xen_hypervisor
  {
    ##
    # Gather the Xen Hypervisor installs info and puts them into an array.
    #
    # @param [app:string] The app name to check for.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    ##
    function get_app_info(app)
    {
      local_var install;

      install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

      install.changeset = install['Changeset'];
      install.manage_status = install['Managed status'];
      install.app = app;

      return install;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [fixes:array] The array containing the fixed versions information.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly if the install is found vulnerable,
    # or audits out.
    ##
    function check_version_and_report(app_info, fixes, severity)
    {
      local_var app_name, version, display_version, path, managed_status, changeset;
      local_var fix, ret, ver_branch, affected_changeset, items, order, report, fix_ver;

      app_name        = app_info.app;
      version         = app_info.version;
      display_version = app_info.display_version;
      path            = app_info.path;
      managed_status  = app_info.managed_status;
      changeset       = app_info.changeset;
      fix = NULL;

      if(!empty_or_null(changeset))
        display_version += ' (changeset ' + changeset + ')';

      # Installations that are vendor-managed are handled by OS-specific local package checks
      if(managed_status == 'managed')
        ::audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

      foreach ver_branch (keys(fixes))
      {
        if(version =~ fixes[ver_branch]['affected_ver_regex'])
        {
          ret = ver_compare(ver:version, fix:fixes[ver_branch]['fixed_ver']);

          if(ret < 0)
          {
            fix = fixes[ver_branch]['fixed_ver_display'];
            fix_ver = fixes[ver_branch]['fixed_ver'];
          }
          else if(ret == 0)
          {
            if(empty_or_null(changeset))
            {
              fix = fixes[ver_branch]['fixed_ver_display'];
              fix_ver = fixes[ver_branch]['fixed_ver'];
            }
            else
            {
              foreach affected_changeset (fixes[ver_branch]['affected_changesets'])
              {
                if(changeset == affected_changeset)
                {
                  fix = fixes[ver_branch]['fixed_ver_display'];
                  fix_ver = fixes[ver_branch]['fixed_ver'];
                }
              }
            }
          }
        }
      }

      if(empty_or_null(fix))
        ::audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

      items  = make_array(
        'Installed version', display_version,
        'Fixed version', fix,
        'Path', path
      );

      order  = make_list('Path', 'Installed version', 'Fixed version');
      report = report_items_str(report_items:items, ordered_fields:order) + '\n';

      store_structured_data(app_info:app_info, fix:fix, fix_version:fix_ver, port:0);
      security_report_v4(port:0, extra:report, severity:severity);
    }
  }

  namespace wordpress
  {
    namespace plugin
    {
      ##
      # Gather the WordPress plugin installs info and puts them into an array.
      #
      # @param [plugin:string] The WordPress plugin name to search for.
      #
      # @return [array] The consolidated app info array, originally gathered from the scartchpad ``wordpress_plugins`` table.
      #
      # @remark
      # This function will branch out if multiple installs are found. But it will audit out if none are found.
      ##
      function get_app_info(plugin)
      {
        local_var app_info, plugin_info;
        if(isnull(plugin)) return arg_error(arg:"plugin", func:FUNCTION_NAME);

        if(query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'wordpress_plugins';"))
          plugin_info = query_scratchpad("SELECT name, version, friendly_name, path, port
                                          FROM wordpress_plugins WHERE name = ?;", plugin);
        else
          vcf::vcf_exit(0);

        if(plugin_info)
        {
          app_info = branch(plugin_info);

          # Inform customers they need paranoid if they want to fire against unknown versions
          if(tolower(app_info.version) == 'unknown' && report_paranoia < 2)
            exit(0, 'The version of WP Plugin: ' + app_info.friendly_name + ' could not be determined, but it may ' +
                'still be vulnerable. To report on unknown versions, please enable Paranoid scanning.');

          app_info.parsed_version = vcf::parse_version(app_info.version);
          app_info.webapp = TRUE;
          app_info.app = "WP Plugin: " + app_info.friendly_name;
          app_info["cpe/v23"] = "cpe:2.3:a:wordpress:wordpress";
          return app_info;
        }
        else
          vcf::audit();
      }
    }
  }

  namespace samba
  {
    ##
    # Gather the "Samba" installs info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # version, parsed version, port and app name.
    #
    # @remark
    # This function will exit if the KB item "SMB/NativeLanManager" is not set.
    ##
    function get_app_info()
    {
      local_var app_info = {};
      local_var port, lanman, version;

      port = get_kb_item("SMB/transport");
      if(!port) port = 445;

      lanman = get_kb_item_or_exit("SMB/NativeLanManager");
      if("Samba " >!< lanman) vcf::audit(AUDIT_NOT_LISTEN, "Samba", port);

      version = lanman - 'Samba ';

      app_info.version = version;
      app_info.parsed_version = parse_version(app_info.version);
      app_info.port = port;
      app_info.app = "Samba";
      app_info["cpe/v23"] = "cpe:2.3:a:samba:samba";

      return app_info;
    }
  }

  namespace joomla
  {
    namespace extension
    {
      ##
      # Gather the Joomla extension installs info and puts them into an array.
      #
      # @param [extension:string] The Joomla extension name to search for.
      # @param [subextension:string] The Joomla sub-extension name to search for (optional).
      #
      # @return [array] The consolidated app info array, originally gathered from the scartchpad ``joomla_extensions`` table.
      #
      # @remark
      # This function will branch out if multiple installs are found. But it will audit out if none are found.
      ##
      function get_app_info(extension, subextension)
      {
        local_var app_info, plugin_info, sp_query, ext_name;
        if(isnull(extension)) return arg_error(arg:"extension", func:FUNCTION_NAME);

        if(query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'joomla_extensions';"))
        {
          if(subextension)
            plugin_info = query_scratchpad("SELECT
                  joomla_subextensions.'version' AS 'version',
                  joomla_extensions.'pretty_name' AS 'pretty_name',
                  joomla_extensions.'name' AS 'name',
                  joomla_extensions.'port' AS 'port',
                  joomla_extensions.'path' AS 'path',
                  joomla_subextensions.'name' AS 'subextension_name',
                  joomla_subextensions.'version' AS 'version'
                FROM joomla_extensions
                INNER JOIN joomla_subextensions ON joomla_extensions.'id' = joomla_subextensions.'extension_id'
                WHERE joomla_extensions.'extension' = ? AND joomla_subextensions.'subextension' = ?;",
                extension, subextension);
          else
            plugin_info = query_scratchpad("SELECT
                  joomla_extensions.'pretty_name' AS 'pretty_name',
                  joomla_extensions.'name' AS 'name',
                  joomla_extensions.'version' AS 'version',
                  joomla_extensions.'port' AS 'port',
                  joomla_extensions.'path' AS 'path'
                FROM joomla_extensions
                WHERE joomla_extensions.'extension' = ?;",
                extension);
        }
        else
          vcf::vcf_exit(0);

        if(plugin_info)
        {
          app_info = branch(plugin_info);
          app_info.webapp = TRUE;
          app_info.parsed_version = vcf::parse_version(app_info.version);

          if(app_info.pretty_name)
            ext_name = app_info.pretty_name;
          else if(app_info.name)
            ext_name = app_info.name;

          if(ext_name && app_info.subextension_name)
          {
            app_info.app = "Joomla! Extension: " + ext_name + " Subextension: " + app_info.subextension_name;
          }
          else if(ext_name)
          {
            app_info.app = "Joomla! Extension: " + ext_name;
          }
          else
          {
            app_info.app = "Joomla! Extension";
          }

          app_info["cpe/v23"] = "cpe:2.3:a:joomla:joomla\!";

          return app_info;
        }
        else
          vcf::audit();
      }
    }
  }

  namespace oracle_bi_publisher
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If there are no matching constraints the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver, patch, bundle;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;
        if(!isnull(matching_constraint.patch)) patch = matching_constraint.patch;
        if(!isnull(matching_constraint.bundle)) bundle = matching_constraint.bundle;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags, patch:patch, bundle:bundle);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    # @param [patch:string] The required patch to fix the vulnerability.
    # @param [bundle:string] The bundle in which the patch is present.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags, patch, bundle)
    {
      local_var report, version, port;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(patch)) return arg_error(arg:"patch", func:FUNCTION_NAME);
      if(isnull(bundle)) return arg_error(arg:"bundle", func:FUNCTION_NAME);

      if(isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(
        version:version,
        fix:fix,
        path:app_info.path,
        source:app_info.source,
        webapp:app_info.webapp,
        port:app_info.port,
        patch:patch,
        bundle:bundle
      );
      if(is_error(report)) return vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

      store_structured_data(app_info:app_info, fix:fix, fix_version:fix_version, port:port);

      security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      return vcf_exit(0);
    }

    ##
    # Builds the vulnerability report.
    #
    # @param [version:string] The installed version of the app.
    # @param [path:string] The install path of the app.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [webapp:boolean] Falg to tell if the app install was found as being a webapp install.
    # @param [port:integer] The port on which the install was found.
    # @param [source:string] The detection source.
    # @param [patch:string] The required patch to fix the vulnerability.
    # @param [bundle:string] The bundle in which the patch is present.
    #
    # @return [string] The formatted report string returned by ``report_items_str()``.
    ##
    function build_report(version, path, fix, webapp, port, source, patch, bundle)
    {
      local_var order, report, report_items;

      report_items = {
        "Installed version" : version,
        "Fixed version"     : fix,
        "Required patch"    : patch,
        "Bundled in"        : bundle
      };
      order = ["Installed version", "Fixed version", "Required patch", "Bundled in"];

      if(!empty_or_null(path))
      {
        if(webapp)
        {
          if(isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);
          report_items["URL"] = build_url2(qs:path, port:port);
          order = ["URL", "Installed version", "Fixed version", "Required patch", "Bundled in"];
        }
        else
        {
          report_items["Path"] = path;
          order = ["Path", "Installed version", "Fixed version", "Required patch", "Bundled in"];
        }
      }
      else if(source)
      {
        report_items["Source"] = source;
        order = ["Source", "Installed version", "Fixed version", "Required patch", "Bundled in"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace cisco_ssm
  {
    ##
    # Adds additional separator
    ##
    function initialize()
    {
      add_separator('-');
    }
  }

  namespace palo_alto
  {
    ##
    # Adds appropriate conversion values and additional separator
    ##
    function initialize()
    {
      add_conversions({'h':0});
      add_separator('-');
    }
  }

  namespace php
  {
    ##
    # Adds appropriate conversion values.
    #
    # @remark
    # This function uses ``add_conversions()``.
    ##
    function initialize()
    {
      add_conversions({'RC':conversions.rc});
    }

    ##
    # Gather the PHP installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install was found.
    #
    # @return [array] The app info array containing:
    # app name, version, source and parsed version.
    #
    # @remark
    # The function will audit out if the scan is not paranoid and the install's version is detected as
    # backported.  And it will also exit if it was unable to parsed the intall's version.
    ##
    function get_app_info(port)
    {
      local_var install = {};
      local_var php, kb_backport, backported;
      local_var parsed_version;

      if(isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);

      install.app = "PHP";

      php = get_php_from_kb(port:port, exit_on_fail:TRUE);

      install.version = php.ver;
      install.source = php.src;

      kb_backport = "www/php/" + port + "/" + install.version + "/backported";
      backported = get_kb_item_or_exit(kb_backport, exit_code:1);
      if(report_paranoia < 2 && backported) ::audit(AUDIT_BACKPORT_SERVICE, port, "PHP " + install.version + " install");

      # Go ahead and parse the app's version here and store it
      parsed_version = parse_version(install.version);
      if(is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      install.parsed_version = parsed_version;
      install["cpe/v23"] = "cpe:2.3:a:php:php";

      return install;
    }
  }

  # HP - Integrated Lights Out
  namespace ilo
  {
    ##
    # Adds appropriate conversion values.
    #
    # @remark
    # This function uses ``add_conversions()``.
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta});
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If the detected generation doesn't match any constraints, the function audits out.
    # If the generation does match a constraint then that constraint is used in ``vcf::check_version_and_report()``.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var generation = get_kb_item_or_exit('ilo/generation');
      local_var moonshot = get_kb_item('www/ilo/moonshot');
      local_var i;
      local_var audit_product_msg;

      audit_product_msg = 'iLO ' + generation;

      if(moonshot)
        audit_product_msg = audit_product_msg + ' (Moonshot)';

      # There are 3 possibilities here according to observed advisories:
      # 1. Mainline iLO [1-5] generation & fix (only interested in this if we haven't detected a moonshot device).
      # 2. Moonshot firmware (with an iLO generation mentioned).
      # 3. Moonshot firmware (no iLO generation mentioned)
      for (i = 0; i < max_index(constraints); i++)
      {
        if(isnull(moonshot))
        { # Scenario 1
          if(constraints[i]['generation'] == generation && isnull(constraints[i]['moonshot']))
          {
            vcf::check_version_and_report(
              app_info:app_info,
              constraints:[constraints[i]],
              severity:severity,
              flags:flags
            );
          }
        }
        else if(constraints[i]['moonshot'] && constraints[i]['generation'] == generation)
        { # Scenario 2
          vcf::check_version_and_report(
            app_info:app_info,
            constraints:[constraints[i]],
            severity:severity,
            flags:flags
          );
        }
        else if(constraints[i]['moonshot'] && isnull(constraints[i]['generation']))
        { # Scenario 3
          vcf::check_version_and_report(
            app_info:app_info,
            constraints:[constraints[i]],
            severity:severity,
            flags:flags
          );
        }
      }
      # Generation doesn't match any of constraints so not affected.
      ::audit(
          AUDIT_WEB_APP_NOT_AFFECTED,
          audit_product_msg,
          build_url2(qs:app_info.path, port:app_info.port),
          app_info.version
        );
    }

    ##
    # Simple check for whether this is a superdome model.
    # Most (many?) iLO vulns do NOT affect superdome, and if they do, it's a different version line.
    #
    # @param [model_kb:string] kb to use to get model if not default
    # @param [audit:boolean] TRUE or FALSE, whether or not to audit out if it's a superdome
    #
    # @return [boolean] TRUE if the model is a superdome model, FALSE otherwise.
    ##
    function check_superdome(model_kb, audit)
    {
      var is_superdome = FALSE;
      if(empty_or_null(model_kb)) model_kb = 'www/ilo/server_model';
      if(empty_or_null(audit) || audit != TRUE) audit = FALSE;

      var server_model = get_kb_item(model_kb);

      if(!empty_or_null(server_model) && server_model =~ "^[Ss]uperdome")
      {
        is_superdome = TRUE;
      }

      if(is_superdome && audit)
        ::audit(AUDIT_HOST_NOT, "affected as it is a Superdome model");

      return is_superdome;
    }
  }

  namespace grandstream
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If there are no matching constraints the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;

      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      local_var report, version, port;

      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

      if(isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      # Detection plugins record model in different places
      if(empty_or_null(app_info.model) && !empty_or_null(app_info.Model))
        app_info.model = app_info.Model;

      report = build_report(model:app_info.model,
                            version:version,
                            fix:fix,
                            path:app_info.path,
                            source:app_info.source,
                            webapp:app_info.webapp,
                            port:app_info.port);

      if(is_error(report)) return vcf::vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

      store_structured_data(app_info:app_info, fix:fix, fix_version:fix_version, port:port);

      security_report_v4(severity:severity,
                         port:port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);

      return vcf::vcf_exit(0);
    }

    ##
    # Builds the vulnerability report.
    #
    # @param [model:string] The model of the device.
    # @param [version:string] The installed version of the app.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [path:string] The install path of the app.
    # @param [source:string] The detection source.
    # @param [webapp:boolean] Falg to tell if the app install was found as being a webapp install.
    # @param [port:integer] The port on which the install was found.
    #
    # @return [string] The formatted report string returned by ``report_items_str()``.
    ##
    function build_report(model, version, fix, path, source, webapp, port)
    {
      local_var order, report, report_items;

      report_items = {
        "Model" : model,
        "Installed version" : version,
        "Fixed version" : fix
      };
      order = ["Model", "Installed version", "Fixed version"];

      if(!isnull(path))
      {
        if(webapp)
        {
          if(isnull(port)) return vcf::arg_error(arg:"port", func:FUNCTION_NAME);
          report_items["URL"] = build_url2(qs:path, port:port);
          order = ["URL", "Model", "Installed version", "Fixed version"];
        }
        else
        {
          report_items["Path"] = path;
          order = ["Path", "Model", "Installed version", "Fixed version"];
        }
      }
      else if(source)
      {
        report_items["Source"] = source;
        order = ["Source", "Model", "Installed version", "Fixed version"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace apache_subversion
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # If there are no matching constraints the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;

      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      local_var report, version, port;

      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

      if(isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(provider:app_info['Packaged with'],
                            version:version,
                            fix:fix,
                            path:app_info.path,
                            source:app_info.source,
                            webapp:app_info.webapp,
                            port:app_info.port);

      if(is_error(report)) return vcf::vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

      store_structured_data(app_info:app_info, fix:fix, fix_version:fix_version, port:port);

      security_report_v4(severity:severity,
                         port:port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);

      return vcf::vcf_exit(0);
    }

    ##
    # Builds the vulnerability report.
    #
    # @param [provider:string] The package provider's name.
    # @param [version:string] The installed version of the app.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [path:string] The install path of the app.
    # @param [source:string] The detection source.
    # @param [webapp:boolean] Falg to tell if the app install was found as being a webapp install.
    # @param [port:integer] The port on which the install was found.
    #
    # @return [string] The formatted report string returned by ``report_items_str()``.
    ##
    function build_report(provider, version, fix, path, source, webapp, port)
    {
      local_var order, report, report_items;

      report_items = {
        "Packaged with" : provider,
        "Installed version" : version,
        "Fixed version" : fix
      };
      order = ["Packaged with", "Installed version", "Fixed version"];

      if(!isnull(path))
      {
        if(webapp)
        {
          if(isnull(port)) return vcf::arg_error(arg:"port", func:FUNCTION_NAME);
          report_items["URL"] = build_url2(qs:path, port:port);
          order = ["URL", "Packaged with", "Installed version", "Fixed version"];
        }
        else
        {
          report_items["Path"] = path;
          order = ["Path", "Packaged with", "Installed version", "Fixed version"];
        }
      }
      else if(source)
      {
        report_items["Source"] = source;
        order = ["Source", "Packaged with", "Installed version", "Fixed version"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace jenkins
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # Filters out constraints which don't match the installed version's edition before checking constraints.
    # If there are no matching constraints the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      local_var edition = app_info['Edition'];
      local_var filtered_constraints = make_list();

      local_var i;

      for (i = 0; i < max_index(constraints); i++)
      {
        # Get list of editions in constraint. Convert to list if it isn't
        local_var list_of_constraint_editions = constraints[i]['edition'];
        if(!is_list(constraints[i]['edition']))
          list_of_constraint_editions = make_list(list_of_constraint_editions);

        if(!collib::contains(list_of_constraint_editions, edition))
          continue;

        # Fourth segment is 0 if and only if fixed train
        # Rolling train will never have the fourth segment equal to 0
        # Example of fixed train: 2.7.x.0.y
        local_var fourth_segment = app_info.parsed_version[0][3];
        if(constraints[i]['rolling_train'] && !empty_or_null(fourth_segment) && fourth_segment == 0)
          continue;

        append_element(var:filtered_constraints, value:constraints[i]);
      }

      if(!empty_or_null(edition))
        app_info.app = 'Jenkins ' + edition;

      # Don't bother checking version against constraints if no constraints are valid
      if(empty_or_null(filtered_constraints))
        return vcf::audit(app_info);

      constraints = filtered_constraints;

      var matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        local_var fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      local_var report, version, port;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

      if(isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(version:version,
                            fix:fix,
                            path:app_info.path,
                            source:app_info.source,
                            webapp:app_info.webapp,
                            port:app_info.port,
                            product:app_info.app);

      if(is_error(report)) return vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

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
    # Builds the vulnerability report.
    #
    # @param [version:string] The installed version of the app.
    # @param [path:string] The install path of the app.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [webapp:boolean] Falg to tell if the app install was found as being a webapp install.
    # @param [port:integer] The port on which the install was found.
    # @param [source:string] The detection source.
    # @param [product:string] The product's name.
    #
    # @return [string] The formatted report string returned by ``report_items_str()``.
    #
    # @remark
    # The product name should be one of "Jenkins Open Source LTS" or "Jenkins Enterprise".
    ##
    function build_report(version, path, fix, webapp, port, source, product)
    {
      local_var order, report, report_items;

      report_items = {
        "Product" : product,
        "Installed version" : version,
        "Fixed version" : fix
      };
      order = ["Product", "Installed version", "Fixed version"];

      if(webapp)
      {
        if(isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);
        report_items["URL"] = build_url2(qs:path, port:port);
        order = ["Product", "URL", "Installed version", "Fixed version"];
      }
      else if(!empty_or_null(path))
      {
        report_items["Path"] = path;
        order = ["Product", "Path", "Installed version", "Fixed version"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }

    # Additonal namespace for Jenkins plugins
    namespace plugin
    {
      ##
      # Gather the Jenkins plugins installs info and puts them into an array.
      #
      # @param [plugins:list] The list of arrays making up the constraints.
      #
      # @return [array] The consolidated app info array, originally gathered via the scratchpad ``jenkins_plugins`` table.
      #
      # @remark
      # Unlike other ``get_app_info()`` functions, this one will only retrieve information about the plugins
      # present in the constraint arrays. This prevents manipulating massive objects. If the function doesn't
      # find any matching installs it will audit out.
      ##
      function get_app_info(plugins)
      {
        var app_info, plugin_info;
        var plugin_info_list = make_list();
        if(empty_or_null(plugins) || !is_list(plugins)) return arg_error(arg:'plugins', func:FUNCTION_NAME);

        # Verify that Jenkins is installed first
        get_install_count(app_name:'Jenkins', exit_if_zero:TRUE);

        # Build list of plugins from constraints
        var plugin_list = make_list();
        foreach var plugin_and_constraint (plugins)
          append_element(var:plugin_list, value:plugin_and_constraint.plugin);
        plugin_list = list_uniq(plugin_list);

        if(query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'jenkins_plugins';"))
          foreach var plugin (plugin_list)
          {
            plugin_info = query_scratchpad('SELECT longName, mappedName, version, pluginVersion, path, pluginPath, port, source
                                            FROM jenkins_plugins
                                            WHERE LOWER(mappedName) = ?;',
                                            tolower(plugin));
            if(!empty_or_null(plugin_info))
              plugin_info_list = make_list(plugin_info_list, plugin_info);
          }
        else
          vcf::audit();

        if(!empty_or_null(plugin_info_list))
        {
          app_info = branch(plugin_info_list);
          if(app_info.source == 'remote')
          {
            app_info.webapp = TRUE;
          }
          else if(app_info.source == 'local')
          {
            app_info.version = app_info.pluginVersion;
            app_info.path = app_info.pluginPath;
          }
          else
          {
            # The entries in the jenkins_plugin table should *always* have a source, so this shouldn't happen
            vcf::vcf_exit(1, 'Plugin entry in jenkins_plugins table has an invalid "source" value.');
          }

          # Strip out bad version formatting
          var ver_match = pregmatch(string:app_info.version, pattern:"^([0-9\.]+)");
          if(!empty_or_null(ver_match) && !empty_or_null(ver_match[1]))
          {
            app_info.display_version = app_info.version;
            app_info.version = ver_match[1];
          }

          app_info.parsed_version = vcf::parse_version(app_info.version);
          app_info.app = 'Jenkins Plugin: ' + app_info.longName;
          app_info["cpe/v23"] = "cpe:2.3:a:jenkins:jenkins";

          return app_info;
        }
        else
          vcf::audit();
      }

      ##
      # Builds the report used in reporting output
      #
      # @param [version:string] reports as "Installed version"
      # @param [path:string] reports as "Path" or "URL" (dep on webapp flag)
      # @param [fix:string] reports as "Fixed version"
      # @param [webapp:boolean] TRUE/FALSE (or NULL) to determine path format
      # @param [port:integer] Only used when building URLs
      # @param [plugin:string] reports as "Plugin"
      #
      # @return [string] The appropriate report string (extra)
      ##
      function build_report(version, path, fix, webapp, port, plugin)
      {
        var order, report, report_items;

        report_items = {
          'Plugin' : plugin,
          'Installed version' : version,
          'Fixed version' : fix
        };
        order = ['Plugin', 'Installed version', 'Fixed version'];

        if(webapp)
        {
          if(isnull(port)) return arg_error(arg:'port', func:FUNCTION_NAME);
          report_items['URL'] = build_url2(qs:path, port:port);
          order = ['Plugin', 'URL', 'Installed version', 'Fixed version'];
        }
        else if(!empty_or_null(path))
        {
          report_items['Path'] = path;
          order = ['Plugin', 'Path', 'Installed version', 'Fixed version'];
        }

        return report_items_str(report_items:report_items, ordered_fields:order);
      }

      ##
      # Check the version against the constraints and only report versions matching those constraints.
      #
      # @param [app_info:array] The app information to check.
      # @param [constraints:list] The list of array making up the constraints.
      # @param [severity:string] One of the ``SECURITY_*`` global variables.
      # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
      #
      # @remark
      # This function calls ``security_report_v4()`` directly if the install is found vulnerable,
      # or audits out.
      ##
      function check_version_and_report(app_info, constraints, severity, strict, flags)
      {
        var matching_constraint, fix, report_ver, filtered_constraints, version;

        if(isnull(app_info)) return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if(isnull(severity)) return arg_error(arg:'severity', func:FUNCTION_NAME);
        if(isnull(constraints)) return arg_error(arg:'constraints', func:FUNCTION_NAME);

        filtered_constraints = make_list();

        # Filter constraints for Jenkins plugin
        for (var i = 0; i < max_index(constraints); i++)
        {
          # Case insensitive check
          if(tolower(constraints[i]['plugin']) != tolower(app_info.mappedName))
            continue;

          append_element(var:filtered_constraints, value:constraints[i]);
        }

        constraints = filtered_constraints;

        matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
        if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

        if(!isnull(matching_constraint))
        {
          fix = matching_constraint.fixed_display;
          if(isnull(fix)) fix = matching_constraint.fixed_version;

          if(isnull(app_info.display_version)) version = app_info.version;
          else version = app_info.display_version;

          var report = build_report(version:version,
                                    fix:fix,
                                    path:app_info.path,
                                    webapp:app_info.webapp,
                                    port:app_info.port,
                                    plugin:app_info.longName);

          if(is_error(report)) return vcf_exit(1, report.message);

          var port = app_info.port;
          if(isnull(port)) port = 0;

          store_structured_data(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, port:port);

          security_report_v4(severity:severity,
                             port:port,
                             extra:report,
                             xss:flags.xss,
                             xsrf:flags.xsrf,
                             sqli:flags.sqli,
                             proto:app_info.proto);
        }
        # Audit
        else
          return vcf::audit(app_info);

        return vcf_exit(0);
      }
    }
  }

  namespace csm
  {
    ##
    # Gather the "Cisco Security Manager" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    #
    # @remark
    # This function uses ``add_conversions()`` and ``add_separator()`` to handle Service Pack versions.
    ##
    function get_app_info()
    {
      local_var app, parsed_version;
      add_conversions({'SP':0});
      add_separator('-');

      app = vcf::get_app_info(app:'Cisco Security Manager', win_local:TRUE);

      # if a sp exists tack it onto main version
      if(!isnull(app["Service Pack"]))
        app['version'] = app['version'] + "-SP" + app["Service Pack"];

      parsed_version = parse_version(app['version']);
      if(is_error(parsed_version))
      {
        return vcf_exit(1, parsed_version['message']);
      }
      app['parsed_version'] = parsed_version;

      return app;
    }
  }

  namespace commvault
  {

    ##
    # Gather the "Commvault" webapp installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install was found.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    #
    # @remark
    # This function uses ``add_conversions()`` and ``add_separator()`` to handle Service Pack versions.
    ##
    function get_webapp_info(port)
    {
      local_var app, parsed_version;
      add_conversions({'SP':0});
      add_separator('-');

      app = vcf::get_app_info(app:"Commvault", webapp:TRUE, port:port);

      if(!isnull(app["Service Pack"]))
        app.version = app.version + "-SP" + app["Service Pack"];

      parsed_version = parse_version(app.version);
      if(is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      app.parsed_version = parsed_version;

      return app;
    }

    ##
    # Gather the locally-detected "Commvault" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info_windows()
    {
      local_var app, parsed_version;

      app = vcf::get_app_info(app:"Commvault", win_local:TRUE);
      local_var cvd = app['cvd.exe File Version'];
      if(isnull(cvd)) return ::audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

      # create a simple semantic version
      # if a sp / hf exists tack it onto
      if(!isnull(app["Service Pack"]))
        app.version = app.version + "." + app["Service Pack"];
      else
         app.version = app.version + ".0";

      if(!isnull(app["Hotfix Pack"]))
        app.version = app.version + "." + app["Hotfix Pack"];
      else
         app.version = app.version + ".0";

      parsed_version = parse_version(app.version);
      if(is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      app.parsed_version = parsed_version;

      return app;
    }
  }
  namespace proxysg
  {
    ##
    # Gather the Bluecoat ProxySG installs info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # version, parsed version, display version (the UI version when applicable) and app name.
    ##
    function get_app_info()
    {
      local_var app_info = {};
      local_var version    = get_kb_item_or_exit('Host/BlueCoat/ProxySG/Version');
      local_var ui_version = get_kb_item('Host/BlueCoat/ProxySG/UI_Version');

      # Select version for report
      #We have to take into consideration the ui_version and use it instead of version for reporting only
      local_var report_ver = version;
      if(!empty_or_null(ui_version))
        report_ver = ui_version;

      app_info.version = version;
      app_info.parsed_version = parse_version(app_info.version);
      app_info.display_version = report_ver;
      app_info.app = 'ProxySG';

      # Handle case where x.x.x.1xx is actually less than x.x.x.1
      # Rewrite x.x.x.1xx as x.x.x.0.1xx
      if(app_info.parsed_version[0][3] >= 100)
      {
        var stored_version = app_info.parsed_version[0][3];
        app_info.parsed_version[0][3] = 0;
        app_info.parsed_version[0][4] = stored_version;
      }

      app_info["cpe/v23"] = "cpe:2.3:a:broadcom:symantec_proxysg";

      return app_info;
    }
  }

  namespace pulse_connect_secure
  {
    ##
    # Gather the app's installs info and puts them into an array.
    #
    # @param [app:string] application name
    # @param [port:integer] port to check for application with
    # @param [kb_ver:string] kb path to use to obtain version information
    # @param [kb_backport:string] kb path to use to obtain backport information
    # @param [kb_source:string] kb path to use to obtain source information
    # @param [win_local:boolean] sets port to 445 after obtaining version info
    # @param [webapp:boolean] sets a value in app_info to determine path report output later
    # @param [service:boolean] sets a value in app_info that affects audit messages
    # @param [proto:string] protocol to use for reporting/audit outputs
    # @param [full_version:boolean] Set to TRUE to use the ``extras['Full Version']`` as the version
    # (which resembles 9.0.1.63949), or to FALSE to run as normal, using the translated 9.0R1 version style.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app, port, kb_ver, kb_backport, kb_source,  win_local, webapp, service, proto, full_version)
    {
      local_var app_info = {};
      app_info = vcf::get_app_info( app:app, port:port, kb_ver:kb_ver, kb_backport:kb_backport, kb_source:kb_source,
                                    win_local: win_local, webapp:webapp, service:service, proto:proto );

      if(full_version == TRUE && !empty_or_null(app_info['Full Version']))
      {
        app_info.version = app_info['Full Version'];
        app_info.parsed_version = parse_version(app_info.version);
      }

      return app_info;
    }
  }

  namespace cisco_cer
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # Filters out constraints using their ``required_cop`` entry, against the output of "show active version".
    # If there are no matching constraints the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var show_active = "";
      local_var matching_constraint, fix;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        if(!isnull(matching_constraint.required_cop))
        {
          show_active = get_kb_item_or_exit("Host/Cisco/show_version_active");
          if(show_active =~ matching_constraint.required_cop)
            return vcf::audit(app_info);
        }

        vcf::report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity, flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }
  }

  namespace cisco_dcnm_web
  {
    ##
    # Adds appropriate additional separators.
    #
    # @remark
    # This function uses ``add_separator()``.
    ##
    function initialize()
    {
      add_separator('(');
      add_separator(')');
    }

    ##
    # Gather the "Cisco Prime DCNM" local installs (or "cisco_dcnm_web" webapp installs)
    # info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info()
    {
      local_var webapp, port, app, install_count, app_info;

      webapp = FALSE;
      port = NULL;

      # Try local detection
      app = 'Cisco Prime DCNM';
      install_count = get_install_count(app_name:app);

      # Try remote detection if no local installs
      if(install_count < 1)
      {
        app = 'cisco_dcnm_web';
        get_install_count(app_name:app, exit_if_zero:TRUE);
        port = get_http_port(default:443);
        webapp = TRUE;

        # Only need to run initialize if we're using web detection due to version format
        vcf::cisco_dcnm_web::initialize();
      }

      app_info = vcf::get_app_info(app:app, port:port, webapp:webapp);

      return app_info;
    }
  }

  namespace cisco_ip_phone
  {
    ##
    # Gather the app's installs info and puts them into an array.
    #
    # @param [app:string] The app's name for which to gather info.
    # @param [port:integer] The port on which the install was found.
    # @param [proto:string] The detection protocol's name.
    #
    # @return [array] The app info array containing:
    # app name, version, model, port and detection protocol.
    ##
    function get_app_info(app, port, proto)
    {
      var app_info = {};
      var model, version;

      model = get_kb_item_or_exit('installed_sw/' + port + '/' + app + '/service/' + proto + '/SIP/Model');
      version = get_kb_item_or_exit('installed_sw/' + port + '/' + app + '/service/' + proto + '/SIP/version');

      app_info.app = app;
      app_info.version = version;
      app_info.model = model;
      app_info.port = port;
      app_info.proto = proto;

      app_info["cpe/v23"] = "cpe:2.3:h:cisco:ip_phone";

      return app_info;
    }

    ##
    # Check the version against the constraints and builds the vulnerability report.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    #
    # @return [string] The report string.
    #
    # @remark
    # This function is essentially a wapper for ``vcf::check_version()``.
    ##
    function check_version(app_info, constraints)
    {
      var output, report;

      output = vcf::check_version(version:vcf::parse_version(app_info.version), constraints:constraints);

      if(!vcf::is_error(output) && !isnull(output))
      {
        report =
        '\n  Product           : ' + app_info.app +
        '\n  Model             : ' + app_info.model +
        '\n  Installed Version : ' + app_info.version +
        '\n  Fixed Version     : ' + output.fixed_display +
        '\n  Port / Protocol   : ' + app_info.port + ' / ' + app_info.proto +
        '\n';
      }

      return report;
    }
  }

  namespace cisco_finesse
  {
    ##
    # Gather the Cisco Finesse app's installs info and puts them into an array.
    #
    # @param [app:string] application name
    # @param [port:integer] port to check for application with
    # @param [kb_ver:string] kb path to use to obtain version information
    # @param [kb_backport:string] kb path to use to obtain backport information
    # @param [kb_source:string] kb path to use to obtain source information
    # @param [win_local:boolean] sets port to 445 after obtaining version info
    # @param [webapp:boolean] sets a value in app_info to determine path report output later
    # @param [service:boolean] sets a value in app_info that affects audit messages
    # @param [proto:string] protocol to use for reporting/audit outputs
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app, port, kb_ver, kb_backport, kb_source, win_local, webapp, service, proto)
    {
      var app_info, es_version, patch, patches, matches;

      app_info = vcf::get_app_info(
                        app         : app,
                        port        : port,
                        kb_ver      : kb_ver,
                        kb_backport : kb_backport,
                        kb_source   : kb_source,
                        win_local   : win_local,
                        webapp      : webapp,
                        service     : service,
                        proto       : proto
                      );

      es_version = get_kb_item("cisco/finesse/es_version");

      if(isnull(es_version))
      {
        es_version = '0';
        patches = app_info.patches;
        patches = split(patches, sep:';');
        foreach patch (patches)
        {
          matches = pregmatch(string:patch, pattern:".ES([0-9]+).");
          if(isnull(matches)) continue;
          if(matches[1] > es_version) es_version = matches[1];
        }
        replace_kb_item(name:"cisco/finesse/es_version", value:es_version);
      }

      app_info['es_version'] = vcf::parse_version(es_version);

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # Filters out constraints using their ``required_cop`` entry, against the output of "show active version".
    # If there are no matching constraints the function will audit out.
    #
    # @remark
    # This function also checks that the app info has a matching or greater ``es_version`` than the constraint.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;
      local_var show_active = "";

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {

        # check es_version
        if(
          !isnull(matching_constraint.es_version) &&
          vcf::compare_version_to_check(version:app_info.es_version, comparator:'>=', cmp_ver:matching_constraint.es_version)
        )
          return vcf::audit(app_info);

        # check required_cop
        if(!isnull(matching_constraint.required_cop))
        {
          show_active = get_kb_item("Host/Cisco/show_version_active");
          if(show_active =~ matching_constraint.required_cop)
            return vcf::audit(app_info);
        }

        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info,
                       fix:fix,
                       fix_version:matching_constraint.fixed_version,
                       severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }
  }

  namespace jboss
  {
    namespace eap
    {
      ##
      # Adds appropriate conversion values.
      #
      # @remark
      # This function uses ``add_conversions()``.
      ##
      function initialize()
      {
        # https://developer.jboss.org/wiki/JBossProjectVersioning
        # There is also a timestamp one: 'major.minor.micro.TIMESTAMP-Mn'
        add_conversions({'GA': 0, 'Final': 0, 'Beta': conversions.beta, 'Alpha': conversions.alpha, "CR": conversions.rc});
      }

      ##
      # Gather the "JBoss" installs info, filters out the EAP variant and puts them into an array.
      #
      # @return [array] The consolidated app info array, originally gathered via ``get_installs()``.
      #
      # @remark
      # This function will branch out for each install it found.
      ##
      function get_app_info()
      {

        local_var install, installs, parsed_version;
        local_var app_name = 'JBoss';

        installs = get_installs(app_name:app_name, exit_if_not_found:TRUE);
        installs = installs[1];

        installs = collib::filter(installs, f: function ()
          {
            local_var install = _FCT_ANON_ARGS[0];
            return 'jboss_enterprise_application_platform' >< install.cpe;
          }
        );

        if(!isnull(installs) && max_index(installs) > 0)
        {
          install = branch(installs);
          install.app = app_name;

          parsed_version = parse_version(install.version);
          if(is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

          install.parsed_version = parsed_version;
          return install;
        }
        else
        {
          vcf::audit();
        }
      }
    }
  }

  namespace ntp
  {
    ##
    # Gather the "NTP Server" install info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # port, version, display version and parsed version.
    #
    # @remark
    # The function will audit out if there are no installs,
    # some versions are missing or don't have the right format.
    ##
    function get_app_info()
    {
      local_var match, verfields, major, minor, rev, patch, revpatch, port, ver;
      local_var app_info = make_array();
      local_var app_name = 'NTP Server';

      # Make sure NTP server is running
      get_kb_item_or_exit('NTP/Running');

      app_info.port = get_kb_item('Services/udp/ntp');
      if(empty_or_null(app_info.port))
        app_info.port = 123;

      app_info.display_version = get_kb_item_or_exit('Services/ntp/version');
      if(app_info.display_version == 'unknown')
        ::audit(AUDIT_UNKNOWN_APP_VER, 'NTP Server');

      match = pregmatch(string:app_info.display_version, pattern:"^([0-9]+\.[0-9]+\.[0-9p]+)");
      if(empty_or_null(match))
        ::audit(AUDIT_UNKNOWN_APP_VER, app_name);

      ver = match[1];
      verfields = split(ver, sep:'.', keep:FALSE);
      major = int(verfields[0]);
      minor = int(verfields[1]);
      if('p' >< verfields[2])
      {
        revpatch = split(verfields[2], sep:'p', keep:FALSE);
        rev = int(revpatch[0]);
        patch = int(revpatch[1]);
        app_info.version = major + '.' + minor + '.' + rev + '.' + patch;
      }
      else
      {
        rev = verfields[2];
        patch = 0;
        app_info.version = major + '.' + minor + '.' + rev + '.0';
      }

      app_info.parsed_version = vcf::parse_version(app_info.version);
      app_info["cpe/v23"] = "cpe:2.3:a:ntp:ntp";
      return app_info;
    }
  }

  namespace mobileiron_core
  {
    ##
    # Gather the "MobileIron Core" installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install was found.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    ##
    function get_app_info(port)
    {
      local_var version, build;
      local_var app_info = get_single_install(app_name:"MobileIron Core", port:port);

      # major . minor . release . build . patch
      #  10    .  3    .    0    .  4    . 0
      # { 'min_version' : '10.3.0.4-0', 'fixed_version' : '10.3.0.4-19' },
      # the patch is appended onto the version below

      if(!empty_or_null(app_info.Build))
        app_info.version = app_info.version + "." + app_info.Build;

      app_info.port = port;
      app_info.webapp = TRUE;
      app_info.parsed_version = app_info.version;

      dbg::detailed_log(src:FUNCTION_NAME, lvl:3, msg:'[mobileiron_core::get_app_info::return] ' + obj_rep(app_info));
      return app_info;
    }
  }

  namespace apache_http_server
  {
    ##
    # Gather the Apache HTTP Server installs info and puts them into an array.
    #
    # @param [app:string] The app's name for which to gather information.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::combined_get_app_info()``.
    #
    # @remark
    # This function will audit out if the scan is not paranoid and:
    # the install is backported, or is managed, of is disabled, the install's version matches ``^\d+$``.
    ##
    function combined_get_app_info(app)
    {
      var app_info;

      app_info = vcf::combined_get_app_info(app:app);
      app_info.service = TRUE;

      if(empty_or_null(app_info.port))
        app_info.port = 0;

      # backported != managed
      # only webapps (typically remote detections) should have app_info['port']
      if(app_info['backported'] && app_info['port'] && report_paranoia < 2)
        ::audit(AUDIT_BACKPORT_SERVICE, app_info.port, app);

      # the backporting checks we have in VCF expect a port to be associated with the install, but because this is also enumerated
      # locally (by extracting the banner from the exe) there is no port, so the backporting check above does not work.
      if(app_info['backported'] && !app_info['port'] && report_paranoia < 2)
        ::audit(AUDIT_HOST_NOT, 'relevant to this plugin as Apache HTTP Server was possibly installed by a package manager');

      if(app_info['Managed'] && report_paranoia < 2)
        ::audit(AUDIT_HOST_NOT, 'relevant to this plugin as Apache HTTP Server was installed by a package manager');

      if(app_info['Disabled'] && report_paranoia < 2)
        ::audit(AUDIT_HOST_NOT, 'relevant to this plugin as Apache HTTP Server is disabled');

      if(app_info['version'] =~ "^\d+$" && report_paranoia < 2)
        ::audit(AUDIT_VER_NOT_GRANULAR, app, app_info['version']);

      if(!empty_or_null(app_info['Loaded modules']))
      {
        app_info['Loaded modules'] = split(app_info['Loaded modules'], sep:';', keep:FALSE);
      }

      return app_info;
    }

    ##
    # Check the version of loaded Apache modules against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` or ``report_results()`` directly
    # if the install is found vulnerable, or audits out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      var matching_constraint, fix, loaded_modules, vulnerable_loaded_modules, report_items, order, report_str;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      constraints = filter_constraints(app_info: app_info, constraints: constraints);

      if(empty_or_null(constraints))
      {
        ::audit(AUDIT_HOST_NOT, 'running Apache HTTP Server with an affected module loaded');
      }

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix))
          fix = matching_constraint.fixed_version;

        // Vulnerable modules to report
        if(!empty_or_null(matching_constraint.modules))
        {
          report_items = {
            'Path' : app_info.path,
            'Installed version' : app_info.version,
            'Fixed version' : fix,
            'Vulnerable loaded modules' : join(matching_constraint.modules, sep:', ')
          };
          order = ['Path', 'Installed version', 'Fixed version', 'Vulnerable loaded modules'];
          report_str = report_items_str(report_items:report_items, ordered_fields:order);
          store_structured_data(app_info:app_info,
                                fix:fix,
                                fix_version:matching_constraint.fixed_version,
                                port:app_info.port);
          security_report_v4(severity:severity,
                             port:app_info.port,
                             extra:report_str,
                             xss:flags.xss,
                             xsrf:flags.xsrf,
                             sqli:flags.sqli,
                             proto:app_info.proto);

          return vcf_exit(0);
        }
        else
        {
          # Without any loaded modules or modules in the constraints we can report normally
          report_results(app_info:app_info,
                         fix:fix,
                         fix_version:matching_constraint.fixed_version,
                         severity:severity,
                         flags:flags);
        }
        return vcf_exit(0);
      }
      return vcf::audit(app_info);
    }

    ##
    # Filters the constraints to remove constraints which aren't applicable to the app_info's loaded modules.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of arrays making up the constraints.
    #
    # @remark
    # If no loaded modules are found in the app_info, add constraint-specific paranoia.
    ##
    function filter_constraints(app_info, constraints)
    {
      var filtered_constraints = [];
      foreach var constraint (constraints)
      {
        // No modules in contraint. Pass constraint along for processing.
        if(empty_or_null(constraint['modules']))
        {
          append_element(var:filtered_constraints, value:constraint);
        }
        else // Constraint contains module.
        {
          // No loaded modules from install. Require paranoia for the given constraint.
          if(empty_or_null(app_info['Loaded modules']))
          {
            constraint['require_paranoia'] = TRUE;
            constraint['modules'] = NULL;
            append_element(var:filtered_constraints, value:constraint);
            continue;
          }

          var intersection = collib::intersection(app_info['Loaded modules'], constraint.modules);
          if(!empty_or_null(intersection))
          {
            constraint.modules = intersection;
            append_element(var:filtered_constraints, value:constraint);
          }
        }
      }
      return filtered_constraints;
    }
  }

  namespace acos
  {
    ##
    # Convert the ACOS version to a '.'-separated version string.
    #
    # @param [version_str:string] The version string to convert.
    #
    # @return [string] The new version string, or NULL if an error occurred.
    ##
    function convert_version(version_str)
    {
      var item, retval;
      retval = '';

      # check that version string conforms to our expectations to avoid
      # false any potential false positives
      if(version_str !~ ("^[0-9]+\.[0-9]+\.[0-9]+" +
                          "(\-[pP][0-9]+|" +
                          "\-[gG][rR][0-9]+|" +
                          "\-[gG][rR][0-9]+\-[pP][0-9]+)?" +
                          "(\-[sS][pP][0-9]+)?$"))
        return NULL;
      item = pregmatch(pattern:"^([0-9.]+)($|[^0-9.])", string:version_str);
      if(isnull(item)) return NULL;

      retval += item[1] + '.';

      item = pregmatch(pattern:"-[gG][rR]([0-9]+)($|[^0-9])", string:version_str);
      if(isnull(item)) retval += '0.';
      else retval += item[1] + '.';

      item = pregmatch(pattern:"-[pP]([0-9]+)($|[^0-9])", string:version_str);
      if(isnull(item)) retval += '0.';
      else retval += item[1] + '.';

      item = pregmatch(pattern:"-[sS][pP]([0-9]+)($|[^0-9])", string:version_str);
      if(isnull(item)) retval += '0';
      else retval += item[1];

      return retval;
    }

    ##
    # Gather the A10 ACOS install info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # display version, version, parsed version and app name.
    ##
    function get_app_info()
    {
      var version;
      var app_info = make_array();

      # Make sure it's A10
      get_kb_item_or_exit('A10/ACOS');
      version = get_kb_item_or_exit("Host/A10_ACOS/version");
      app_info.display_version = version;
      app_info.version = convert_version(version_str:version);

      app_info.parsed_version = vcf::parse_version(app_info.version);
      app_info.app = "A10 ACOS";
      app_info["cpe/v23"] = "cpe:2.3:o:a10networks:advanced_core_operating_system";

      return app_info;
    }
  }

  namespace openoffice
  {
    # For OpenOffice, we make vulnerability determinations based on the build number.
    # See: https://www.openoffice.org/download/ for a list of versions & their corresponding build number.

    ##
    # Gather the "OpenOffice" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    ##
    function get_app_info()
    {
      var app_info;
      var app_name = 'OpenOffice';
      var install, win_port, version;

      app_info = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
      version = parse_version(version_str:app_info['version']);

      app_info.app = app_name;
      app_info.parsed_version = vcf::parse_version(version);
      if('build ' >< app_info['display_version'])
        app_info['display_version'] = app_info['display_version'] - 'build ';

      win_port = get_kb_item('SMB/transport');
      if(!win_port)
        app_info.port = 445;
      else
        app_info.port = win_port;

      return app_info;
    }

    ##
    # Parse the OpenOffice build number out of the version string.
    #
    # @param [version_str:string] The version string to parse.
    #
    # @return [string] The OpenOffice build number from the given version string.
    ##
    function parse_version(version_str)
    {
      var matches;
      matches = pregmatch(string:version_str, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");

      if(isnull(matches))
        ::audit(AUDIT_UNKNOWN_APP_VER, 'OpenOffice');
      return matches[2];
    }
  }

  namespace intel_amt
  {
    ##
    # Parses the Intel Active Management Technology version and puts it into an app info array.
    #
    # @param [fw_version:string] The version string to parse and add to the info array.
    #
    # @return [array] The app info array containing:
    # version, parsed version, app name and port.
    ##
    function get_app_info(fw_version)
    {
      var app_info = make_array();
      var port;

      if(empty_or_null(fw_version))
      {
        ::audit(
            AUDIT_HOST_NOT,
            'affected as it does not have Intel Active Management Technology (AMT) enabled.'
          );
      }

      app_info.version = fw_version;
      app_info.parsed_version = vcf::parse_version(fw_version);
      app_info.app = 'Intel Active Management Technology';

      port = get_kb_item('SMB/transport');
      if(!port)
        port = 445;
      else
        port = int(port);

      app_info.port = port;
      app_info["cpe/v23"] = "cpe:2.3:o:intel:active_management_technology_firmware";

      return app_info;
    }
  }

  namespace vmware_workspace_one_access
  {
    ##
    # Gather the "VMware Workspace ONE Access" installs info and puts them into an array.
    #
    # @param [port:integer] The port on which the install was found.
    # @param [combined:boolean] Boolean to set to TRUE to get remotely- and locally-detected installs.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    #
    # @remark
    # ``port`` and ``combined`` are mutually exclusive. ``port`` is only used for remotely-detected installs.
    # The function will exit if both arguments are set.
    ##
    function get_app_info(port, combined)
    {
      if(!empty_or_null(port) && combined)
        return vcf_exit(1, 'port and combined cannot both be set');

      local_var app_info = {};
      if(combined)
      {
        app_info = get_single_install(app_name:"VMware Workspace ONE Access", combined:TRUE);
      }
      else
      {
        app_info = get_single_install(app_name:"VMware Workspace ONE Access", port:port, webapp:TRUE);
        app_info.port = port;
      }

      # Local installs should have port be 0 or not set
      if(!empty_or_null(app_info.port) && app_info.port > 0)
        app_info.webapp = TRUE;

      app_info.display_version = app_info['version'] + " Build " + app_info["Build"];
      app_info.version = app_info['version'] + '.' + app_info['Build'];
      app_info.parsed_version = parse_version(app_info.version);

      app_info.patch_list = app_info['Hotfixes'];
      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] UNUSED.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``. UNUSED.
    # @param [expected_patch:string] The patch to check for in the list of installed patches to determine if the
    # install is vulnerable.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags, expected_patch)
    {
      local_var matching_constraint, fix, report_ver, check_ver;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      if(!empty_or_null(expected_patch) && !empty_or_null(app_info.patch_list))
      {
        if(expected_patch >< app_info.patch_list)
        {
          ::audit(AUDIT_HOST_NOT, 'affected.');
        }
      }

      vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:severity);
    }
  }

  namespace vmware_vcenter
  {
    ##
    # Gather the "VMWare vCenter Server" install info and puts them into an array.
    #
    # @return [array] The app info array containing:
    # app name, port, release, display version, version and parsed version.
    ##
    function get_app_info()
    {
      var app_info = {};
      var app_name = 'VMWare vCenter Server';
      var version_str, version_match, version;

      app_info['app'] = app_name;
      app_info['port'] = get_kb_item_or_exit('Host/VMware/vCenter');
      app_info['release'] = get_kb_item_or_exit('Host/VMware/release');
      version_str = get_kb_item_or_exit('Host/VMware/version');

      # Extract and verify the build number
      var build = ereg_replace(pattern:"^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$", string:app_info['release'], replace:"\1");
      if(build !~ "^[0-9]+$")
        ::audit(AUDIT_UNKNOWN_BUILD, app_name);

      version_match = pregmatch(pattern:"^VMware vCenter ([0-9]+\.[0-9]+).*$", string:version_str);
      if(isnull(version_match))
        ::audit(AUDIT_OS_NOT, app_name);

      version = version_match[1];
      if(version !~ "^(8\.0|7\.0|6\.(5|7))$")
        ::audit(AUDIT_OS_NOT, app_name + ' 6.5 / 6.7 / 7.0 / 8.0');


      app_info['display_version'] = version + " Build " + build;
      app_info['version'] = version + '.' + build;
      app_info.parsed_version = parse_version(app_info.version);
      app_info["cpe/v23"] = "cpe:2.3:a:vmware:vcenter_server";

      return app_info;
    }
  }

  namespace tenable_sc
  {
    ##
    # Gather the "SecurityCenter" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``combined_get_app_info()``.
    ##
    function get_app_info()
    {
      local_var install = NULL;

      install = combined_get_app_info(app:'SecurityCenter');
      if(empty_or_null(install)) return NULL;

      if(!empty_or_null(install['Installed Patches']))
        install.installed_patches = install['Installed Patches'];
      install.app = 'Tenable.sc';
      return install;
    }

    ##
    # Check if the given SecurityCenter patches are installed
    #
    # @param [app_info:array] The app info array containing the installed patches information.
    # @param [patches:list] The list of patches to check for.
    #
    # @remark
    # The function will audit out if none of the patches are installed.
    #
    # @remark
    # At least one of the patches needs to be installed to be considered as patched.
    ##
    function check_for_patch(app_info, patches)
    {
      var remote_audit_msg = 'Tenable Security Center version ' + app_info.version + ' was detected via remote ' +
                             'plugin ID 71157.\nThis plugin cannot enumerate installed patches, so we are unable to ' +
                             'tell if this install is patched or not.\nPlease enable paranoid scanning if you want to ' +
                             'see this plugin in your scan resuults.';

      if(app_info.plugin_id == '71157' && report_paranoia < 2)
        exit(0, remote_audit_msg);

      local_var found_patch = NULL;

      local_var installed_patches = split(app_info.installed_patches, sep:', ', keep:FALSE);

      foreach var patch (patches)
      {
        if(contains_element(var:installed_patches, value:patch))
        {
          found_patch = patch;
          break;
        }
      }

      if(!isnull(found_patch))
      {
        ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version + ' with patch ' + found_patch);
      }
    }
  }

  namespace aruba
  {
    ##
    # Parses and consolidates the ArubaOS app info array if it matches the given OS flavour.
    #
    # @param [app_info:array] The ArubaOS app info array to consolidate.
    # @param [os_flavour:string] The OS flavour to verify.
    #
    # @return [array] The app info array with the following consolidated info:
    # display version, version, parsed version and model version.
    #
    # @remark
    # If the app info doesn't match the os flavour, or if the version
    # doesn't match the expected pattern, the function will audit out.
    #
    # @remark
    # If the the version doesn't start with a letter, the function will return the app info as is.
    ##
    function process_aruba_app_info(app_info, os_flavour)
    {
      if(app_info['OS flavour'] != os_flavour)
        ::audit(AUDIT_DEVICE_NOT_VULN, app_info['OS flavour']);

      # If version is starts with digits and ., return app_info as is
      var ver_match = pregmatch(string:app_info.version, pattern:"^([0-9\.]+)");
      if(!empty_or_null(ver_match))
        return app_info;

      ver_match = pregmatch(string:app_info.version, pattern:"^([A-Za-z]+)\.([0-9\.]+)");
      if(empty_or_null(ver_match))
        exit(1, 'The ArubaOS version ' + obj_rep(app_info.version) + ' is not well-formatted.');

      var ver = ver_match[2];
      var ver_model = ver_match[1];

      app_info.display_version = app_info.version;
      app_info.version = ver;
      app_info.parsed_version = vcf::parse_version(ver);
      app_info.ver_model = ver_model;

      return app_info;
    }

    ##
    # Gather the remotely- and locally-detected "ArubaOS" installs info and puts them into an array.
    #
    # @param [os_flavour:string] The specific ArubaOS flavour for which to get the info.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::combined_get_app_info()``.
    ##
    function combined_get_app_info(os_flavour)
    {
      var combined_app_info = vcf::combined_get_app_info(app:'ArubaOS');
      return process_aruba_app_info(app_info:combined_app_info, os_flavour:os_flavour);
    }

    ##
    # Gather the locally-detected "ArubaOS" installs info and puts them into an array.
    #
    # @param [os_flavour:string] The specific ArubaOS flavour for which to get the info.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info``.
    ##
    function get_app_info(os_flavour)
    {
      var app_info = vcf::get_app_info(app:'ArubaOS');
      return process_aruba_app_info(app_info:app_info, os_flavour:os_flavour);
    }
  }

  namespace nessus
  {
    ##
    # Gather the "Tenable Nessus" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    #
    # @remark
    # The function will audit out if the version doesn't match the expected format.
    ##
    function get_app_info()
    {
      var app_info = {};
      var installs, pref_install, i;
      var port = get_http_port(default:8834);

      installs = get_combined_installs(app_name:"Tenable Nessus", exit_if_not_found:TRUE);

      for (i = 0; i < max_index(installs); i++)
      # Remote detection is no longer able to report versions on Nessus 10.2.0 and newer,
      # so use the app_info[version] that did actually report a version number.
      {
        if((installs[i]['version']) =~ "^\d+\.\d+\.\d+")
          pref_install = i;
        else if((installs[i]['version']) == UNKNOWN_VER)
          ::audit (AUDIT_UNKNOWN_APP_VER, 'Tenable Nessus');
      }

      app_info = installs[pref_install];

      port = app_info['port'];
      if(empty_or_null(port)) port = 0;

      app_info.parsed_version = parse_version(app_info.version);

      return app_info;

    }
  }
  namespace solarwinds_orion
  {
    ##
    # Adds a custom parsing function.
    #
    # @remark
    # This function uses ``vcf::set_custom_parse_version()``.
    ##
    function initialize()
    {
      # Register custom parsing function, also enables
      vcf::set_custom_parse_version(@custom_parser);
      return TRUE;
    }

    ##
    # Replacement function to inject into vcf parse_version.
    #
    # @anonparam [version:string] The version string to parse.
    #
    # @return [list] The version string parsed into its different segments and stored in a list.
    ##
    function custom_parser()
    {
      local_var version =_FCT_ANON_ARGS[0];
      local_var matches, parsed_version;

      # This is probably pretty expensive, check here if there are performance issues
      matches = pregmatch(string:version, pattern:"^([0-9\.]+)\s+HF\s*([0-9]+)$", icase:TRUE);

      if(!isnull(matches))
      {
        parsed_version = vcf::parse_version(matches[1], use_custom:FALSE);
        append_element(var:parsed_version[1], value:int(matches[2]));
      }
      else
      {
        parsed_version = vcf::parse_version(_FCT_ANON_ARGS[0], use_custom:FALSE);
        # Pad if not found to keep pre-release segments the same length and order
        append_element(var:parsed_version[1], value:0);
      }
      return parsed_version;
    }

    ##
    # Gather the remotely- and locally-detected "SolarWinds Orion Core" installs info and puts them into an array.
    #
    # @param [app:string] The app name for which to gather info (optional, defaults to "SolarWinds Orion Core").
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::combined_get_app_info()``.
    ##
    function combined_get_app_info(app)
    {
      local_var app_info;

      if(isnull(app))
        app = 'SolarWinds Orion Core';

      app_info = vcf::combined_get_app_info(app:app);
      # Append hotfix number to the end of the pre-release list and update display_version
      if(app_info.Hotfix)
      {
        # Update the custom generated parsed_version with the Hotfix number from extra
        app_info.parsed_version[1][1] = app_info.Hotfix;
        if(!empty_or_null(app_info.display_version))
          app_info.display_version = app_info.display_version + ' HF' + app_info.Hotfix;
        else
          app_info.display_version = app_info.version + ' HF' + app_info.Hotfix;
      }
      return app_info;
    }
  }

  namespace nutanix
  {

    ##
    # Gets info from Nutanix KBs depending on arguments
    #
    # @param [node:boolean] specifies whether we are dealing with a cluster (AOS/NDFS) or node (AHV). Changes KB items
    #
    # @return [array] The app info array containing:
    # version, parsed version, product name, architecture and LTS flag (only when ``node`` is FALSE or NULL).
    ##
    function get_app_info(node)
    {

      var app_info = {};
      var version, product, arch;

      if(!node)
      {
        version = get_kb_item_or_exit('Host/Nutanix/Data/Version');
        product = get_kb_item_or_exit('Host/Nutanix/Data/Service');
        arch = get_kb_item_or_exit('Host/Nutanix/Data/arch');

        # Only AOS/NDFS (cluster) have LTS distinction
        if(get_kb_item('Host/Nutanix/Data/lts'))
          app_info.lts = TRUE;
        else
          app_info.lts = FALSE;
      }
      else
      {
        version = get_kb_item_or_exit('Host/Nutanix/Data/Node/Version');
        product = get_kb_item_or_exit('Host/Nutanix/Data/Node/Type');

        # Versions on nodes have an ugly format (e.g. el7.nutanix.20201105.2175). We need only the numeric portion
        var ver_matches = pregmatch(string:version, pattern:"(\d+(?:\.\d+)+)");
        if(!empty_or_null(ver_matches) && !empty_or_null(ver_matches[1]))
          version = ver_matches[1];
      }

      if(empty_or_null(version) || version == UNKNOWN_VER)
        app_info.version = UNKNOWN_VER;
      else
        app_info.version = version;

      app_info.parsed_version  = parse_version(app_info.version);
      app_info.product = product;
      app_info.arch = arch;

      # The cpe's for the AOS service and AHV nodes are available through the NVD search portal
      if(tolower(product) == "aos")
        app_info["cpe/v23"] = "cpe:2.3:o:nutanix:aos";
      else if(tolower(product) == "ahv")
        app_info["cpe/v23"] = "cpe:2.3:o:nutanix:ahv";
      else
        app_info["cpe/v23"] = "x-cpe:2.3:o:nutanix:" + product;

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    #
    # @remark
    #   This function calls ``report_results()`` directly
    #   if the install is found vulnerable, or audits out.
    #
    # @remark
    #   Filter constraints based on lts, service, and architecture. Also check for the "exclude" constraint as well.
    #   If no contraints remain after the filtering, the function audits out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      var matching_constraint, fix, report_ver;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      var filtered_constraints = make_list();

      var lts = app_info.lts;
      var product = app_info.product;
      var arch = app_info.arch;

      # Filter constraints based on lts, service, and architecture. Also check for the "exclude" constraint as well
      foreach var constraint (constraints)
      {
        # Check for "exclude" constraints. We want to remove any exclude constraints from the list either way
        if(!empty_or_null(constraint['exclude']))
          if(ver_compare(ver:app_info.version, fix:constraint['exclude'], strict:FALSE) == 0)
            vcf::audit(app_info);
          else
            continue;

        # Filter constraints by product and architecture.
        if(!empty_or_null(product) && !empty_or_null(constraint['product']) &&
            tolower(product) != tolower(constraint['product']))
          continue;
        if(!isnull(arch) && !isnull(constraint['arch']) && tolower(arch != constraint['arch']))
          continue;

        ## Nutanix changed it's versioning at the end of 2024 to a more tradional two digit versioning standard.
        ## This logic prevents new versions from being incorrectly flagged by old plugins, 
        ## and old versions from being incorrectly flagged as not vulnerable.

        var app_new, check_old;
        
        ## We check versions and constraint to see if it has more or less than seven digits, as a practical cutoff.
        ## old style uses 8 digits for Year/Month/Day, new style is a straight forward version check.
        
        app_new = ver_compare(ver:app_info.version, fix:'1000000.0.0', strict:FALSE);

        if (constraint.fixed_version)
        {
          ## See comment above app_new declaration for more information. 
          ## This check is for Fixed Version checks.
          
          check_old = ver_compare(ver:constraint.fixed_version, fix:'1000000.0.0', strict:FALSE);

          ## If the app_info.version is in the new style (e.g. 10) and the check is in the old style (20250312)
          ## We drop the check. Anything in the new style should not be affected by the older vulnerabilities.
          
          if (app_new <= 0 && check_old > 0)
            continue;

          ## If the version is Old Style, and Check is new, we want to flag as vulnerable - 
          ## so set high "old style" fixed_version and set a fixed_display of "See vendor advisory"
          ## to flag as vulnerable and point them towards a proper fix.

          if (app_new > 0 && check_old <= 0)  
          {
            if (!constraint.fixed_display)
              constraint.fixed_display = "See Vendor Advisory";
            constraint.fixed_version = '20261231.0.0';
          }
        }

        ## Above logic mirrored for Max Version checks.
        else if (constraint.max_version)
        {
          check_old = ver_compare(ver:constraint.max_version, fix:'1000000.0.0', strict:FALSE);
          if (app_new <= 0 && check_old > 0)
            continue;

          if (app_new > 0 && check_old <= 0)
            { if (!constraint.fixed_display)
                constraint.fixed_display = "See Vendor Advisory";
              constraint.max_version = '20261231.0.0';
            }
        }
        # Filter for constraints only if the versions are both of the same style.
        # All old LTS branches are EOL and require being moved to the new branches, 
        # so we can do this. However, 'new' lts branches are likely in the future.
        if ((app_new > 0 && check_old > 0)||(app_new <= 0 && check_old <= 0))
        { 
          if(!isnull(lts) && !isnull(constraint['lts']) && lts != constraint['lts'])
              continue;
        }
        append_element(var:filtered_constraints, value:constraint);
      }

      # Don't bother checking version against constraints if no constraints are valid
      if(empty_or_null(filtered_constraints))
        return vcf::audit(app_info);

      constraints = filtered_constraints;

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      local_var report, version, port;

      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

      if(isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(product:app_info.product,
                            version:version,
                            fix:fix,
                            path:app_info.path,
                            source:app_info.source,
                            lts:app_info.lts);

      if(is_error(report)) return vcf::vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

      store_structured_data(app_info:app_info, fix:fix, fix_version:fix_version, port:port);

      security_report_v4(severity:severity,
                         port:port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);

      return vcf::vcf_exit(0);
    }

    ##
    # Builds the vulnerability report.
    #
    # @param [product:string] The product name.
    # @param [version:string] The installed version of the app.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [path:string] The install path of the app.
    # @param [source:string] The detection source.
    # @param [lts:string] The Nutanix LTS status/name.
    # @param [port:integer] The port on which the install was found.
    #
    # @return [string] The formatted report string returned by ``report_items_str()``.
    ##
    function build_report(product, version, fix, path, source, lts, port)
    {
      local_var order, report, report_items;

      # Set null items to empty string
      if(empty_or_null(product))
        product = '';

      if(!empty_or_null(lts))
      {
        report_items = {
          'Product' : product,
          'LTS' : lts,
          'Installed version' : version,
          'Fixed version' : fix
        };
        order = ['Product', 'LTS', 'Installed version', 'Fixed version'];
      }
      else
      {
        report_items = {
          'Product' : product,
          'Installed version' : version,
          'Fixed version' : fix
        };
        order = ['Product', 'Installed version', 'Fixed version'];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace nagiosxi
  {
    ##
    # Gather the "nagios_xi" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_install_from_kb()``.
    #
    # @remark
    # The function will audit out if the version is unknown.
    ##
    function get_app_info()
    {
      local_var install, matches;
      local_var all_installs = [];
      local_var remote_installs = get_combined_installs(app_name:'nagios_xi');
      if(remote_installs[0] == IF_OK && !empty_or_null(remote_installs[1]))
      {
        foreach install (remote_installs[1])
        {
          install.webapp = TRUE;
          append_element(var:all_installs, value:install);
        }
      }
      local_var local_installs = get_combined_installs(app_name:'Nagios XI');
      if(local_installs[0] == IF_OK && !empty_or_null(local_installs[1]))
      {
        foreach install (local_installs[1])
          append_element(var:all_installs, value:install);
      }
      if(empty_or_null(all_installs))
        ::audit(AUDIT_NOT_INST, 'Nagios XI');

      install = branch(all_installs);
      matches = pregmatch(string:install['version'], pattern:"^(((\d+)R([.\d]+))|([0-9.]+))");
      if(empty_or_null(matches))
        exit(1, 'Unable to parse version string ' + install['version']);
      install.parsed_version = parse_version(matches[1]);
      install.display_version = install.version;
      install.app = 'Nagios XI';
      return install;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags, like one passed to ``vcf::check_version_and_report()``.
    # @param [default_fix:string] The fix advice to display for legacy versions (e.g. 2014R2.4) (optional, defaults to "See vendor advisory").
    #
    # @remark
    # This function calls ``report_results()`` directly for legacy versions (e.g. 2014R2.4)
    # because these version are considered vulnerable by default.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags, default_fix)
    {
      local_var matching_constraint, fix, report_ver, check_ver;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      if(isnull(default_fix)) default_fix = 'See vendor advisory';

      # legacy versions like 2014R2.4 are vuln by default, however this format has been brought back
      # in 2024R1 - 2024 will always > 5.x so we can just special-case the old versions
      if(app_info.display_version =~ "^20[01]\d")
      {
        vcf::report_results(app_info:app_info,
                            fix:default_fix,
                            fix_version:default_fix,
                            severity:severity,
                            flags:flags);
      }
      else
      {
        vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:severity, flags:flags);
      }
    }
  }

  namespace zimbra
  {
    ##
    # Gather the remotely- and locally-detected "Zimbra Collaboration Server" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::combined_get_app_info()``.
    #
    # @remark
    # This function uses ``add_separator()``.
    ##
    function combined_get_app_info()
    {
      var app = 'zimbra_zcs';
      var app_full_name = 'Zimbra Collaboration Server';

      vcf::add_separator('_');
      var app_info = vcf::combined_get_app_info(app:app);
      # Change app name for audit trail
      app_info.app = app_full_name;

      # Remote versions are like 9.0.0_GA_4258 where we need only the 9.0.0 in version to match the local
      var remote_version_match = pregmatch(string:app_info.version, pattern:"([0-9.]+)_GA_([0-9]+)");
      if(!empty_or_null(remote_version_match))
      {
        app_info.display_version = app_info.version;
        app_info.version = remote_version_match[1];
        app_info.parsed_version = vcf::parse_version(app_info.version);
        app_info['GA'] = remote_version_match[2];
      }

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags to give to ``report_results()``.
    #
    # @remark
    # This function calls ``report_results()`` directly if matching constraints are found,
    # and audits out if none are found.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      var matching_constraint, fix;
      var vuln = FALSE;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
      if(isnull(strict)) strict = FALSE;

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        # If matching constraint specifies a patch and detected version is equal to the max version or equal, check for a patch or require Paranoia for remote detection
        if (!empty_or_null(matching_constraint['Patch']))
        {
          var potentially_patched = NULL;
          if (!empty_or_null(matching_constraint.equal))
            potentially_patched = matching_constraint.equal;
          else if (!empty_or_null(matching_constraint.max_version))
            potentially_patched = matching_constraint.max_version;

          # Constraints with Patch must specify either max_version or equal, which is the version that can be patched
          if (empty_or_null(potentially_patched))
            return arg_error(arg:"constraints", func:FUNCTION_NAME);

          if(ver_compare(ver:app_info.version, fix:potentially_patched, strict:strict) == 0) # detected version equal to potentially_patched
          {
            # Patch info not available via remote detection, so require paranoia
            if(app_info['Method'] == 'Remote' && report_paranoia < 2)
              ::audit(AUDIT_PARANOID);

            # Patch >= required patch is applied, so audit
            if(!empty_or_null(app_info['Patch']) &&
                ver_compare(ver:app_info['Patch'], fix:matching_constraint['Patch'], strict:strict) >= 0
            )
            {
              return vcf::audit(app_info);
            }
          }
        }
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        vcf::report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity, flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }
  }

  namespace cockroachdb
  {
    ##
    # Gather the "CockroachDB" installs info and puts them into an array.
    #
    # @return [array] The consolidated app info array, originally gathered via ``get_single_install()``.
    #
    # @remark
    # The function audits out if the version is unknown.
    ##
    function get_app_info()
    {
      var app_info = {};
      var port = get_http_port(default:8080);
      var ui_ver = NULL;
      var server_ver = NULL;
      var build_tag = NULL;

      app_info = get_single_install(app_name:'CockroachDB', port:port, webapp:TRUE, exit_if_unknown_ver:FALSE);

      build_tag = app_info['Build Tag'];
      server_ver = app_info['version'];
      if(!empty_or_null(build_tag) && build_tag != UNKNOWN_VER)
        app_info.version = build_tag;
      else if(!empty_or_null(server_ver) && server_ver != UNKNOWN_VER)
        app_info.version = server_ver;
      else
        ::audit(AUDIT_UNKNOWN_APP_VER, 'CockroachDB');

      app_info.app = 'CockroachDB';
      app_info.parsed_version = parse_version(app_info.version);
      app_info.path = app_info['path'];
      app_info.port = port;
      app_info.webapp = 1;
      return app_info;
    }
  }

  namespace av_checks
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags to give to ``report_results()``.
    # @param [check:string] Name of extra parameter to check instead of the parsed version in the app info (optional).
    #
    # @remark
    # This function calls ``report_results()`` directly if matching constraints are found,
    # and audits out if none are found.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags, check)
    {
      local_var matching_constraint, fix, report_ver, check_ver;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      if(isnull(check)) check_ver = app_info.parsed_version;
      else check_ver = parse_version(app_info[check]);

      matching_constraint = check_version(version:check_ver, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags, check:check);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    # @param [check:string] Name of the parameter to use as version instead of the version/display version in the app info (optional).
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags, check)
    {
      local_var report, version, port;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

      if(isnull(check))
      {
        if(isnull(app_info.display_version)) version = app_info.version;
        else version = app_info.display_version;
      }
      else
      {
        version = app_info[check];
      }

      report = build_report(version:version,
                            fix:fix,
                            path:app_info.path,
                            source:app_info.source,
                            webapp:app_info.webapp,
                            port:app_info.port);

      if(is_error(report)) return vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

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
  }

  namespace kaseya_vsa
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags to give to ``report_results()``.
    #
    # @remark
    # This function calls ``report_results()`` directly if matching constraints are found,
    # and audits out if none are found.
    #
    # @remark
    # If the 'Patch Level' is available in the app info array and the scan is not paranoid
    # the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      var matching_constraint, fix;
      var vuln = FALSE;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
      if(isnull(strict)) strict = FALSE;

      # If available, use 'Patch Level' as version.
      # If not available and not paranoid scan, audit out.
      # If not available and is paranoid scan, just carry on.
      if(
        !empty_or_null(app_info['Patch Level']) &&
        app_info['Patch Level'] =~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
      )
      {
        app_info.version = app_info['Patch Level'];
        app_info.parsed_version = vcf::parse_version(app_info['Patch Level']);
      }
      else
        if(report_paranoia < 2) ::audit(AUDIT_PARANOID);

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        vcf::report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity, flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }
  }

  namespace sonicwall_sonicos
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``report_results()``.
    #
    # @remark
    # This function calls ``report_results()`` directly if matching constraints are found,
    # and audits out if none are found.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      var meets_constraint, fix, report_ver;
      foreach var constraint (constraints)
      {
        if(!empty_or_null(constraint.models))
        {
          if(is_string(constraint.models))
            constraint.models = make_list(constraint.models);
          if(!is_list(constraint.models))
            return arg_error(arg:"constraint.models", func:FUNCTION_NAME);


          var model_match = FALSE;
          foreach var model (constraint.models)
          {
            if(toupper(model) == toupper(app_info.Model))
            {
              model_match = TRUE;
              break;
            }
          }
          # Not a matching model, continue to evaluate next constraint
          if(!model_match)
            continue;
        }
        meets_constraint = check_version_against_constraint(version:app_info.parsed_version, constraint:constraint, strict:FALSE);
        if(vcf::is_error(meets_constraint))
          meets_constraint = FALSE;

        if(meets_constraint)
        {
          var ext = app_info.Ext;
          var letter;
          # Check if app_info.Ext < ext
          # Note: I don't know what to make of versions like 5.9.2.13-7o. Calling everything after the - the "ext",
          # there is sometimes an n or o there. Here, I just compare the numeric part of the "ext", which is sufficinet for
          # RES-134469
          if(!empty_or_null(constraint.ext))
          {
            if(empty_or_null(ext))
              ext = 0;
            # If ext has - within it, only compare the first part
            ext = split(ext, sep:'-', keep:FALSE);
            ext = ext[0];

            var ext_match = pregmatch(string:ext, pattern:"([0-9]+)([a-zA-Z]?)");
            if(empty_or_null(ext_match))
            {
              dbg::detailed_log(src:FUNCTION_NAME, lvl:2, msg:'Unexpected ext: ' + obj_rep(ext));
              ext = 0;
            }
            else
            {
              # Set ext to the numeric part
              ext = ext_match[1];
            }
            # patched Ext
            if(ver_compare(fix:toupper(constraint.ext), ver:toupper(ext), strict:FALSE) >= 0)
              continue;
          }
          fix = constraint.fixed_display;
          if(empty_or_null(fix))
            fix = constraint.fixed_version;
          if(empty_or_null(fix))
            return arg_error(arg:"constraint.fixed_version / constraint.fixed_display", func:FUNCTION_NAME);
          vcf::report_results(app_info:app_info, fix:fix, fix_version:constraint.fixed_version, severity:severity, flags:flags);
          return vcf::vcf_exit(0);
        }
      }
      return vcf::audit(app_info);
    }
  }

  namespace mcafee_mtp
  {
    ##
    # Gather the McAfee app installs info and puts them into an array.
    #
    # @param [app:string] The app name for which to get the info.
    # @param [win_local:boolean] Flag to set the port to 445 after obtaining version info (passed to ``vcf::get_app_info()``).
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app, win_local)
    {
      var app_info = vcf::get_app_info(app:app, win_local:win_local);
      # if we have a release and version with just 2 parts, append Release onto version for comparison
      if(!(empty_or_null(app_info['Release'])) && app_info['version'] =~ "^[0-9]+\.[0-9]+$")
      {
        app_info['display_version'] = app_info['version'] + ' Release ' + app_info['Release'];
        var release_match = pregmatch(string:toupper(app_info['Release']), pattern:"R?([0-9]+)");
        if(!empty_or_null(release_match))
        {
          app_info['version'] += '.' + release_match[1];
          app_info['parsed_version'] = vcf::parse_version(app_info['version']);
        }
      }
      dbg::detailed_log(src:FUNCTION_NAME, lvl:3, msg:'app_info: ' + obj_rep(app_info));

      return app_info;
    }
  }

  namespace ivanti_epm
  {
    ##
    # Gather the Ivanti EPM installs info and puts them into an array.
    #
    # @param [app:string] The app name for which to get the info.
    # @param [win_local:boolean] Flag to set the port to 445 after obtaining version info (passed to ``vcf::get_app_info()``).
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app, win_local)
    {
      var app_info = vcf::get_app_info(app:app, win_local:win_local);

      if(!empty_or_null(app_info))
      {
        app_info['display_version'] = app_info['version'] + ' ' + app_info['Release'];
        if(app_info['ServiceUpdate'] > 0)
          app_info['display_version'] += ' SU' + app_info['ServiceUpdate'];

        app_info['version'] += '.' + app_info['ServiceUpdate'];
        app_info['parsed_version'] = vcf::parse_version(app_info['version']);
      }

      return app_info;
    }
  }

  namespace ivanti_csa
  {
    ##
    # Gather the Ivanti CSA installs info and puts them into an array.
    #
    # @param [app:string] The app name for which to get the info.
    # @param [win_local:boolean] Flag to set the port to 445 after obtaining version info (passed to ``vcf::get_app_info()``).
    # @param [port:int] Port the app is listening on
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app, win_local, port)
    {

      var app_info = vcf::get_app_info(app:app, win_local:win_local, port:port);

      if(!empty_or_null(app_info))
      {
        if(!empty_or_null(app_info['Display Version']))
          app_info['version'] = str_replace(string: app_info['Display Version'], find:'-', replace:'.');
        else if(!empty_or_null(app_info['Patch Version']) && !empty_or_null(app_info['version']))
          app_info['version'] = app_info['version'] + '.' + app_info['Patch Version'];
        else
          return app_info;

        app_info['parsed_version'] = vcf::parse_version(app_info['version']);
      }

      return app_info;
    }
  }

  namespace minio
  {
    ##
    # Adds a custom parsing function.
    #
    # @remark
    # This function uses ``vcf::set_custom_parse_version()``.
    ##
    function initialize()
    {
      vcf::set_custom_parse_version(@custom_parser);
      return TRUE;
    }

    ##
    # Replacement function to inject into vcf parse_version.
    #
    # @anonparam [version:string] The version string to parse.
    #
    # @return [list] The version string parsed into its different segments and stored in a list.
    ##
    function custom_parser()
    {
      local_var version = toupper(_FCT_ANON_ARGS[0]);
      local_var matches, parsed_version;

      matches = pregmatch(string:version, pattern:"^RELEASE\.(\d+)-(\d+)-(\d+)T(\d+)[-:](\d+)[-:](\d+)Z");

      if(!empty_or_null(matches))
        parsed_version = [[matches[1], matches[2], matches[3], matches[4], matches[5], matches[6]], [0]];
      else
        return vcf::parse_error(str:version, index:0, msg:'Version not in expected format');

      return parsed_version;
    }
  }

  namespace tomcat
  {
    ##
    # Adds a custom conversions.
    ##
    function initialize()
    {
      vcf::add_conversions({'M': -110});
    }
  }

  namespace adobe_acrobat
  {
    ##
    # Check the target track against the track specified in the constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``vcf::check_version_and_report()``.
    # @param [max_segs:integer] Limits the number of segments of the detected version used to ``max_segs``.
    #
    # @remark
    # ``max_segs`` exists because reader/acrobat versions can have 4 segments, but
    # the listed affected / fixed versions only refer to 3.
    # So, affected 15.6.30355 effectively means < 15.6.30356 affected
    # but our current (Jan 2019) max_versions don't account for this.
    #
    # @remark
    # The constraints are sorted to match track.
    # x.y.20zzz = DC Continuous
    # x.y.30zzz = DC Classic
    # https://helpx.adobe.com/acrobat/kb/identify-product-version.html
    # https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/whatsnewdc.html
    ##
    function check_version_and_report(app_info, constraints, severity, flags, max_segs)
    {
      local_var filtered_constraints = [];
      foreach var constraint (constraints)
      {
        if(constraint['track'] == app_info['Track'])
          append_element(var:filtered_constraints, value:constraint);
      }

      # Don't bother checking version against constraints if no constraints are valid
      if(empty_or_null(filtered_constraints))
        return vcf::audit(app_info);

      vcf::check_version_and_report(
        app_info:app_info,
        constraints:filtered_constraints,
        severity:severity,
        flags:flags
      );
    }
  }

  namespace openssh
  {
    ##
    # Gathers the OpenSSH app install info and puts them into an array.
    #
    # @param [app:string] The app name for which to get the info.
    # @param [port:integer] The port number for which to get the info.
    # @param [skip_upgrade:boolean] Flag that determines whether or not the detected version is "upgraded",
    #                               i.e. parsed as portable. (optional, defaults to FALSE)
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app, port, skip_upgrade)
    {
      var app_info = vcf::get_app_info(app:app, port:port, service:TRUE, proto:'tcp');

      var match = pregmatch(string:app_info.version, pattern:"p([1-9])");
      if(!empty_or_null(match))
        app_info['portable'] = TRUE;
      else
      {
        app_info['portable'] = FALSE;

        if(isnull(skip_upgrade))
          skip_upgrade = FALSE;

        # since this isn't a portable release, we might want to upgrade it
        if(skip_upgrade)
          dbg::log(msg:'skipping version upgrade from native to portable');
        else
        {
          dbg::log(msg:'upgrading version from native to portable');
          app_info['portable_version'] = app_info['version'] + 'p1';
          app_info['parsed_version'] = vcf::parse_version(app_info['portable_version']);
        }
      }

      dbg::log(msg:'app_info: ' + obj_rep(app_info));

      return app_info;
    }

    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags to give to ``report_results()``.
    # @param [require_paranoia:boolean] TRUE if the check requires paranoid scanning.
    # @param [use_returns:boolean] If TRUE and the check requires paranoid a value indicating
    #                              paranoia will be returned instead of the function auditing.
    #
    # @remark
    # This function calls ``report_results()`` directly if matching constraints are found,
    # and audits out if none are found.
    #
    # @remark
    # If the matching constraint requires paranoia the function will audit out.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags, require_paranoia, use_returns)
    {
      local_var matching_constraint, fix, report_ver;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
      if(empty_or_null(require_paranoia)) require_paranoia = FALSE;

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if(is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        if((require_paranoia || matching_constraint.require_paranoia) && report_paranoia < 2)
        {
          if(empty_or_null(app_info.app))
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN';
            else
              ::audit(AUDIT_POTENTIAL_VULN);
          else if(empty_or_null(app_info.version) && empty_or_null(app_info.display_version))
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN: ' + app_info.app;
            else
              ::audit(AUDIT_POTENTIAL_VULN, app_info.app);
          else if(!empty_or_null(app_info.display_version) && !(empty_or_null(app_info.port)))
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.display_version + ', ' + app_info.port;
            else
              ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.display_version, app_info.port);
          else if(!empty_or_null(app_info.version) && !(empty_or_null(app_info.port)))
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.version + ', ' + app_info.port;
            else
              ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.version, app_info.port);
          else if(!empty_or_null(app_info.display_version))
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.display_version;
            else
              ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.display_version);
          else if(!empty_or_null(app_info.version))
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN: ' + app_info.app + ', ' + app_info.version;
            else
              ::audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.version);
          else
            if(use_returns)
              return 'AUDIT_POTENTIAL_VULN';
            else
              ::audit(AUDIT_POTENTIAL_VULN);
        }
        fix = matching_constraint.fixed_display;
        if(isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, fix_version:matching_constraint.fixed_version, severity:severity,
                       flags:flags);
      }
      else if(use_returns)
        return 'AUDIT: target not vuln';
      # Audit
      else
        return vcf::audit(app_info);

      return vcf_exit(0);
    }

    ##
    # Builds the report and reports the vulnerability.
    #
    # @param [app_info:array] The app information to check.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [fix_version:string] the fixed version to include in structured report.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [flags:array] An array of reporting flags to be passed to ``security_report_v4()``.
    # @param [check:string] Name of the parameter to use as version instead of the version/display version in the app info (optional).
    #
    # @remark
    # This function calls ``security_report_v4()`` directly and then exits.
    ##
    function report_results(app_info, fix, fix_version, severity, flags)
    {
      local_var report, version, port;

      if(isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
      if(isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

      if(isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(version:version, fix:fix, banner:app_info['Banner']);
      if(is_error(report)) return vcf_exit(1, report.message);

      port = app_info.port;
      if(isnull(port)) port = 0;

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
    # Builds the vulnerability report.
    #
    # @param [version:string] The installed version of the app.
    # @param [fix:string] The fixed version for the vulnerability.
    # @param [banner:string] The version transmitted in the first packet exchange.
    #
    # @return [string] The formatted report string returned by ``report_items_str()``.
    ##
    function build_report(version, fix, banner)
    {
      local_var order, report, report_items;

      report_items = {
        "Version source" : banner,
        "Installed version" : version,
        "Fixed version" : fix
      };
      order = ["Version source", "Installed version", "Fixed version"];

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace acronis_aci
  {
    ##
    # Gather the Acronis ACI installs info and puts them into an array.
    #
    # @param [app:string] The app name for which to get the info.
    #
    # @return [array] The consolidated app info array, originally gathered via ``vcf::get_app_info()``.
    ##
    function get_app_info(app)
    {

      var app_info = vcf::combined_get_app_info(app:app);

      if(!empty_or_null(app_info))
      {
        if(!empty_or_null(app_info['Build']))
          app_info['version'] = app_info['version'] + '.' + app_info['Build'];

        app_info['parsed_version'] = vcf::parse_version(app_info['version']);
      }

      return app_info;
    }
  }

  namespace jt2go
  {
    ##
    # Check the version against the constraints and only report versions matching those constraints.
    #
    # @param [app_info:array] The app information to check.
    # @param [constraints:list] The list of array making up the constraints.
    # @param [severity:string] One of the ``SECURITY_*`` global variables.
    # @param [strict:boolean] Flag to set version comparision in strict mode.
    # @param [flags:array] An array of reporting flags to give to ``report_results()``.
    # @param [require_paranoia:boolean] TRUE if the check requires paranoid scanning.
    # @param [use_returns:boolean] If TRUE and the check requires paranoid a value indicating
    #                              paranoia will be returned instead of the function auditing.
    #
    # @remark
    # This function calls ``report_results()`` directly if matching constraints are found,
    # and audits out if none are found.
    #
    # @remark
    # If the matching constraint requires paranoia the function will audit out.
    ##
    function check_version_and_report(use_copyright_ver, app_info, constraints, severity, strict, flags, require_paranoia, use_returns)
    {
      if(use_copyright_ver == TRUE)
      {
        var cr_ver = app_info['Copyright Version'];
        if(!empty_or_null(cr_ver))
        {
          dbg::detailed_log(lvl:1, msg:'jt2go::check_version_and_report: using copyright version against constraints');
          app_info['parsed_version'] = vcf::parse_version(cr_ver);
        }
      }

      return vcf::check_version_and_report(
        app_info:app_info,
        constraints:constraints,
        severity:severity,
        strict:strict,
        flags:flags,
        require_paranoia:require_paranoia,
        use_returns:use_returns
      );
    }
  }
}
