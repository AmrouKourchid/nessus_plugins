include('compat_shared.inc');
include('debug.inc');
include('url_func.inc');
include('install_func.inc');

include('tenable_ot_assets_funcs.inc');
#pragma static(include)
include('tenable_ot_regexes.static');
include('tenable_ot_regexes_order.static');
#pragma static(include:false)

namespace tenable_ot
{
  var controller_types = [
    'controller',
    'cnc',
    'rtu',
    'ied',
    'dcs',
    'plc'
  ];

  var OT_SUCCESS = 1;
  var OT_NEXTMATCH = -1;
  var OT_FAILURE = 0;

  var TAP = 0;

  namespace cve
  {
    ##
    # Compare CVE info to asset data
    #
    # @param [cpe_order:array] proper ordering of families pulled from tenable_ot_regexes_order.inc
    # @param [cpe_group:array] regexes used to identify an asset pulled from tenable_ot_regexes.inc
    # @param [cpes:array] CVE info using CPE as key and criteria as value. Comes from vuln detection plugins
    # @param [asset:array] asset information pulled from the scan
    #
    # @remark reports or audits out
    #
    # @return NULL always
    ##
    function _is_vulnerable(plugin_info, asset)
    {
      var asset_family, cpe_name, cpe_names, cpe_family, vuln_cpe, family_pattern, criteria, ret, order_numbers;
      var vuln = false;

      # Retrieve CPE regex based on the asset's vendor and family
      var cpe_group = get_cpe_group(asset:asset);

      # Order of the regex matters going from most to least specific
      var cpe_order = get_cpe_order(asset:asset);

      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'cpe_order: '+obj_rep(cpe_order)+', cpe_group: '+obj_rep(cpe_group)+', vuln_models: '+obj_rep(plugin_info.vuln_models)+'\n');

      if(empty_or_null(plugin_info.cpes) && empty_or_null(plugin_info.vuln_models))
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Missing argument: plugin_info.cpes and plugin_info.vuln_models');
        return false;
      }
      if(empty_or_null(asset))
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Missing argument: asset');
        return false;
      }

      # Remove spaces (e.g. MicroLogix 1400 => MicroLogix1400)
      asset_family = str_replace(string:asset.rawFamily, find:' ', replace:'');
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Asset family: ' + asset_family);

      # if the plugin contains plugin_info.vuln_models instead of vuln_cpes, process them and return
      if (!empty_or_null(plugin_info.vuln_models))
        return _is_model_relevant_for_asset(vuln_models:plugin_info.vuln_models, asset:asset);

      var family_adds = associate_family_with_plugin_cpes(plugin_info:plugin_info, cpe_order:cpe_order, cpe_group:cpe_group);
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'added family data to '+family_adds+' plugin CPEs\n');

      # Process each vulnerable CPE from CVE entry
      foreach vuln_cpe (keys(plugin_info.cpes))
      {

        cpe_family = plugin_info.cpes[vuln_cpe].family;
        order_numbers = plugin_info.cpes[vuln_cpe].orderNumbers;

        # it's unlikely but possible there are CPEs on plugins that have no family matches
        # we can skip them here since nothing to do. in the future we may want to handle this case differently.
        if (empty_or_null(cpe_family))
          continue;

        # Ensure that the modelName is lowercased
        if(!empty_or_null(asset.modelName))
        {
          asset.modelName = tolower(asset.modelName);
        }

        if (_is_cpe_relevant_for_asset(asset:asset, asset_family:asset_family, vuln_cpe:vuln_cpe, cpe_family:cpe_family, order_numbers:order_numbers) )
        {
          # Check if CPE criteria (e.g. versionEndIncluding) matches 
          criteria = plugin_info.cpes[vuln_cpe];
          if (compare(asset:asset, criteria:criteria, cpe_family:cpe_family))
          {
            vuln = true;
            break;
          }
        }
      }

      return vuln;
    }

    ##
    # quick helper function for readability. This function identifies the 
    # set of family<->regex pairs to use based on the vendor in the asset struct.
    #
    # @param [asset:array] asset information
    #
    # @return the order from includes/tenable_ot_regexes.static
    ##
    function get_cpe_group(asset)
    {
      # Retrieve CPE regex based on the asset's vendor and family
      var cpe_group = tenable_ot::regexes::families[str_replace(string:asset.vendor, find:' ', replace:'')];
      if (empty_or_null(object:cpe_group ))
      {
        cpe_group = tenable_ot::regexes::families['Generic'];
      }
      return cpe_group;
    }

    ##
    # quick helper function for readability. This function identifies the 
    # set of family<->regex order to use based on the vendor in the asset struct.
    #
    # @param [asset:array] asset information
    #
    # @return the order from includes/tenable_ot_regexes_order.static
    ##
    function get_cpe_order(asset)
    {
      # Order of the regex matters going from most to least specific
      var cpe_order = tenable_ot::order::families[str_replace(string:asset.vendor, find:' ', replace:'')];
      if ( empty_or_null(object:cpe_order) )
      {
        cpe_order = tenable_ot::order::families['Generic'];
      }
      return cpe_order;
    }    

    ##
    # Originally we matched the family to the CPE in the plugin at runtime every
    # single time. That logic was also intertwined with the vuln matching logic
    # and was pretty confusing. This function will just associate families by
    # regex with the CPE from the plugin.
    #
    # @param [plugin_info:array] struct of plugin_info
    # @param [cpe_order:array] proper ordering of families pulled from tenable_ot_regexes_order.inc
    # @param [cpe_group:array] regexes used to identify an asset pulled from tenable_ot_regexes.inc
    #
    # @return count of how many items had family added. Note plugin_info is updated
    #         by reference
    ##
    function associate_family_with_plugin_cpes(&plugin_info, cpe_order, cpe_group)
    {
      var count = 0;
      foreach var vuln_cpe (keys(plugin_info.cpes))
      {
        if ( !empty_or_null(plugin_info.cpes[vuln_cpe].family) )
          continue;
        foreach var cpe_name (keys(cpe_order))
        {
          # Process each regex matching to family (e.g. MicroLogix1400)
          foreach var cpe_family (cpe_order[cpe_name])
          {
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Processing CPE from CVE entry: ' + vuln_cpe + ' with cpe_name: '+ cpe_name + ' and cpe_family: '+ cpe_family);
            var family_pattern = cpe_group[cpe_name][cpe_family];

            var plugin_cpe_matches_family = _match_cpe_family(family_pattern:family_pattern, vuln_cpe:vuln_cpe);
            if (!plugin_cpe_matches_family)
              continue;
            
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'CPE Pattern matched: ' + family_pattern);

            plugin_info.cpes[vuln_cpe].family = cpe_family;
            count++;
            break;
          }
          if (plugin_cpe_matches_family)
            break;
        }
      }
      return count;
    }

    ##
    # quick regex helper function for readability. likely only used if there are 
    # CPEs on a plugin without family already associated. This is how they started
    # but we're hoping to change that.
    #
    # @param [family_pattern:string] regex to match
    # @param [vuln_cpe:string] cpe string from plugin
    #
    # @return true: there's a match
    #         false: no match
    ##
    function _match_cpe_family(family_pattern, vuln_cpe)
    {
      # Attempt to match regex to CPE from CVE entry
      var match = preg(string:vuln_cpe, pattern:family_pattern, icase:true);
      return match;
    }

    ##
    # compare_and_report can be called with either vuln_models or vuln_cpes. This function
    # processes the vuln_models if they exist.
    #
    # @param [asset:array] asset information
    # @param [vuln_models:string] model string from plugin
    #
    # @return true: vuln_model  is relevant for given asset
    #         false: vuln_cpe is not relevant for given asset
    ##
    function _is_model_relevant_for_asset(vuln_models, asset)
    {
      var criteria, ret;

      if (!empty_or_null(vuln_models))
      {
        foreach var vuln_model (keys(vuln_models))
        {
          if ( tenable_ot::cve::model_compare_helper(asset:asset, vuln_model:vuln_model) == OT_SUCCESS )
          {
            dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'vuln_model: ' + vuln_model);
            criteria = vuln_models[vuln_model];
            if (compare(asset:asset, criteria:criteria))
              return true;
          }
        }
      }
      return false;
    }

    ##
    # Performs many checks to see if a CPE from the plugin is relevant for an asset
    #
    # @param [asset:array] asset information, passed by reference for tridium/assetBag
    # @param [asset_family:string] family ingested from asset info
    # @param [vuln_cpe:string] cpe string from plugin
    # @param [cpe_family:string] cpe family as extracted via family regex in _is_vulnerable
    #
    # @return true: vuln_cpe is relevant for given asset
    #         false: vuln_cpe is not relevant for given asset
    ##
    function _is_cpe_relevant_for_asset(&asset, asset_family, vuln_cpe, cpe_family, order_numbers)
    {
      var dcpe, ret, criteria, matches;
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'if plugin_info.cpes[vuln_cpe].family TRUE: vuln_cpe: '+vuln_cpe+', cpe_family: '+cpe_family+', order_numbers: '+obj_rep(order_numbers)+'\n');
      
      # Handle application CPE
      dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:vuln_cpe);

      if (dcpe[0] != IF_OK)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + vuln_cpe);
        return false;
      }

      if (dcpe[1].part == "a")
      {
        ret = tenable_ot::cve::app_compare_helper(asset:asset, cpe:vuln_cpe, app:cpe_family);
      }

      if ( ret == OT_SUCCESS)
        return true;

      # some CPEs only apply to PLCs, check if that's the case AND asset is a PLC.
      if (!check_controller(asset:asset, cpe:vuln_cpe))
        return false;

      ret = tenable_ot::cve::model_compare_helper(asset:asset, cpe:vuln_cpe, cpe_family:cpe_family, order_numbers:order_numbers);
      if ( ret == OT_FAILURE )
        return false;
      else if ( ret == OT_NEXTMATCH )
      {
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'model_compare_helper: OT_NEXTMATCH');
        // if we're not doing model matching, also check that the family matches the asset
        if ( empty_or_null(asset_family) )
          return false;
        asset_family = strip_raw_family(raw_family:asset_family);
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'asset_family: '+asset_family+', cpe_family: '+cpe_family);
        if ( asset_family != cpe_family )
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'cpe family set but asset_family!=cpe_family');
          return false;
        }
      }

      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('Matched vendor CPE ', asset.vendor, ' and family ', asset_family));
      return true;
    }

    ##
    # Strips some non-alpha chars from rawFamily so it can be compared with
    # CPE family
    #
    # @param [raw_family:string] rawFamily attribute from asset
    #
    # @remark does not check for null string
    #
    # @return stripped string
    ##
    function strip_raw_family(raw_family)
    {
      var strip_from_raw_family = ['-','_','.',':'];
      foreach var char (strip_from_raw_family)
        raw_family = str_replace(string:raw_family, find:char, replace:'');
      return raw_family;
    }

    ##
    # Compare CVE info to asset and report
    #
    # @param [asset:array] asset information
    # @param [cpes:array] CVE info using CPE as key and criteria as value
    # @param [severity:int] severity level of report as defined in global_settings.inc
    #
    # @remark reports or audits out
    #
    # @return NULL always
    ##
    function compare_and_report(asset, cpes, vuln_models, severity)
    {
      var req_asset_attribs, req_asset_attrib;
      var vuln, cpe_group, cpe_order, items, order, report, level;
      var plugin_info = {
        "cpes":cpes,
        "vuln_models":vuln_models,
        "severity":severity
      };
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'entry point');
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'plugin_info: '+obj_rep(plugin_info)+'\n');
      req_asset_attribs = [ 'vendor', 'family', 'rawFamily' ];
      foreach req_asset_attrib (req_asset_attribs)
      {
        if (empty_or_null(asset[req_asset_attrib]))
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Missing required asset attribute: ' + req_asset_attrib);
          return NULL;
        }
      }

      # Determine if anything here is vulnerable
      vuln = _is_vulnerable(plugin_info:plugin_info, asset:asset);

      # Report 
      if (!vuln) 
      {
        if (TAP) return 0;
        else audit(AUDIT_DEVICE_NOT_VULN, strcat(asset.vendor, ' ', asset.family));
      }

      items = {
        'Vendor'  : asset.vendor,
        'Family'  : asset.family,
        'Model'   : asset.modelName,
        'Version' : asset.firmwareVersion
      };

      order = [ 'Vendor', 'Family', 'Model', 'Version' ];

      # Model and Version can be undefined, calling report_items_str with those values NULL will cause a NULL output
      # This is only for plugin output and will not interfere with detection logic
      if (empty_or_null(asset.modelName))
      {
        items['Model'] = '';
      }

      if (empty_or_null(asset.firmwareVersion))
      {
        items['Version'] = '';
      }

      report = report_items_str(report_items:items, ordered_fields:order);

      if (plugin_info.severity == SECURITY_NOTE) level = 0;
      else if (plugin_info.severity == SECURITY_WARNING) level = 1;
      else if (plugin_info.severity == SECURITY_HOLE) level = 2;


      security_report(port:0, level:level, extra:report, host:asset.id); 

      if (TAP) return 1;

      return NULL;
    }

    # Helper function to choose the correct ver_compare to use. Add new ver_compare functions to 
    # the ver_compare_funcs table. This is to handle special cases in a version string for vendors 
    # or specific cpe families.
    # 
    # @param [ver:string] firmware version
    # @param [fix:string] version to compare with
    # @param [vendor:string] asset vendor to handle special cases in a version string for a whole vendor family (e.g. Rockwell)
    # @param [cpe_family:string] cpe family to handle special cases in a version string for a specific cpe family (e.g. MicroLogix1400)
    #
    # @return -1 if ver < fix, 0 if ver == fix, 1 if ver > fix.
    ##
    function ver_compare_helper(asset, fix, cpe_family)
    {
      var ver = asset.firmwareVersion;
      var vendor = asset.vendor;

      var ver_compare_funcs = {
        "Mitsubishi" : @tenable_ot::cve::mitsubishi::ver_compare_custom,
        "ABB" : @tenable_ot::cve::abb::ver_compare_custom,
        "Yokogawa" : @tenable_ot::cve::yokogawa::ver_compare_custom,
        "Wago" : @tenable_ot::cve::wago::ver_compare_custom,
        "Desigo" : @tenable_ot::cve::siemens::desigo::ver_compare_custom,
        "Apogee" : @tenable_ot::cve::siemens::desigo::ver_compare_custom,
        "PxcCompact" : @tenable_ot::cve::siemens::desigo::ver_compare_custom,
        "PxcModular" : @tenable_ot::cve::siemens::desigo::ver_compare_custom,
        "PhoenixContact" : @tenable_ot::cve::phoenixcontact::ver_compare_custom,
        "Schneider" : @tenable_ot::cve::schneider::ver_compare_custom,
        "Rockwell": @tenable_ot::cve::rockwell::ver_compare_custom,
        "Siemens" : @tenable_ot::cve::siemens::ver_compare_custom,
        "Siprotec" : @tenable_ot::cve::siemens::siprotec::ver_compare_custom,
        "Siprotec4" : @tenable_ot::cve::siemens::siprotec::ver_compare_custom,
        "Siprotec5" : @tenable_ot::cve::siemens::siprotec::ver_compare_custom,
        "SEL" : @tenable_ot::cve::sel::ver_compare_custom,
        "Niagara": @tenable_ot::cve::tridium::ver_compare_custom,
        "Cisco": @tenable_ot::cve::cisco::ver_compare_custom,
        "Stratix": @tenable_ot::cve::cisco::ver_compare_custom,
        "EHPMX": @tenable_ot::cve::honeywell::experion::ver_compare_custom,
        "HoneywellExperion": @tenable_ot::cve::honeywell::experion::ver_compare_custom,
        "SprecherAutomation": @tenable_ot::cve::sprecherautomation::ver_compare_custom,
        "Eaton": @tenable_ot::cve::eaton::ver_compare_custom,
        "BoschSecuritySystems": @tenable_ot::cve::bosch::ver_compare_custom,
        "MobotixCameras": @tenable_ot::cve::mobotix::mobotixcameras::ver_compare_custom,
        "MikroTik": @tenable_ot::cve::mikrotik::ver_compare_custom,
        "CiscoIPPhones": @tenable_ot::cve::cisco::ciscoipphones::ver_compare_custom,
        "Illustra": @tenable_ot::cve::illustra::ver_compare_custom,
        "Welotec": @tenable_ot::cve::welotec::ver_compare_custom,
        "AKSM800": @tenable_ot::cve::danfoss::AKSM800::ver_compare_custom,
        "Hikvision": @tenable_ot::cve::hikvision::ver_compare_custom,
        "DahuaSecurity": @tenable_ot::cve::dahuasecurity::ver_compare_custom,
        "Nexans": @tenable_ot::cve::nexans::ver_compare_custom,
        "InSight": @tenable_ot::cve::cognex::insight::ver_compare_custom,
        "DiskStation": @tenable_ot::cve::synology::diskstation::ver_compare_custom,
        "Hirschmann": @tenable_ot::cve::hirschmann::ver_compare_custom,
        "HanwhaVision": @tenable_ot::cve::hanwha::ver_compare_custom,
        "QuTShero": @tenable_ot::cve::qnap::qutshero::ver_compare_custom,
        "Teltonika": @tenable_ot::cve::teltonika::ver_compare_custom,
        "GeoVision": @tenable_ot::cve::geovision::ver_compare_custom,
        "JetNet": @tenable_ot::cve::korenix::ver_compare_custom,
        "Microhard": @tenable_ot::cve::microhard::ver_compare_custom
      };

      # NVD may refer to vulnerable Mitsubishi MELSEC-Q/MELSEC-L products thanks to the first digits of their serial numbers
      if (
        tolower(cpe_family) =~ "melsec[ql]"
        && !empty_or_null(asset.serial) 
        && asset.serial =~ "^\d{5}"
        && fix =~ "^\d{5}$"
      )
      {
        var serial_match = pregmatch(pattern:"^\d{5}", string:asset.serial);

        if( !empty_or_null(serial_match) && !empty_or_null(serial_match[0]) )
        {
          ver = serial_match[0];
        }
      }

      if ( tolower(cpe_family) == "ape1808" )
        return tenable_ot::cve::siemens::ape::ver_compare_custom(asset:asset, fix:fix);
      else if ( !empty_or_null(cpe_family) && ver_compare_funcs[cpe_family] )
        return ver_compare_funcs[cpe_family](ver:ver, fix:fix);
      else if ( !empty_or_null(vendor) && ver_compare_funcs[vendor] )
        return ver_compare_funcs[vendor](ver:ver, fix:fix);
      else
        return ver_compare(ver:ver, fix:fix, strict:false);
    }

    ##
    # Compare version range from CPE
    # 
    # @param [ver:string] firmware version
    # @param [criteria:array] version element (e.g. versionEndIncluding) as key and associated version as value
    #
    # @return true if firmware version is in version range
    #         false if firmware version is not in version range
    #         NULL if an error occurred
    ##
    function compare(asset, criteria, cpe_family)
    {
      var match_start, match_end, res_compare;

      match_start = false;
      match_end = false;

      # if elements don't exist return true
      if (
        !(criteria.versionStartIncluding || criteria.versionStartExcluding ||
        criteria.versionEndIncluding || criteria.versionEndExcluding)
      )
        return true;

      if (empty_or_null(asset.firmwareVersion))
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Missing "asset.firmwareVersion" argument.');
        return NULL;
      }

      # versionStart elements
      if (criteria.versionStartIncluding)
      {
        res_compare = ver_compare_helper(asset:asset, fix:criteria.versionStartIncluding, cpe_family:cpe_family);
        if(isnull(res_compare)) return NULL;

        match_start = (res_compare >= 0);
      } else if (!match_start && criteria.versionStartExcluding)
      {
        res_compare = ver_compare_helper(asset:asset, fix:criteria.versionStartExcluding, cpe_family:cpe_family);
        if(isnull(res_compare)) return NULL;

        match_start = (res_compare > 0);
      }

      # versionEnd elements
      if (criteria.versionEndIncluding)
      {
        res_compare = ver_compare_helper(asset:asset, fix:criteria.versionEndIncluding, cpe_family:cpe_family);
        if(isnull(res_compare)) return NULL;

        match_end = (res_compare < 1);
      } else if (!match_end && criteria.versionEndExcluding)
      {
        res_compare = ver_compare_helper(asset:asset, fix:criteria.versionEndExcluding, cpe_family:cpe_family);
        if(isnull(res_compare)) return NULL;

        match_end = (res_compare < 0);
      }

      # versionStart AND versionEnd elements are specified
      if (
        (criteria.versionStartIncluding || criteria.versionStartExcluding) &&
        (criteria.versionEndIncluding || criteria.versionEndExcluding)
      )
        return (match_start && match_end);
      
      # versionStart OR versionEnd element is specifed
      return (match_start || match_end);
    }

    ##
    # Compare asset modelName to model from CPE OR models list
    # 
    # @param [asset:string] asset information
    # @param [cpes:array] list of vulnerable CPEs from plugin
    # @param [cpe_family] cpe family as extracted via family regex in _is_vulnerable
    # @param [vuln_model:array] a single vulnerable model from plugin, if included
    #
    # @return true if model matches a vulnerable model
    #         false if model does not match a vulnerable model
    ##
    function model_compare(asset, cpe, cpe_family, vuln_model)
    {
      if (!empty_or_null(vuln_model))
      {
        if (vuln_model >< asset.modelName)
          return OT_SUCCESS;
        return OT_FAILURE;
      }
      else
      {
        # handle model matching for non-special vendors:
        # 1. check if cpe_match is substr of model_match
        # 2. check if model_match is substr of cpe_match
        cpe_family = tolower(cpe_family);
        var cpe_match = pregmatch(pattern:tenable_ot::regexes::models[cpe_family].genericModelRegex, string:tolower(cpe));
        if(!empty_or_null(cpe_match))
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe_match: ',obj_rep(cpe_match)));

        if(!empty_or_null(asset.modelName))
          asset.modelName = str_replace(string:asset.modelName, find:' ', replace:'');
        var model_match = pregmatch(pattern:tenable_ot::regexes::models[cpe_family].genericModelRegex, string:tolower(asset.modelName));
        if(!empty_or_null(model_match))
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model_match: ',obj_rep(model_match)));

        # For Metasys and PowerLogic, we use regexes to extract groups and then 
        # check if the groups are substrings of the larger groups.

        if ( empty_or_null(cpe_match) || empty_or_null(cpe_match[0]) || 
          empty_or_null(model_match) || empty_or_null(model_match[0]) )
          return OT_FAILURE;

        if ( cpe_match[0] >< model_match[0] )
        {
          return OT_SUCCESS;
        }
        if ( model_match[0] >< cpe_match[0] )
        {
          return OT_SUCCESS;
        }
        if ( !empty_or_null(model_match[1]) && !empty_or_null(model_match[2]) &&
            ( model_match[1] >< cpe_match[0] && model_match[2] >< cpe_match[0] ) )
          return OT_SUCCESS;
        if ( !empty_or_null(cpe_match[1]) && !empty_or_null(cpe_match[2]) &&
            ( cpe_match[1] >< model_match[0] && cpe_match[2] >< model_match[0] ) )
          return OT_SUCCESS;
      }

      return OT_FAILURE;
    }

    ##
    # Check if an asset is of a controller type AND cpe string contains 'controller'
    #
    # @param [asset:array] asset information pulled from the scan
    # @param [cpe:string] vulnerable CPE string to test against
    #
    # @return true cpe does not contain 'controller', cpe contains 'controller' and asset is of type controller
    #         false iff cpe contains 'controller' AND asset is not of type controller
    ##
    function check_controller(asset, cpe)
    {
      if (empty_or_null(asset.type))
        return true;

      if ('controller' >< tolower(cpe))
      {
        foreach var type (controller_types)
        {
          if (tolower(asset.type) == type)
            return true;
        }
        return false;
      }

      return true;
    }

    function _extract_model_indicators_symphony(model_name, family, type)
    {
      var model_info = {
        "generic_model_number": ""
      };

      var model_str = tolower(model_name);
      var family_name = tolower(family);

      local_var generic_matches;
      local_var model_number;
      # Check if an asset type was specified for model matching
      if( !empty_or_null(type) )
      {
        generic_matches = pregmatch(pattern:tenable_ot::regexes::models[family_name][type].genericModelRegex, string:model_str);
      }

      if ( !empty_or_null(generic_matches) )
      {
        if ( !empty_or_null(generic_matches[0]) )
          model_number = str_replace(string: generic_matches[0], find:"-" , replace:"");
          model_number = str_replace(string: model_number, find:"_" , replace:"");
          model_number = str_replace(string: model_number, find:" " , replace:"");
          model_info.generic_model_number = model_number;
      }
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'model_info: '+obj_rep(model_info));

      return model_info;
    }

    ##
    # Extracts effective model from modelName or CPE string
    # 
    # @param [model_str:string] modelName or CPE string
    #
    # @return array: generic_part_number, generic_model_number, part_number,
    #         model_indicator, subfamily
    ##
    function _extract_model_indicators(model_name, vendor, type)
    {
      var model_info = {
        "generic_part_number": "",
        "generic_model_number": "",
        "part_number": "",
        "model_indicator": "",
        "subfamily": ""
      };

      var model_str = tolower(model_name);
      var vendor_name = tolower(vendor);

      local_var generic_matches, part_number, model_indicator, subfamily;
      # Check if an asset type was specified for model matching
      if( !empty_or_null(type) )
      {
        generic_matches = pregmatch(pattern:tenable_ot::regexes::models[vendor_name][type].genericModelRegex, string:model_str);
        part_number = pregmatch(pattern:tenable_ot::regexes::models[vendor_name][type].partNumberRegex, string:model_str);
        model_indicator = pregmatch(pattern:tenable_ot::regexes::models[vendor_name][type].modelIndicatorRegex, string:model_str);
        subfamily = pregmatch(pattern:tenable_ot::regexes::models[vendor_name][type].subFamilyRegex, string:model_str);
      }
      else
      {
        generic_matches = pregmatch(pattern:tenable_ot::regexes::models[vendor_name].genericModelRegex, string:model_str);
        part_number = pregmatch(pattern:tenable_ot::regexes::models[vendor_name].partNumberRegex, string:model_str);
        model_indicator = pregmatch(pattern:tenable_ot::regexes::models[vendor_name].modelIndicatorRegex, string:model_str);
        subfamily = pregmatch(pattern:tenable_ot::regexes::models[vendor_name].subFamilyRegex, string:model_str);
      }

      if ( !empty_or_null(generic_matches) )
      {
        if ( !empty_or_null(generic_matches[1]) )
          model_info.generic_part_number = generic_matches[1];
        if ( !empty_or_null(generic_matches[2]) )
          model_info.generic_model_number = generic_matches[2];
      }
      if ( !empty_or_null(part_number) && !empty_or_null(part_number[0]))
        model_info.part_number = part_number[0];

      if ( !empty_or_null(model_indicator) && !empty_or_null(model_indicator[0]) )
        model_info.model_indicator = model_indicator[0];

      if ( !empty_or_null(subfamily) && !empty_or_null(subfamily[0]) )
        model_info.subfamily = subfamily[0];

      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'model_info: '+obj_rep(model_info));

      return model_info;
    }


    ##
    # Helper function to choose the correct model_compare to use. Add new model_compare functions to 
    # the model_compare_funcs table.
    # 
    # @param [asset:string] asset information
    # @param [cpe:string] vulnerable CPE from plugin, calling function should iterate over lists
    # @param [cpe_family] cpe family as extracted via family regex in _is_vulnerable
    # @param [vuln_model:array] a single vulnerable model from the plugin, if included
    #
    # @return true if model matches a vulnerable model
    #         false if model does not match a vulnerable model
    ##
    function model_compare_helper(&asset, cpe, cpe_family, vuln_model, order_numbers)
    {
      var model_compare_funcs = {
        "Wago" : @tenable_ot::cve::wago::model_compare,
        "Rockwell" : @tenable_ot::cve::rockwell::model_compare,
        "JohnsonControls" : @tenable_ot::cve::model_compare,
        "PhoenixContact" : @tenable_ot::cve::phoenixcontact::model_compare,
        "PowerLogicPM" : @tenable_ot::cve::model_compare,
        "ModiconM340M580CP" : @tenable_ot::cve::model_compare,
        "ModiconM340PRA" : @tenable_ot::cve::model_compare,
        "ModiconM340": @tenable_ot::cve::schneider::modicon::model_compare,
        "ModiconM580" : @tenable_ot::cve::schneider::modicon::model_compare,
        "ModiconMC80" : @tenable_ot::cve::schneider::modicon::model_compare,
        "MomentumUnity" : @tenable_ot::cve::schneider::modicon::model_compare,
        "PremiumCP" : @tenable_ot::cve::schneider::modicon::model_compare,
        "Premium" : @tenable_ot::cve::schneider::modicon::model_compare,
        "QuantumUnityCP" : @tenable_ot::cve::schneider::modicon::model_compare,
        "QuantumUnity" : @tenable_ot::cve::schneider::modicon::model_compare,
        "QuantumConcept" : @tenable_ot::cve::schneider::modicon::model_compare,
        "Atrium" : @tenable_ot::cve::schneider::modicon::model_compare,
        "Concept" : @tenable_ot::cve::schneider::modicon::model_compare,
        "Compact" : @tenable_ot::cve::schneider::modicon::model_compare,
        "MomentumConcept" : @tenable_ot::cve::schneider::modicon::model_compare,
        "Micom" : @tenable_ot::cve::schneider::micom::model_compare,
        "MelodyRack" : @tenable_ot::cve::abb::symphonyplus::model_compare,
        "HarmonyRack" : @tenable_ot::cve::abb::symphonyplus::model_compare,
        "SDSeries" : @tenable_ot::cve::abb::symphonyplus::model_compare,
        "Omron" : @tenable_ot::cve::omron::model_compare,
        "Rtac" : @tenable_ot::cve::sel::model_compare,
        "Sel" : @tenable_ot::cve::sel::model_compare,
        "Mitsubishi" : @tenable_ot::cve::mitsubishi::model_compare,
        "Moxa" : @tenable_ot::cve::moxa::model_compare,
        "SITOP" : @tenable_ot::cve::siemens::sitop::model_compare,
        "PxcCompact" : @tenable_ot::cve::siemens::desigo::model_compare,
        "PxcModular" : @tenable_ot::cve::siemens::desigo::model_compare,
        "Festo" : @tenable_ot::cve::festo::model_compare,
        "iDRAC7" : @tenable_ot::cve::dell::idrac::model_compare,
        "iDRAC8" : @tenable_ot::cve::dell::idrac::model_compare,
        "Neuberger": @tenable_ot::cve::neuberger::model_compare,
        "AxisCommunication": @tenable_ot::cve::axis::model_compare,
        "AUTODOME": @tenable_ot::cve::bosch::model_compare,
        "MIC": @tenable_ot::cve::bosch::model_compare,
        "MobotixCameras": @tenable_ot::cve::mobotix::mobotixcameras::model_compare,
        "MFP": @tenable_ot::cve::ricoh::mfp::model_compare,
        "CiscoIPPhones": @tenable_ot::cve::cisco::ciscoipphones::model_compare,
        "CiscoSmallBusiness": @tenable_ot::cve::cisco::ciscosmallbusiness::model_compare,
        "Watchdog": @tenable_ot::cve::vertiv::watchdog::model_compare,
        "WestermoLynx": @tenable_ot::cve::westermo::westermolynx::model_compare,
        "Westermo": @tenable_ot::cve::westermo::model_compare,
        "LANTIME": @tenable_ot::cve::meinberg::lantime::model_compare,
        "Zebra": @tenable_ot::cve::zebra::model_compare,
        "IRZRouters": @tenable_ot::cve::irz::irzrouters::model_compare,
        "WelotecIndustrialRouters": @tenable_ot::cve::welotec::welotecindustrialrouters::model_compare,
        "Hikvision": @tenable_ot::cve::hikvision::model_compare,
        "DahuaSecurity": @tenable_ot::cve::dahuasecurity::model_compare,
        "PanasonicIPCameras": @tenable_ot::cve::panasonic::panasonicipcameras::model_compare,
        "Ovation": @tenable_ot::cve::emerson::ovation::model_compare,
        "SEHUSBDeviceServers": @tenable_ot::cve::seh::sehusbdeviceservers::model_compare,
        "Sony": @tenable_ot::cve::sony::model_compare,
        "DellLaserPrinter": @tenable_ot::cve::dell::laserprinter::model_compare,
        "DiskStation": @tenable_ot::cve::synology::diskstation::model_compare,
        "Hirschmann": @tenable_ot::cve::hirschmann::model_compare,
        "HanwhaVision": @tenable_ot::cve::hanwha::model_compare,
        "GeoVision": @tenable_ot::cve::geovision::model_compare,
        "JetNet": @tenable_ot::cve::korenix::model_compare,
        "SPRECONE": @tenable_ot::cve::sprecherautomation::sprecone::model_compare,
        "EHPMX": @tenable_ot::cve::honeywell::experion::model_compare,
        "HoneywellExperion": @tenable_ot::cve::honeywell::experion::model_compare,
        "MicrohardCellularModem": @tenable_ot::cve::microhard::model_compare
      };

      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), ',\n\tcpe: ', cpe, ',\n\tcpe_family: ', cpe_family, ',\n\tvuln_model:', obj_rep(vuln_model), ',\n\torder_numbers: ', obj_rep(order_numbers), '\n'));

      if ( !empty_or_null(vuln_model) )
        return tenable_ot::cve::model_compare(asset:asset, vuln_model:vuln_model);

      if ( empty_or_null(cpe_family) )
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'cpe_family is empty, cannot continue. check that plugin CPE strings are valid and for families we handle.\n');
        return OT_FAILURE;
      }

      if (cpe_family =~ "scalance\w")
      {
        return tenable_ot::cve::siemens::scalance::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family, order_numbers:order_numbers);
      }
      else if (cpe_family =~ "s7\d+")
      {
        return tenable_ot::cve::siemens::simatics7::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family, order_numbers:order_numbers);
      }
      else if (cpe_family =~ "ruggedcom")
      {
        return tenable_ot::cve::siemens::ruggedcom::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family, order_numbers:order_numbers);
      }
      else if (cpe_family =~ "sicam[qp]\d+")
      {
        return tenable_ot::cve::siemens::sicam::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family, order_numbers:order_numbers);
      }
      else if (cpe_family =~ "netcp1600")
      {
        return tenable_ot::cve::siemens::simaticnet::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family, order_numbers:order_numbers);
      }
      else if (cpe_family =~ "siprotec\d?")
      {
        return tenable_ot::cve::siemens::siprotec::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
      }
      else if (cpe_family =~ "logo![bec]m")
      {
        return tenable_ot::cve::siemens::logo::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
      }
      else if (tolower(asset.vendor) == "eaton" && cpe_family =~ "^(plc|ups)")
      {
        # Special case for UPS9000x where cpe is 9000x and model is v[ps]x9000, default to family match
        if (cpe_family == "UPS9000X")
        {
          return OT_NEXTMATCH;
        }
        return tenable_ot::cve::eaton::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
      }
      else if (cpe_family =~ "powerlogicegx")
      {
        return tenable_ot::cve::siemens::powerlogicegx::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
      }
      else if ( model_compare_funcs[asset.vendor] )
        return model_compare_funcs[asset.vendor](asset:asset, cpe:cpe, cpe_family:cpe_family);
      else if ( model_compare_funcs[cpe_family] )
        return model_compare_funcs[cpe_family](asset:asset, cpe:cpe, cpe_family:cpe_family);
      else if ( !empty_or_null(tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex) )
      {
        return model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
      }
      else
      { 
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'returning OT_NEXTMATCH');
        return OT_NEXTMATCH;
      }
    }

    ##
    # Helper function to perform common checks when model matching is required
    # 
    # @param [asset:string] asset information
    # @param [cpe:string] vulnerable CPE from plugin, calling function should iterate over lists
    # @param [model_regex] model regex
    #
    # @return true if model matches a vulnerable model
    #         false if model does not match a vulnerable model
    ##
    function model_matching(asset, cpe, model_regex, loose_comparison)
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), '; cpe: ', cpe, '; model_regex: ', model_regex));

      # At this point the model_regex should be set
      if(empty_or_null(model_regex))
      {
        return OT_NEXTMATCH;
      }

      var model = "";

      var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

      if (dcpe[0] != IF_OK)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
        return OT_FAILURE;
      }

      var product = tolower(urldecode(estr:dcpe[1].product));
      
      if(!empty_or_null(asset.modelName))
      {
        model = tolower(asset.modelName);
      }
      else
      {
        # If asset model is not set and cpe includes model, return failure
        if (product =~ model_regex)
        { 
            return OT_FAILURE;
        }
        # Else, default to family matching
        return OT_NEXTMATCH;
      }

      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model: ', model));

      # If the specified model does not match the regex, exit
      if((model !~ model_regex))
      {
        return OT_FAILURE;
      }

      # If cpe does not match model regex, default to family checking
      if(product !~ model_regex)
      {
        return OT_NEXTMATCH;
      }

      # Let's compare models the models mentioned in both asset.modelName and in the CPE
      var cpeModel = pregmatch(pattern:model_regex, string:product);
      var extractedModel = pregmatch(pattern:model_regex, string:model);

      if(!empty_or_null(cpeModel) && !empty_or_null(extractedModel))
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpeModel: ', obj_rep(cpeModel),'; extractedModel: ', obj_rep(extractedModel)));
        
        # pregmatch return the whole match as first element, then captured groups
        # so if captured groups are involved, we skip the first element
        var i = 0;
        if (len(cpeModel) > 1)
        {
          i = 1;
        }

        # Allow to use multiple capturing groups to be compared
        for (; i<len(cpeModel); i++)
        {
          var res = cpeModel[i] != extractedModel[i];

          # loose_comparison allows to search for substrings
          if(!empty_or_null(loose_comparison) && loose_comparison == 1){
            res = cpeModel[i] >!< extractedModel[i];
          }

          if (res)
          {
            return OT_FAILURE;
          }
        }

        return OT_SUCCESS;
      }

      return OT_FAILURE;
    }

    ##
    # Helper function to perform common checks when application matching is required
    # 
    # @param [asset:string] asset information
    # @param [cpe:string] vulnerable CPE from plugin, calling function should iterate over lists
    # @param [app] app as listed in
    #
    # @return true if asset matches the app in the cpe
    #         false if asset does not match the app in the cpe
    ##
    function app_compare_helper(&asset, cpe, app)
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', asset, '; cpe: ', cpe, '; app: ', app));
      var app_compare_funcs = {
        "Niagara" : @tenable_ot::cve::tridium::app_compare
      };

      if ( app_compare_funcs[app] )
        return app_compare_funcs[app](asset:asset);
      else
      {
        dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'returning OT_NEXTMATCH');
        return OT_NEXTMATCH;
      }
    }

    ##
    # Quick helper function which sanitizes a cpe before calling 
    # the install_func.inc decode_cpe function 
    #
    # @param [base_cpe:string] cpe
    #
    # @return the decoded cpe
    ##
    function decode_cpe_helper(base_cpe)
    {
      # Sanitize/encode here - based on unreserved variable from urlencode() - url_func.inc
      var unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'/-:%]";
      var lcpe = urlencode(str:base_cpe, unreserved:unreserved);
      return decode_cpe(base_cpe:lcpe);
    }

    namespace abb
    {
      # For versions that have format "^(\d+\.\d+\.\d+\.)[A-Za-z]\d$" (e.g.1.1.0.c0) replace 
      # char c with a numeric equivalent (e.g. ord('c')-ord('A') = 1.1.0.34.0).

      function ver_compare_custom(ver, fix)
      {
        local_var new_ver, new_fix, pattern, current_char;
        if ( ver =~ "^(\d+\.\d+\.\d+\.)[A-Za-z]\d$" )
        {
          new_ver = ereg_replace(pattern:"^(\d+\.\d+\.\d+\.)[A-Za-z]\d$", string:ver, replace:"\1");
          new_ver = new_ver + (ord(ver[strlen(ver)-2]) - ord('A'));
          new_ver = new_ver + '.' + ver[strlen(ver)-1];
          ver = new_ver;
        }
        else if ( ver =~ "^\d+\.\d+\.\d+-\d+$")
        {
          ver = str_replace(string:ver, find:'-', replace:'.');
        }
        else if (ver =~ "\d{0,}?-\d{0,}")
        {
          ver = str_replace(string:ver, find:'-', replace:'.');
        }
        else if (ver =~ "r\.(\d\.?)+_ics\d{0,}")
        {
          ver = pregmatch(pattern:"r\.(\d\.?)+_ics\d{0,}", string:ver);
          ver = ver[1];
        }
        else if (ver =~ "[[A-Za-z]\d{1,2}[A-Za-z]\d{1,3}_{0,1}\d{0,}")
        {
          ver = str_replace(string:ver, find:'r',replace:'');
          pattern = "_\d{0,}";
          
          if (pregmatch(pattern:pattern, string:ver))
          {
            ver = ereg_replace(pattern:pattern, replace:"", string:ver);
          }
          for (var i=0; i<strlen(ver); i++)
          {
            current_char = toupper(ver[i]);
            
            # If the character is a letter, convert it to its numerical value and append it to the converted string
            if (pregmatch(string:current_char, pattern:"[a-zA-Z]"))
            {
              var converted_value = ord(current_char) - ord('A');
              # Add a period before and after the converted value if the letter is surrounded by numerical values
              if (i > 0 && i < strlen(ver) - 1 && pregmatch(string:ver[i-1], pattern:"[0-9]") && pregmatch(string: ver[i+1], pattern: "[0-9]"))
              {
                new_ver += "." + converted_value + ".";
              }
              else
              {
                new_ver += converted_value;
                # Add a period after the letter if it's not at the end of the string
                if (i < strlen(ver) - 1)
                {
                  new_ver += ".";
                }
              }
            }
            # If the character is a number, append it directly to the converted string
            else
            {
              new_ver += current_char;
            }
            ver = new_ver;
          }
        }
        else if (ver =~ "[A-Za-z]_[A-Za-z\d]")
        {
          // ver = str_replace(string:ver, find:'_',replace:'.');
          for (i=0; i<strlen(ver); i++)
          {
            current_char = toupper(ver[i]);

            if(pregmatch(string:current_char, pattern:"[A-Z]"))
            {
              converted_value = ord(current_char) - ord('A');
              new_ver += converted_value;
            }
            else if (pregmatch(string:current_char, pattern:"_"))
            {
              new_ver += ".";
            }
            else{
              new_fix += current_char;
            }
          }
          ver = new_ver;
        }
        if ( fix =~ "^(\d+\.\d+\.\d+\.)[A-Za-z]\d$" )
        {
          new_fix = ereg_replace(pattern:"^(\d+\.\d+\.\d+\.)[A-Za-z]\d$", string:fix, replace:"\1");
          new_fix = new_fix + (ord(fix[strlen(fix)-2]) - ord('A'));
          new_fix = new_fix + '.' + fix[strlen(fix)-1];
          fix = new_fix;
        }
        else if(fix =~ "[A-Za-z]_[A-Za-z\d]")
        {
          for (i=0; i<strlen(fix); i++)
          {
            current_char = toupper(fix[i]);

            if(pregmatch(string:current_char, pattern:"[A-Z]"))
            {
              converted_value = ord(current_char) - ord('A');
              new_fix += converted_value;
            }
            else if (pregmatch(string:current_char, pattern:"_"))
            {
              new_fix += ".";
            }
            else{
              new_fix += current_char;
            }
          }
          fix = new_fix;
        }
        else if ( fix =~ "^\d+\.\d+\.\d+-\d+$")
        {
          fix = str_replace(string:fix, find:'-', replace:'.');
        }
        else if (fix =~ "\d{0,}?-\d{0,}")
        {
          fix = str_replace(string:fix, find:'-', replace:'.');
        }
        else if (fix =~ "r\.(\d\.?)+_ics\d{0,}")
        {
          fix = pregmatch(pattern:"r\.(\d\.?)+_ics\d{0,}", string:fix);
          fix = fix[1];
        }
        else if (fix =~ "[[A-Za-z]\d{1,2}[A-Za-z]\d{1,3}_{0,1}\d{0,}")
        {
          fix = str_replace(string:fix, find:'r',replace:'');
          pattern = "_\d{0,}";

          if (pregmatch(pattern:pattern, string:fix))
          {
            fix = ereg_replace(pattern: pattern, replace:"", string:fix);
          }
          for (i=0; i<strlen(fix); i++)
          {
            current_char = toupper(fix[i]);

            # If the character is a letter, convert it to its numerical value and append it to the converted string
            if (pregmatch(string:current_char, pattern:"[a-zA-Z]"))
            {
              converted_value = ord(current_char) - ord('A');
              # Add a period before and after the converted value if the letter is surrounded by numerical values
              if (i > 0 && i < strlen(fix) - 1 && pregmatch(string:fix[i-1], pattern:"[0-9]") && pregmatch(string:fix[i+1], pattern:"[0-9]"))
              {
                new_fix += "." + converted_value + ".";
              }
              else
              {
                new_fix += converted_value;
                # Add a period after the letter if it's not at the end of the string
                if (i < strlen(fix) - 1)
                {
                    new_fix += ".";
                }
              }
            }
            # If the character is a number, append it directly to the converted string
            else
            {
              new_fix += current_char;
            }
            fix = new_fix;
          }
        }
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      namespace symphonyplus
      {
        ##
        # Compare asset modelName to model from CPE OR models list
        # 
        # @param [asset:string] asset information
        # @param [cpes:array] list of vulnerable CPEs from plugin
        # @param [vuln_models:array] list of vulnerable models from plugin, if included
        #
        # @return true if model matches a vulnerable model
        #         false if model does not match a vulnerable model
        ##
        function model_compare(asset, cpe, cpe_family)
        {
          return tenable_ot::cve::abb::symphonyplus::check_model_indicators(asset:asset, cpe:cpe, cpe_family:cpe_family);
        }

        ##
        # Run a series of checks to see if the modelName is a vulnerable model
        #
        # @param [asset:string] asset information
        # @param [cpe:array] CPE info from CPE array
        #
        # @return true if model matches a vulnerable model
        #         false if model does not match a vulnerable model
        ##

        function check_model_indicators(asset, cpe, cpe_family)
        {
          var model_name = tolower(asset.modelName);
          var family_name = tolower(asset.family);
          var asset_type = tolower(asset.type);

          local_var ret, asset_model_info, cpe_model_info;
          # Check if asset is a communication module
          if (asset_type == "cp")
          {
            asset_model_info = tenable_ot::cve::_extract_model_indicators_symphony(model_name:model_name, family:family_name, type:"cp");
            cpe_model_info = tenable_ot::cve::_extract_model_indicators_symphony(model_name:cpe, family:family_name, type:"cp");
            ret = check_cp_asset_with_cpe(asset_model_info:asset_model_info, cpe_model_info:cpe_model_info);
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_cp_asset_with_cpe result: ' + ret);
            return ret;
          }
          else{
            # Else, default to controller type
            asset_model_info = tenable_ot::cve::_extract_model_indicators_symphony(model_name:model_name, family:family_name, type:"controller");
            cpe_model_info = tenable_ot::cve::_extract_model_indicators_symphony(model_name:cpe, family:family_name, type:"controller");

            # successOnAssetModelNameMatchCpeModel
            ret = check_asset_model_name_in_cpe(asset_model_info:asset_model_info, cpe_model_info:cpe_model_info);
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_asset_model_name_in_cpe result: ' + ret);
            if ( ret != OT_NEXTMATCH ) return ret;

            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'No matched conditions');
          }
          return OT_SUCCESS;
        }
        ##
        # Check if Communication module asset's model info is present is vulnerable to the cpe
        #
        # @param [asset_model_info:array] output of _extract_model_indicators_symphony()
        # @param [cpe_model_info:array] output of _extract_model_indicators_symphony()
        #
        # @return true if model matches a vulnerable model
        #         false if model does not match a vulnerable model
        ##
        function check_cp_asset_with_cpe(asset_model_info, cpe_model_info)
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe: ', cpe_model_info.generic_model_number, '; model: ', asset_model_info.generic_model_number));

          if ( empty_or_null(asset_model_info.generic_model_number))
              return OT_FAILURE;

          if ( empty_or_null(cpe_model_info.generic_model_number))
              return OT_FAILURE;

          # Check if model and generic part number match
          if (asset_model_info.generic_model_number == cpe_model_info.generic_model_number)
              return OT_SUCCESS;

          return OT_FAILURE;
        }
        ##
        # Check if asset's model info is present in the vulnerable CPE
        # 
        # @param [asset_model_info:array] output of _extract_model_indicators()
        # @param [cpe:string] vulnerable CPE string to test against
        #
        # @return true if model matches a vulnerable model
        #         false if model does not match a vulnerable model
        ##
        function check_asset_model_name_in_cpe(asset_model_info, cpe_model_info)
        {
          # successOnAssetModelNameMatchCpeModel

          if ( empty_or_null(asset_model_info.generic_model_number))
            return OT_NEXTMATCH;

          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model: ', asset_model_info.generic_model_number));

          if ( empty_or_null(cpe_model_info.generic_model_number))
              return OT_NEXTMATCH;

          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model: ', cpe_model_info.generic_model_number));

          if (asset_model_info.generic_model_number == cpe_model_info.generic_model_number)
            return OT_SUCCESS;

          return OT_FAILURE;
        }
      }
    }

    namespace axis
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["axis"].genericModelRegex;
        var loose_comparison = 0;

        if ('series' >< cpe)
        {
          model_regex = tenable_ot::regexes::models["axis"].seriesRegex;
          loose_comparison = 1;
        }

        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex, loose_comparison:loose_comparison);
      }
    }

    namespace bosch
    {
      function ver_compare_custom(ver, fix)
      {
        var prefix = "cpp";
        ver = ver - prefix;
        fix = fix - prefix;
 
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["boschsecuritysystems"].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace cisco
    {
      function format_release_number(ver)
      {
        # Versions may contain urlencoded characters (i.e. parenthesis)
        if ( ver =~ '%[0-9a-fA-F]{2}' )
        {
          ver = urldecode(estr:ver);
        }

        # Stripping escaping char '\'
        ver = str_replace(string:ver, find:'\\', replace:'');

        # Catching releases numbers like 7.0(3)I7(9)
        var regex = "^([\d\.]+)(\([a-zA-Z0-9\.]+\))?([a-zA-Z0-9]+)?(\([a-zA-Z0-9\.]+\))?";
        if ( ver =~ regex )
        {
          ver = pregmatch(pattern:regex, string:ver);
          
          # We have at least one capturing group with weird chars to update
          if(!empty_or_null(ver) && !empty_or_null(ver[1]))
          {
            # Captured groups may have trailing dots
            var new_release_version = ereg_replace(pattern:"\.$", replace:"", string:ver[1]);
            
            # Some groups need formatting
            if(len(ver) > 2)
            {
              for (var i=2; i<len(ver); i++)
              {
                var group = ereg_replace(pattern:"[\(\)]", replace:"", string:ver[i]);
                
                if(! empty_or_null(group))
                {
                  # Captured groups may have trailing dots
                  group = ereg_replace(pattern:"\.$", replace:"", string:group);
                  group = '.' + group;

                  # Skipping the first dot
                  for(var j=0; j<strlen(group); j++)
                  {
                    var current_char = group[j];
                    if ( current_char =~ '[a-zA-Z]' )
                    {
                      current_char = ord(current_char) - ord('A');
                    }
                    
                    new_release_version = new_release_version + current_char;
                  }
                }
              }
            }
        
            # As the max number of digits is 10 (because of native ver_compare casting in int type)
            # we need to split versions more than 10 digits long
            var versions = split(new_release_version, sep: '.', keep: FALSE);
            new_release_version = '';
            for(var x=0;x<len(versions);x++)
            {
              var version = versions[x];
              if(len(version) > 10)
              {
                version = '';
                for(var y=0;y<len(versions[x]);y++)
                {
                  version = version + versions[x][y];
                  if((y+1)%10 == 0)
                  {
                    version = version + '.';
                  }
                }
              }
              # Deleting potential trailing dot
              version = ereg_replace(pattern:"\.$", replace:"", string:version);
              new_release_version = new_release_version + version + '.';
            }
            # Deleting trailing dot
            new_release_version = ereg_replace(pattern:"\.$", replace:"", string:new_release_version);
            ver = new_release_version;
          }
        }
        return ver;
      }

      function ver_compare_custom(ver, fix)
      {
        ver = tenable_ot::cve::cisco::format_release_number(ver:ver);
        fix = tenable_ot::cve::cisco::format_release_number(ver:fix);

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      namespace ciscoipphones
      {
        function format_release_number(ver)
        {
          # Versions may contain urlencoded characters (i.e. parenthesis)
          if ( ver =~ '%[0-9a-fA-F]{2}' )
          {
            ver = urldecode(estr:ver);
          }

          var regex = "^(\d+)-(\d+)-(\d+)-?(?:sr|mpp|0)?-?(\d*)";
          if ( ver =~ regex )
          {
            var release_group = pregmatch(pattern:regex, string:ver);
            if(!empty_or_null(release_group) 
              && !empty_or_null(release_group[1])
              && !empty_or_null(release_group[2])
              && !empty_or_null(release_group[3])
            )
            {
              var ver_tmp = release_group[1] + '.' + release_group[2] + '(' + release_group[3] + ')';
              if(!empty_or_null(release_group[4]))
              {
                if('mpp' >!< ver)
                {
                  ver_tmp = ver_tmp + 'sr' + release_group[4][0];
                } else {
                  if(release_group[4] =~ '[0-9]{3}')
                  {
                    ver_tmp = ver_tmp + 'mppsr' + release_group[4][1];
                  } else {
                    ver_tmp = release_group[1] + '.' + release_group[2] + '(' + release_group[3] + '.' + release_group[4] + ')mpp';
                  }
                }
                
              }
              ver = ver_tmp;
            }
          }

          return ver;
        }

        function ver_compare_custom(ver, fix)
        {
          # Should be converted from 14-2-1-0201-40 to 14.2(1)SR2
          # or 9-4-2SR4 => 9.4(2)SR4
          ver = tolower(ver);
          fix = tolower(fix);
          ver = tenable_ot::cve::cisco::ciscoipphones::format_release_number(ver:ver);
          fix = tenable_ot::cve::cisco::ciscoipphones::format_release_number(ver:fix);

          # Only Multi Platform firmware vulnerable - 'MPP' in fix but not in version
          if('mpp' >< fix && 'mpp' >!< ver)
          {
            return NULL;
          }
          return tenable_ot::cve::cisco::ver_compare_custom(ver:ver, fix:fix);
        }

        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["ciscoipphones"].genericModelRegex;
          if ('series' >< cpe)
          {
            model_regex = tenable_ot::regexes::models["ciscoipphones"].seriesRegex;
          }
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace ciscosmallbusiness
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["ciscosmallbusiness"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace dahuasecurity
    {
      function ver_compare_custom(ver, fix)
      {
        var date_pattern = "\d{2,4}[-/]\d{2}[-/]\d{2,4}";
        var dahua_ver_regex = "v?\d+\.\d+\.\d+\.\d+\.r\.(\d{6})$";
        var dahua_ver_regex2 = "v?\d+\.\d+\.\d+\.\d+\.r\.(\d{8})$";
        local_var date, patt;
        ver = tolower(ver);
        fix = tolower(fix);

        # 2018-01-01 -> 2018.01.01
        if (ver =~ date_pattern)
        {
          var ddmmyyyy = "\d{2}/\d{2}/\d{4}";
          
          # 3.210.0001.3, Build Date:20/10/2016 -> 2016/10/20
          if (ver =~ ddmmyyyy)
          {
            date = pregmatch(pattern:ddmmyyyy, string:ver);
        
            if ( !empty_or_null(date) && !empty_or_null(date[0]) ){
        
              var date_parts = split(date[0], sep: '/', keep: FALSE);
              ver = date_parts[2] + "." + date_parts[1] + "." + date_parts[0];
            } 
          } else 
          {
            date = pregmatch(pattern:date_pattern, string:ver);
        
            if ( !empty_or_null(date) && !empty_or_null(date[0]) )
            {
              ver = date[0];
              ver = ereg_replace(pattern:"[\-/]", string:ver, replace:".");
            }
          }
        }
        #v2.812.0000032.2.r.220804 -> 2022.08.04
        else if (ver =~ dahua_ver_regex)
        {
          patt = pregmatch(pattern:dahua_ver_regex, string:ver);
          if ( !empty_or_null(patt) && !empty_or_null(patt[0]) && !empty_or_null(patt[1]))
          {
            date=patt[1];
            ver = "20"+date[0]+date[1]+"."+date[2]+date[3]+"."+date[4]+date[5];
          }
        }
        # v2.400.0000.3.r.20150312 -> 2015.03.12
        else if (ver =~ dahua_ver_regex2)
        {
          patt = pregmatch(pattern:dahua_ver_regex2, string:ver);
          if ( !empty_or_null(patt) && !empty_or_null(patt[0]) && !empty_or_null(patt[1]))
          {
            date=patt[1];
            ver = date[0]+date[1]+date[2]+date[3]+"."+date[4]+date[5]+"."+date[6]+date[7];
          }
        }

        # 2018-01-01
        if (fix =~ "\d{4}-\d{2}-\d{2}")
        {
          fix = str_replace(string:fix, find:'-', replace:'.');
        }
        #v2.812.0000032.2.r.220804 -> 2022.08.04
        else if (fix =~ dahua_ver_regex)
        {
          patt = pregmatch(pattern:dahua_ver_regex, string:fix);
          if ( !empty_or_null(patt) && !empty_or_null(patt[0]) && !empty_or_null(patt[1]))
          {
            date=patt[1];
            fix = "20"+date[0]+date[1]+"."+date[2]+date[3]+"."+date[4]+date[5];
          }
        }
        # v2.400.0000.3.r.20150312 -> 2015.03.12
        else if (fix =~ dahua_ver_regex2)
        {
          patt = pregmatch(pattern:dahua_ver_regex2, string:fix);
          if ( !empty_or_null(patt) && !empty_or_null(patt[0]) && !empty_or_null(patt[1]))
          {
            date = patt[1];
            fix = date[0]+date[1]+date[2]+date[3]+"."+date[4]+date[5]+"."+date[6]+date[7];
          }
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        local_var model_regex, cpe_regex;

        # strict model comparison

        if ( cpe =~ 'hac[\\-_]h.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].hdvciCameraRegex;
        }
        else if (cpe =~ 'ipc[\\-_]h.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].networkCameraRegex;
        }
        else if (cpe =~ 'ipc[\\-_]p.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].networkPanoramicCameraRegex;
        }
        else if (cpe =~ 'ipc[\\-_][cakgfdbt]\\d{2}.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].consumerCameraRegex;
        }
        else if (cpe =~ 'ipc[\\-_][bdt].*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].networkCameraEZIPRegex;
        }
        else if (cpe =~ 'tpc[\\-_].*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].thermalCameraRegex;
        }
        else if (cpe =~ '(?<!tpc-)sd\\d.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].speedDomeCameraRegex;
        }
        else if (cpe =~ '(eca|epc|sdzw)\\d.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].explosionProofAntiCorrosionCameraRegex;
        }
        else if (cpe =~ '(?:[nxd]|hc)vr-?\\d.*')
        {
          model_regex = tenable_ot::regexes::models["dahuasecurity"].videoRecorderRegex;
        }
        else
        {
          return OT_FAILURE;
        }

        # Perform model matching if asset model matches regex   
        if (asset.modelName =~ model_regex)
        {
          
          # remove _firmware suffix from cpe
          cpe = cpe - "_firmware";

          # loose model comparison fix
          # if the cpe contains placeholder values marked as x, replace it as a wildcard (.+ as it is sometimes responsible for multiple char) match it here
          if ( cpe =~ "x")
          {
            # decode cpe to keep only the product part
            var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

            if (dcpe[0] != IF_OK)
            {
              dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
              return OT_FAILURE;
            }

            cpe_regex = dcpe[1].product;
            # Remove the dhi?- prefix from the product
            cpe_regex = ereg_replace(pattern:"^dhi?-", string:cpe_regex, replace:"");
            cpe_regex = str_replace(string:cpe_regex, find:'x', replace:'.+');

            if ( asset.modelName =~ cpe_regex )
            {
              return OT_SUCCESS;
            }
            else
            {
              return OT_FAILURE;
            }
          }
          # Strict model comparison
          else
          {
            return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
          }
        }
        else
        {
          return OT_NEXTMATCH;
        }
      }
    }

    namespace danfoss
    {
      namespace AKSM800
      {
        function ver_compare_custom(ver, fix)
        {
          var prefix = "g";
          ver = tolower(ver);
          fix = tolower(fix);
          ver = ver - prefix;
          fix = fix -prefix;
  
          return ver_compare(ver:ver, fix:fix, strict:false);
        }
      }
    }

    namespace dell
    {
      namespace idrac
      {
        # Matching iDRAC flavor (RAC type)
        function model_compare(asset, cpe, cpe_family)
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), '; cpe_family: ', cpe_family));

          # Fallback to families comparison - RAC type not provided in asset
          if (empty_or_null(asset.modelName)) return OT_NEXTMATCH;

          /* 
          RAC type value will be sent through asset.modelName

          DellRacType ::= INTEGER
          {
            other(1),               -- the DRAC type is not one of the following
            unknown(2),             -- the DRAC type is unknown
            dracIII(3),             -- Drac III
            era(4),                 -- ERA
            drac4(5),               -- Drac 4
            drac5(6),               -- Drac 5
            drac5MC(7),             -- Drac 5/MC
            cmc(8),                 -- CMC
            idrac(9),               -- iDRAC
            idrac7monolithic(16),   -- iDRAC7 Monolithic
            idrac7modular(17),      -- iDRAC7 Modular
            vrtxCMC(18),            -- VRTX CMC
            fx2CMC(19),             -- FX2 Family CMC
            idrac8monolithic(32),   -- iDRAC8 Monolithic
            idrac8modular(33)       -- iDRAC8 Modular
          }
          */

          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          # None RAC type found in CPE
          if(!("monolithic" >< product || "modular" >< product)) return OT_NEXTMATCH;

          if ("monolithic" >< product && tolower(cpe_family) == "idrac7" && asset.modelName == "16") return TRUE;
          if ("modular" >< product && tolower(cpe_family) == "idrac7" && asset.modelName == "17") return TRUE;
          if ("monolithic" >< product && tolower(cpe_family) == "idrac8" && asset.modelName == "32") return TRUE;
          if ("modular" >< product && tolower(cpe_family) == "idrac8" && asset.modelName == "33") return TRUE;

          return OT_FAILURE;
        }
      }

      namespace laserprinter
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["delllaserprinter"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace eaton
    {
      function ver_compare_custom(ver, fix)
      {
        # 8.0r9
        if (ver=~ "r\d")
        {
          ver = str_replace(string:ver, find:'r', replace:'.');
        }
        if (fix =~ "r\d")
        {
          fix = str_replace(string:fix, find:'r', replace:'.');
        }
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["eaton"].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace emerson
    {
      namespace ovation
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["ovation"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace festo
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }

      # In case we match a pattern like this: 3.4.6+f1ea33e0b4ea.20170822.11854
      function ver_compare_custom(ver, fix)
      {
        if (ver =~ "^[0-9\.]+\+")
        {
          var temp_ver = pregmatch(pattern:"^([0-9\.]+)\+", string:ver);
          if (!empty_or_null(temp_ver) && !empty_or_null(temp_ver[1]))
            ver = temp_ver[1];
        }
        if (fix =~ "^[0-9\.]+\+")
        {
          var temp_fix = pregmatch(pattern:"^([0-9\.]+)\+", string:fix);
          if (!empty_or_null(temp_fix) && !empty_or_null(temp_fix[1]))
            fix = temp_fix[1];
        }

        return ver_compare(ver:str_replace(string:ver, find:"-", replace:"."), fix:str_replace(string:fix, find:"-", replace:"."), strict:false);
      }
    }

    namespace hanwha
    {
      function ver_compare_custom(ver, fix)
      {
        var prefix = "ss";
        ver = tolower(ver);
        fix = tolower(fix);
        ver = ver - prefix;
        fix = fix - prefix;
  
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;

        if ( 'series' >< cpe )
        {
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          # we get the series name
          var series = pregmatch(pattern:"^[a-zA-Z0-9]+_series", string:product);

          if( !empty_or_null(series) && !empty_or_null(series[0]) )
          {
            series = series[0];

            # we get the series regex
            model_regex = tenable_ot::regexes::models[tolower(cpe_family)][tolower(series)];
            if( empty_or_null(model_regex) )
            {
              return OT_FAILURE;
            }
          } else 
          {
            return OT_FAILURE;
          }
        }

        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace hikvision
    {
      function ver_compare_custom(ver, fix)
      {

        ver = ereg_replace(pattern:"(?i)[\s_]*b(?:uild)?[\s_]*", string:ver, replace:".");
        fix = ereg_replace(pattern:"(?i)[\s_]*b(?:uild)?[\s_]*", string:fix, replace:".");

        # residual underscore
        ver = str_replace(string:ver, find:'_', replace:'.');
        fix = str_replace(string:fix, find:'_', replace:'.');

        var prefix = "v";
        ver = tolower(ver);
        fix = tolower(fix);
        ver = ver - prefix;
        fix = fix -prefix;

        # Specific case comparing only build dates, e.g. "versionEndExcluding" : "build200123" => ".200123" (YYMMDD)
        if ( fix =~ "^\.[0-9]{6,}$" )
        {
          var build_date_fix = pregmatch(pattern:"\.([0-9]{6,})$", string:fix);
          var build_date_ver = pregmatch(pattern:"\.([0-9]{6,})$", string:ver);

          if ( !(empty_or_null(build_date_fix) || empty_or_null(build_date_fix[1]) || empty_or_null(build_date_ver) || empty_or_null(build_date_ver[1])) )
          {
            fix = build_date_fix[1];
            ver = build_date_ver[1];
          }
        }
        
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["hikvision"].genericModelRegex;

        if ( 'series' >< cpe )
        {
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          # We get the model prefix
          var series = pregmatch(pattern:"((?:i?ds|ipc)-[a-z0-9\(\)\/\-]+)_series", string:product);

          if( !empty_or_null(series) && !empty_or_null(series[1]) )
          {
            series = series[1];
            
            # remove trailing 'x' if necessary
            var pattern = str_replace(string:series, find:'x', replace:'.*');

            if(!empty_or_null(asset.modelName))
            {
              var model = tolower(asset.modelName);
              var model_match = pregmatch(pattern:pattern, string:model);
              
              if( !empty_or_null(model_match) && !empty_or_null(model_match[0]) )
              {
                return OT_SUCCESS;
              }
            }

            return OT_FAILURE;

          } else 
          {
            return OT_FAILURE;
          }
        }

        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace hirschmann
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["hirschmann"].hiosModelRegex;
        var res;

        # First we check if we can match HiOS/HiSecOS strings
        if(!empty_or_null(asset.os))
        {
          # Comparing HiOS/HiSecOS against nvd product
          asset.modelName = asset.os;
          res = tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);

          if(res == OT_SUCCESS)
          {
            return res;
          }
        } 

        # Then trying model matching with model names
        model_regex = tenable_ot::regexes::models["hirschmann"].genericModelRegex1;
        res = tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        
        if(res != OT_SUCCESS)
        {
          model_regex = tenable_ot::regexes::models["hirschmann"].genericModelRegex2;
          res = tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);

          if(res != OT_SUCCESS)
          {
            return OT_FAILURE;
          }
        }

        return res;
      }

      function ver_compare_custom(ver, fix)
      {

        # If ver looks like "HiOS-2A-09.0.02 2022-03-22 08:32"
        var regex = "Hi(?:Sec)?OS-[a-zA-Z0-9]+-([\d\.]+)";

        if ( ver =~ regex )
        {
          var extracted_ver = pregmatch(pattern:regex, string:ver);

          if ( !empty_or_null(extracted_ver) && !empty_or_null(extracted_ver[1]) )
          {
            ver = extracted_ver[1];
          }
        }
        
        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace honeywell
    {
      namespace experion
      {
        function ver_compare_custom(ver, fix)
        {
          # Experion version number can include hf (hotfix) and tcu (Tools and Contoller) such as 
          # 501.6hf8
          # 511.5tcu3 
          # We can treat them as sub-minor versions and replace them with a '.'
          
          if (ver=~ "^\d+\.\d+(?:hf|tcu)\d+$")
          {
            ver = str_replace(string:ver, find:'tcu', replace:'.');
            ver = str_replace(string:ver, find:'hf', replace:'.');
          }
          if (fix =~ "^\d+\.\d+(?:hf|tcu)\d+$")
          {
            fix = str_replace(string:fix, find:'tcu', replace:'.');
            fix = str_replace(string:fix, find:'hf', replace:'.');
          }
          return ver_compare(ver:ver, fix:fix, strict:false);
        }

        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace illustra
    {
      function ver_compare_custom(ver, fix)
      {
        var prefix = "ss";
        ver = tolower(ver);
        fix = tolower(fix);
        ver = ver - prefix;
        fix = fix - prefix;
  
        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace irz
    {
      namespace irzrouters
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["irzrouters"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace korenix
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }

      function ver_compare_custom(ver, fix){
        var prefix = "v";
        ver = tolower(ver);
        fix = tolower(fix);
        ver = ver - prefix;
        fix = fix -prefix;

        # transform letter suffix into numeric version for comparison*
        # eg 1.0c -> 1.0.34
        local_var new_ver, new_fix;
        if ( ver =~ "^(\d+\.\d+)[A-Za-z]$" )
        {
          new_ver = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:ver, replace:"\1.");
          new_ver = new_ver + (ord(ver[strlen(ver)-1]) - ord('A'));
          ver = new_ver;
        }

        if (fix =~ "^(\d+\.\d+)[A-Za-z]$")
        {
          new_fix = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:fix, replace:"\1.");
          new_fix = new_fix + (ord(fix[strlen(fix)-1]) - ord('A'));
          fix = new_fix;
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace meinberg
    {
      namespace lantime
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["lantime"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace microhard
    {

      function format_version(version)
      {
        # version may look like 1.2.2-r122

       var _version = preg_replace(pattern:"[\-_]", replace:'.', string:version);
        
        if( !empty_or_null(_version) ) version = _version;

        _version = preg_replace(pattern:"r", replace:'', string:version);
        
        if( !empty_or_null(_version) ) version = _version;

        return version;
      }

      function ver_compare_custom(ver, fix)
      {
        
        fix = tenable_ot::cve::microhard::format_version(version:fix);
        ver = tenable_ot::cve::microhard::format_version(version:ver);

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace mikrotik
    {
      function ver_compare_custom(ver, fix)
      {
        # Considering releases channels, e.g. 7.4beta4, 7.1rc4
        var channel_regex = "[0-9\.]+(\w*)";
        var channel_suffix_ver = "";
        var channel_suffix_fix = "";
        
        if (ver =~ channel_regex)
        {
          var channel_match = pregmatch(pattern:channel_regex, string:ver);
        
          if(!empty_or_null(channel_match) && !empty_or_null(channel_match[1]) )
          {
            channel_suffix_ver = channel_match[1];
          }
        }
        
        if (fix =~ channel_regex)
        {
          channel_match = pregmatch(pattern:channel_regex, string:fix);
        
          if(!empty_or_null(channel_match) && !empty_or_null(channel_match[1]) )
          {
            channel_suffix_fix = channel_match[1];
          }
        }
        
        # If channel beta or rc is mentioned in the fix, then we should take care
        # See unit tests for more details
        if(!empty_or_null(channel_suffix_ver)){
          ver = ver - channel_suffix_ver;
          if(!empty_or_null(channel_suffix_fix)){
              if(channel_suffix_fix == channel_suffix_ver){
                fix = fix - channel_suffix_fix;
              }
          }
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace mitsubishi
    {
      # If both versions have format "^(\d+\.\d+)[A-Za-z]$" (e.g.7.14q) replace last alpha char
      # with a minor version corresponding to the char. If only one version has a terminating
      # alpha char - just remove it as optional.

      function ver_compare_custom(ver, fix)
      {
        local_var new_ver, new_fix;
        if ( ver =~ "^(\d+\.\d+)[A-Za-z]$" && fix =~ "^(\d+\.\d+)[A-Za-z]$" )
        {
          new_ver = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:ver, replace:"\1.");
          new_ver = new_ver + (ord(ver[strlen(ver)-1]) - ord('A'));
          ver = new_ver;          

          new_fix = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:fix, replace:"\1.");
          new_fix = new_fix + (ord(fix[strlen(fix)-1]) - ord('A'));
          fix = new_fix;          
        }
        else if ( ver =~ "^(\d+\.\d+)[A-Za-z]$" )
        {
          ver = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:ver, replace:"\1");          
        }
        else if ( fix =~ "^(\d+\.\d+)[A-Za-z]$" )
        {
          fix = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:fix, replace:"\1");          
        }
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["mitsubishi"]["subfamilies"][tolower(cpe_family)];
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Using Mitsubishi model_regex: ' + model_regex);
        # Model matching if subfamily regex exists, default to family matching
        if (!empty_or_null(model_regex))
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        else
          return OT_NEXTMATCH;
      }
    }

    namespace mobotix
    {
      namespace mobotixcameras
      {
        function ver_compare_custom(ver, fix)
        {
          var mobotix_version_regex = ".*v((?:\d+\.?)+)$";
          
          if ( ver =~ mobotix_version_regex )
          {
            ver = pregmatch(pattern:mobotix_version_regex, string:ver);
            ver = ver[1];
          }

          if ( fix =~ mobotix_version_regex )
          {
            fix = pregmatch(pattern:mobotix_version_regex, string:fix);
            fix = fix[1];
          }
  
          return ver_compare(ver:ver, fix:fix, strict:false);
        }

        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["mobotixcameras"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace moxa
    {
      ##
      # Compare asset modelName to model from CPE OR models list
      # 
      # @param [asset:string] asset information
      # @param [cpes:array] list of vulnerable CPEs from plugin
      # @param [vuln_models:array] list of vulnerable models from plugin, if included
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function model_compare(asset, cpe, cpe_family)
      {
        local_var model_regex;        

        if ('series' >< cpe)
        {
          return tenable_ot::cve::moxa::check_model_indicators(asset: asset, cpe:cpe, cpe_family:tolower(cpe_family));
        }
        else
        {
          model_regex = tenable_ot::regexes::models["moxa"][tolower(cpe_family)].genericModelRegex;
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('DEBUG: ',obj_rep(asset)));
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      function check_model_indicators(asset, cpe, cpe_family)
      {
        # Check cpe with generic series

        # Retrieve required info for matching
        var model_name = tolower(asset.modelName);
          
        var cpe_match = pregmatch(pattern:tenable_ot::regexes::models['moxa'][cpe_family].genericModelRegex, string:tolower(cpe));
        if(!empty_or_null(cpe_match))
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe_match: ',obj_rep(cpe_match)));
        else
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'cpe_match is empty or null');
        
        if(!empty_or_null(model_name))
          model_name = str_replace(string:model_name, find:' ', replace:'');

        var model_match = pregmatch(pattern:tenable_ot::regexes::models['moxa'][cpe_family].genericModelRegex, string:model_name);
        if(!empty_or_null(model_match))
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model_match: ',obj_rep(model_match)));
        else
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'model_match is empty or null');
        
        if ( empty_or_null(cpe_match) || empty_or_null(cpe_match[0]) ||
          empty_or_null(model_match) || empty_or_null(model_match[0]) )
          return OT_FAILURE;

        local_var series, model_prefix;

        # Handle NPort
        if ('nport' >< cpe)
        {
          # convert nport generic series to regex
          # 5600 -> 56\d\d
          series = str_replace(string:cpe_match[0], find:'-', replace:'');
          series = str_replace(string:series, find:'0', replace:'\\d');
          model_prefix = str_replace(string: model_match[0], find:'-', replace:'');
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('series: ',series, ' model_prefix: ', model_prefix));
          if (preg(string:model_prefix, pattern: series))
            return OT_SUCCESS;
          else
            return OT_FAILURE;
        }
        # Handle iologik
        else if ('iologik' >< cpe)
        {
          # match iologik generic series 
          # iologik ioLogik E1200 series should match e1210-t
          series = str_replace(string:cpe_match[0], find:'-', replace:'');
          series = str_replace(string:series, find:'0', replace:'\\d');
          model_prefix = str_replace(string: model_match[0], find:'-', replace:'');
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('series: ',series, ' model_prefix: ', model_prefix));
          if (preg(string:model_prefix, pattern: series))
            return OT_SUCCESS;
          else
            return OT_FAILURE;
        }
        # Fail otherwise as, for now, no other subfamilies uses generic series matching
        else
        {
          return OT_FAILURE;
        }
      }
    }

    namespace neuberger
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["neuberger"].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace nexans
    {
      function ver_compare_custom(ver,fix)
      {
          # For versions that have format "^\d+\.\d+[a-z]$" (e.g: 1.0c) replace 
          # char c with a numeric equivalent (e.g. ord('c')-ord('A') = 1.0.34).
          
          ver = tolower(ver);
          fix = tolower(fix);

          local_var new_ver, new_fix;
          if ( ver =~ "^(\d+\.\d+)[A-Za-z]$" )
          {
            new_ver = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:ver, replace:"\1.");
            new_ver = new_ver + (ord(ver[strlen(ver)-1]) - ord('A'));
            ver = new_ver;
          }
  
          if (fix =~ "^(\d+\.\d+)[A-Za-z]$")
          {
            new_fix = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:fix, replace:"\1.");
            new_fix = new_fix + (ord(fix[strlen(fix)-1]) - ord('A'));
            fix = new_fix;
          }
  
          return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace omron
    {
      function model_compare(asset, cpe, cpe_family)
      {
        local_var model_regex;
        if (tolower(cpe_family) =~ "cj2[mh]")
        {
          model_regex = tenable_ot::regexes::models["omron"]["cj2"].genericModelRegex;
        } else if (tolower(cpe_family) =~ "nj\d+") 
        {
          model_regex = tenable_ot::regexes::models["omron"]["nj"].genericModelRegex;
        } else if (tolower(cpe_family) =~ "nx\d") 
        {
          model_regex = tenable_ot::regexes::models["omron"]["nx"].genericModelRegex;
        } else {
          model_regex = tenable_ot::regexes::models["omron"][tolower(cpe_family)].genericModelRegex;
        }
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace panasonic
    {
      namespace panasonicipcameras
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["panasonicipcameras"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace phoenixcontact
    {
      # RFC versions may include 'V 4.25U.18'
      function ver_compare_custom(ver, fix)
      {
        ver = ver - "V ";
        fix = fix - "V ";
        ver = ver - "U";
        fix = fix - "U";
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      # Examples of models; RFC 470 PN 3TX, ILC 131 ETH, RFC 430 ETH-IB
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(asset.vendor)].genericModelRegex;
        # ILC2000 devices won't have ILC in the model name, fix it before model matching
        if (cpe_family == "ILC2000")
        {
          asset.modelName = "ILC " + asset.modelName;
        }
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }

    }

    namespace ricoh
    {
      namespace mfp
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["mfp"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace rockwell
    {
      ##
      # Compare asset modelName to model from CPE OR models list
      # 
      # @param [asset:string] asset information
      # @param [cpes:array] list of vulnerable CPEs from plugin
      # @param [vuln_models:array] list of vulnerable models from plugin, if included
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function model_compare(asset, cpe, cpe_family)
      {
        if (cpe_family =~ "armorstart")
        {
          return tenable_ot::cve::rockwell::armorstart::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
        } else if (cpe_family =~ "stratix")
        {
          return tenable_ot::cve::rockwell::stratix::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
        } else {
          return tenable_ot::cve::rockwell::check_model_indicators(asset:asset, cpe:cpe, cpe_family:cpe_family);
        }
      }

      ##
      # Run a series of checks to see if the modelName is a vulnerable model
      #
      # @param [asset:string] asset information
      # @param [cpe:array] CPE info from CPE array
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_model_indicators(asset, cpe, cpe_family)
      {
        var model_name = tolower(asset.modelName);
        var vendor_name = tolower(asset.vendor);
        var asset_type = tolower(asset.type);

        local_var ret, asset_model_info, cpe_model_info;
        # Check if asset is a communication module
        if (asset_type == "cp")
        {
          asset_model_info = tenable_ot::cve::_extract_model_indicators(model_name:model_name, vendor:vendor_name, type:"cp");
          cpe_model_info = tenable_ot::cve::_extract_model_indicators(model_name:cpe, vendor:vendor_name, type:"cp");
          ret = check_cp_asset_with_cpe(asset_model_info:asset_model_info, cpe_model_info:cpe_model_info);
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_asset_model_name_in_cpe result: ' + ret);
          return ret;
        }
        # Else, default to controller type
        else
        {
          asset_model_info = tenable_ot::cve::_extract_model_indicators(model_name:model_name, vendor:vendor_name, type:"controller");
          cpe_model_info = tenable_ot::cve::_extract_model_indicators(model_name:cpe, vendor:vendor_name, type:"controller");

          # successOnAssetModelNameInCpe
          ret = check_asset_model_name_in_cpe(asset_model_info:asset_model_info, cpe:cpe);
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_asset_model_name_in_cpe result: ' + ret);
          if ( ret != OT_NEXTMATCH ) return ret;

          # matchByCpeModelName
          # start with generics
          ret = check_cpe_model_name_in_asset(cpe_model_info:cpe_model_info, model:model_name);
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_cpe_model_name_in_asset result: ' + ret);
          if ( ret != OT_NEXTMATCH ) return ret;

          # failOnMismatchingAndVendorFamilies
          # check CPE family
          ret = check_cpe_family(cpe_family:cpe_family, asset_family:asset.rawFamily);
          if ( ret != OT_NEXTMATCH ) return ret;

          # matchByCpeModelIndicators
          # check specifics
          ret = check_cpe_model_in_asset(cpe_model_info:cpe_model_info, model:model_name);
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_cpe_model_in_asset result: ' + ret);
          if ( ret != OT_NEXTMATCH ) return ret;

          # matchBySubFamilyNumber
          ret = check_subfamily_number(asset_model_info:asset_model_info, asset_family:asset.family, asset_vendor:asset.vendor, cpe_model_info:cpe_model_info, cpe_family:cpe_family, type:"controller");
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'check_subfamily_number result: ' + ret);
          if ( ret != OT_NEXTMATCH ) return ret;

          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'No matched conditions');
        }


        return OT_SUCCESS;
      }

      ##
      # Check if Communication module asset's model info is present is vulnerable to the cpe
      #
      # @param [asset_model_info:array] output of _extract_model_indicators()
      # @param [cpe_model_info:array] output of _extract_model_indicators()
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_cp_asset_with_cpe(asset_model_info, cpe_model_info)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('part: ', asset_model_info.generic_part_number, '; model: ', asset_model_info.generic_model_number));

        if ( empty_or_null(asset_model_info.generic_model_number) || empty_or_null(asset_model_info.generic_part_number) )
            return OT_FAILURE;

        if ( empty_or_null(cpe_model_info.generic_model_number) || empty_or_null(cpe_model_info.generic_part_number) )
            return OT_FAILURE;

        # Check if model and generic part number match
        if ( (asset_model_info.generic_model_number == cpe_model_info.generic_model_number) && (asset_model_info.generic_part_number == cpe_model_info.generic_part_number))
          #if cpe model does not include series / part number, return true
          if (empty_or_null(cpe_model_info.part_number))
            return OT_SUCCESS;
          # if both asset and cpe models include series / part number, and they match return true
          else if ( !empty_or_null(asset_model_info.part_number) && (cpe_model_info.part_number == asset_model_info.part_number ))
            return OT_SUCCESS;

        return OT_FAILURE;
      }

      ##
      # Check if asset's model info is present in the vulnerable CPE
      # 
      # @param [asset_model_info:array] output of _extract_model_indicators()
      # @param [cpe:string] vulnerable CPE string to test against
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_asset_model_name_in_cpe(asset_model_info, cpe, cpe_model_info)
      {
        # successOnAssetModelNameInCpe
        # find index of partnumber in CPE
        # find index of model number in CPE
        # if check that partNumberIndex != 1 && modelNumberIndex != 1 && partNumberIndex < modelNumberIndex:
        #   return true

        if ( empty_or_null(asset_model_info.generic_model_number) || empty_or_null(asset_model_info.generic_part_number) )
          return OT_NEXTMATCH;

        var part_idx = stridx(cpe, asset_model_info.generic_part_number);
        var model_idx = stridx(cpe, asset_model_info.generic_model_number);

        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('part: ', asset_model_info.generic_part_number, '; model: ', asset_model_info.generic_model_number));

        if ( part_idx >= 0 && model_idx >= 0 && part_idx < model_idx )
          return OT_SUCCESS;

        return OT_NEXTMATCH;
      }

      ##
      # Check if extracted vulnerable CPE model info is present in the asset's modelName
      #
      # @param [cpe_model_info:array] output of _extract_model_indicators()
      # @param [model:string] vulnerable model string to test against
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_cpe_model_name_in_asset(cpe_model_info, model)
      {
        # matchByCpeModelName

        if ( empty_or_null(cpe_model_info.generic_model_number) || empty_or_null(cpe_model_info.generic_part_number) )
          return OT_NEXTMATCH;

        var part_idx = stridx(model, cpe_model_info.generic_part_number);
        var model_idx = stridx(model, cpe_model_info.generic_model_number);

        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe_model_info.generic_part_number: ', cpe_model_info.generic_part_number, '; cpe_model_info.generic_model_number: ', cpe_model_info.generic_model_number, ', model: ', model));

        if ( part_idx >= 0 && model_idx >= 0 && part_idx < model_idx )
          return OT_SUCCESS;

        return OT_FAILURE;
      }

      ##
      # Check some constraints on matched CPE family
      #
      # @param [cpe_family:string] matched cpe family
      # @param [asset_family:string] family ingested from asset info
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_cpe_family(cpe_family, asset_family)
      {
        # failOnMismatchingAndVendorFamilies
        if ( empty_or_null(cpe_family) || !(cpe_family >< str_replace(string:asset_family, find:' ', replace:'')) )
          return OT_FAILURE;

        return OT_NEXTMATCH;
      }

      ##
      # Check if extracted vulnerable CPE model info is present in the asset's modelName
      #
      # @param [cpe_model_info:array] output of _extract_model_indicators()
      # @param [model:string] vulnerable model string to test against
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_cpe_model_in_asset(cpe_model_info, model)
      {
        # matchByCpeModelIndicators
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe part number: ', cpe_model_info.part_number, '; cpe model indicator: ', cpe_model_info.model_indicator, '; model name: ', model));

        if ( empty_or_null(cpe_model_info.model_indicator) && empty_or_null(cpe_model_info.part_number) )
          return OT_NEXTMATCH;

        var check_model = cpe_model_info.part_number + '-' + cpe_model_info.model_indicator;
        if ( check_model >< model )
          return OT_SUCCESS;

        return OT_FAILURE;
      }

      ##
      # Check if asset's model subfamily is the same as the subfamily in the vulnerable CPE string
      #
      # @param [asset_model_info:array] output of _extract_model_indicators()
      # @param [cpe_model_info:array] output of _extract_model_indicators()
      #
      # @return true if model matches a vulnerable model
      #         false if model does not match a vulnerable model
      ##
      function check_subfamily_number(asset_model_info, asset_family, asset_vendor, cpe_model_info, cpe_family, type)
      {
        # matchBySubFamilyNumber
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model subfamily: ', asset_model_info.subfamily, '; cpe subfamily: ', cpe_model_info.subfamily));

        if ( empty_or_null(cpe_model_info.subfamily) )
          cpe_model_info.subfamily = subfamily_lookup(family:cpe_family, vendor:asset_vendor, type:type);

        if ( empty_or_null(asset_model_info.subfamily) || empty_or_null(cpe_model_info.subfamily) )
          return OT_NEXTMATCH;

        #trim cpe subfamily right 0
        # is trimmed cpe subfamily prefix of asset subfamily
        var zero_idx = stridx(cpe_model_info.subfamily, '0') - 1;
        # we should compare at least the first two digits of this 4 digit number...
        if ( zero_idx >= 1 && substr(asset_model_info.subfamily, 0, zero_idx) == substr(cpe_model_info.subfamily, 0, zero_idx) )
          return OT_SUCCESS;

        return OT_FAILURE;
      }

      function subfamily_lookup(family, vendor, type)
      {
        var trim_family = str_replace(string:family, find:' ', replace:'');
        var vendor_name = tolower(vendor);

        foreach var found (keys(tenable_ot::regexes::models[vendor_name][type].subfamilies))
        {
          if (trim_family == found)
          {
            return tenable_ot::regexes::models[vendor_name][type].subfamilies[found];
          }
        }

        return "";
      }

      # For versions that start with 'v' (e.g. v31.011) remove 'v'
      function ver_compare_custom(ver, fix)
      {
        if ( tolower(ver[0]) == 'v' )
        {
          ver = substr(ver, 1);
        }
        if ( tolower(fix[0]) == 'v' )
        {
          fix = substr(fix, 1);
        }        
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      namespace armorstart
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["armorstart"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace stratix
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["stratix"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace schneider
    {
      function format_release_number(ver){

        var schneider_version_regex = "[a-zA-Z]*(\d+(?:\.\d+)*)(?:[\s\.]*(?:ir|IR)(\d+)([a-zA-Z])?)?";
        var captured_groups = pregmatch(pattern:schneider_version_regex, string:ver);

        if ( !empty_or_null(captured_groups) && !empty_or_null(captured_groups[1]) )
        {
          ver = captured_groups[1];

          if ( !empty_or_null(captured_groups[2]) )
          {
            ver = strcat(ver, '.', captured_groups[2]);

            # e.g. ir15b
            if ( !empty_or_null(captured_groups[3]) )
            {
              ver = ver + (ord(captured_groups[3]) - ord('A'));
            }
          }
        }

        return ver;
      }

      # For versions that start with non digit chars and/or suffixed with IR value
      # e.g. d6.0, sv1.6, "v02.50 ir28", v01.70.ir4   
      # remove the non digit chars at the beginning
      function ver_compare_custom(ver, fix)
      {
        ver = tenable_ot::cve::schneider::format_release_number(ver:ver);
        fix = tenable_ot::cve::schneider::format_release_number(ver:fix);

        # Check if version is suffixed by the IR (Internal Revision) value 
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      namespace modicon
      {
        function model_compare(asset, cpe, cpe_family)
        {
          cpe_family = tolower(cpe_family);
          var cpe_match = pregmatch(pattern:tenable_ot::regexes::models[cpe_family].genericModelRegex, string:tolower(cpe));
          
          if(!empty_or_null(cpe_match))
          {
            cpe_match[0] = str_replace( find: '-' , replace: '', string:cpe_match[0] );
            cpe_match[0] = str_replace( find: '_' , replace: '', string:cpe_match[0] );
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe_match: ',obj_rep(cpe_match)));
          } else {
            # When the part number is not found in the CPE, NVD refers to the modicon series as modicon_m\d{3}, modicon_mc80,  bmx_p34x (M340)
            return OT_NEXTMATCH;
          }

          if(!empty_or_null(asset.modelName))
          {
            asset.modelName = str_replace(string:asset.modelName, find:' ', replace:'');
            asset.modelName = str_replace(string:asset.modelName, find:'-', replace:'');
          }
          else
          {
            # When modelName is not set, abort model matching 
            return OT_FAILURE;
          }
          
          var model_match = pregmatch(pattern:tenable_ot::regexes::models[cpe_family].genericModelRegex, string:tolower(asset.modelName));
          if(!empty_or_null(model_match))
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model_match: ',obj_rep(model_match)));
          else{
            # At this point, we have a part number in the CPE and none asset.modelName
            return OT_FAILURE;
          }
  
          if ( cpe_match[0] >< model_match[0] )
          {
            return OT_SUCCESS;
          }

          if ( !empty_or_null(model_match[1]) && !empty_or_null(model_match[2]) &&
              ( model_match[1] >< cpe_match[0] && model_match[2] >< cpe_match[0] ) )
            return OT_SUCCESS;
          if ( !empty_or_null(cpe_match[1]) && !empty_or_null(cpe_match[2]) &&
              ( cpe_match[1] >< model_match[0] && cpe_match[2] >< model_match[0] ) )
            return OT_SUCCESS;
  
          return OT_FAILURE;
        }
      }

      namespace micom
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace sel
    {
      # Converting SEL devices versions, e.g. r150-v2 => 1502
      # We also should be able to compare r150 with r150-v0, r150-v1, ...
      function ver_compare_custom(ver, fix)
      {
        var sel_regex = "r\d+(-v\d+)?";

        ver = tolower(ver);
        
        if ( ver =~ sel_regex )
        {
          var sel_version_prefix = pregmatch(pattern:sel_regex, string:ver);

          if ( !empty_or_null(sel_version_prefix) && !empty_or_null(sel_version_prefix[0]) )
          {
            if ( empty_or_null(sel_version_prefix[1]) )
            {
              sel_version_prefix = sel_version_prefix[0] + '-v0';
            } else {
              sel_version_prefix = sel_version_prefix[0];
            }
          }

          ver = ereg_replace(pattern:"\D", string:sel_version_prefix, replace:"");
        }

        if ( fix =~ sel_regex )
        {
          var sel_fix_prefix = pregmatch(pattern:sel_regex, string:fix);

          if ( !empty_or_null(sel_fix_prefix) && !empty_or_null(sel_fix_prefix[0]) )
          {
            if ( empty_or_null(sel_fix_prefix[1]) )
            {
              sel_fix_prefix = sel_fix_prefix[0] + '-v0';
            } else {
              sel_fix_prefix = sel_fix_prefix[0];
            }
          }

          fix = ereg_replace(pattern:"\D", string:sel_fix_prefix, replace:"");          
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace seh
    {
      namespace sehusbdeviceservers
      {
        function model_compare(asset, cpe, cpe_family)
        {
          if(!empty_or_null(asset.modelName)){
            asset.modelName = str_replace(string:asset.modelName, find:' ', replace:'_');
          }
          var model_regex = tenable_ot::regexes::models["sehusbdeviceservers"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }
    
    namespace siemens
    {
      
      # For versions that start with 'v' (e.g.v4.0.1.1) remove 'v'
      function ver_compare_custom(ver, fix)
      {
        var temp_ver = "";
        var temp_fix = "";

        if ( ver =~ "[^\d]" )
        {
          temp_ver = pregmatch(pattern:"(\w*v)?((\w\.?)+)", string:ver);
          if(!empty_or_null(temp_ver) && !empty_or_null(temp_ver[2]))
          {
            ver = temp_ver[2];
          }
        }
        if ( fix =~ "[^\d]" )
        {
          temp_fix = pregmatch(pattern:"(\w*v)?((\w\.?)+)", string:fix);
          if(!empty_or_null(temp_fix) && !empty_or_null(temp_fix[2]))
          {
            fix = temp_fix[2];
          }
        }

        # version like 0492 should give 04.92 (major part on 2 digits)
        if (ver =~ "^(\d+)$" && strlen(ver) > 2)
        {
          ver = substr(ver, 0, 1) + "." + substr(ver, 2, strlen(ver) - 1);
        }

        if (fix =~ "^(\d+)$" && strlen(fix) > 2)
        {
          fix = substr(fix, 0, 1) + "." + substr(fix, 2, strlen(fix) - 1);
        }

        # version sometimes are mentioned like V3.X.14
        if (fix =~ "^\d+\.x")
        {
          var pregregex = "^\d+(\.\d+)?\.?\d*$";

          if (fix =~ "x$")
          {
            pregregex = "^\d+([\.\d]*)$";
          }

          fix = str_replace(string:fix, find:'.x', replace:'');
          var minus = preg_replace(pattern:pregregex, replace:"\1", string:ver);

          if(!empty_or_null(minus))
          {
            ver = ver - minus;
          }
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      # Comparing asset / cpe order numbers
      function order_number_compare(data, regex, key, product, order_numbers)
      {
          # ######
          # hardwareOrderNumber matching (also refering as hardwareNumber, partNumber, ...)
          # ######

          # If data.hardwareOrderNumber is defined, then:
          # 1) check if it matches CPE product, if not then
          # 2) check if it matches CPE 'orderNumbers' attribute

          if(!empty_or_null(data) && !empty_or_null(data[key]))
          {

            data[key] = str_replace(string:data[key], find:' ', replace:'');

            # The condition here is that we have something to test against data[key]
            # If not, we should next
            if(product =~ regex || !empty_or_null(order_numbers)){

              # First test - do we find a hon in the cpe ?
              if(product =~ regex && tolower(data[key]) >< product)
              {
                return OT_SUCCESS;
              }

              # Second test - we fallback to the cpe attribute "orderNumbers", e.g. "orderNumbers" : ["6ES7511-1AK02-0AB0"]
              if(!empty_or_null(order_numbers) && typeof(order_numbers) == 'array')
              {
                foreach var order_number (order_numbers)
                {
                  # order_number (mentioned as a cpe attribute) can be generic, e.g. 6GK6108-4AM00
                  if(tolower(order_number) >< tolower(data[key]))
                  {
                    return OT_SUCCESS;
                  }
                }
              }

              return OT_FAILURE;
            }
          }

          return OT_NEXTMATCH;
      }
      
      namespace desigo
      {
        # versions may look like 01.21.142.5-22
        # versions may look like FW=01.21.50.128;WPC=1.7.10; SVS-300.4:SBC=13.22
        function ver_compare_custom(ver, fix)
        {
          if ("FW=" >< ver)
          {
            var temp_ver = pregmatch(pattern:"FW=V?((\d+\.)+\d+(?:-\d+)?)\s*[;\/]", string:ver);
            if (!empty_or_null(temp_ver) && !empty_or_null(temp_ver[1]))
              ver = temp_ver[1];
          }
          if ("FW=" >< fix)
          {
            var temp_fix = pregmatch(pattern:"FW=V?((\d+\.)+\d+(?:-\d+)?)\s*[;\/]", string:fix);
            if (!empty_or_null(temp_fix) && !empty_or_null(temp_fix[1]))
              fix = temp_fix[1];
          }

          return ver_compare(ver:str_replace(string:ver, find:"-", replace:"."), fix:str_replace(string:fix, find:"-", replace:"."), strict:false);
        }

        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex;
          if (cpe =~ "modular_equipment")
            model_regex = tenable_ot::regexes::models[tolower(cpe_family)].mecRegex;
          else if (cpe =~ "building")
            model_regex = tenable_ot::regexes::models[tolower(cpe_family)].mbcRegex;
          else
            model_regex= tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace scalance
      {
        function model_compare(asset, cpe, cpe_family, order_numbers)
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), '; cpe_family: ', cpe_family));

          # Handle cpe with generic series for scalance X models 
          # e.g. scalance_x-300_series_firmware shoud match all SCALANCEX300 models
          if ( 'series' >< cpe )
          {
            if( asset.family == cpe_family)
              return OT_SUCCESS;
            else
              return OT_FAILURE;
          }

          var generic_cpe_family = pregmatch(pattern:"scalance\w", string:tolower(cpe_family));
          if(!empty_or_null(generic_cpe_family) && !empty_or_null(generic_cpe_family[0]))
          {
            return tenable_ot::cve::siemens::scalance::check_model_indicators(asset:asset, cpe:cpe, cpe_family:tolower(generic_cpe_family[0]), order_numbers:order_numbers);
          }

          return OT_FAILURE;
        }

        function check_model_indicators(asset, cpe, cpe_family, order_numbers)
        {
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          var asset_profinetcm = asset.profinetCM;

          # We only matter if we have a string to decode (integration api or flatlines)
          if(!empty_or_null(asset_profinetcm) && typeof(asset_profinetcm) == 'data')
          {
            asset_profinetcm = deserialize(asset_profinetcm);
          }

          var hon_res = tenable_ot::cve::siemens::order_number_compare(data:asset_profinetcm, regex:tenable_ot::regexes::orderNumberRegex, key:'orderNumber', product:product, order_numbers:order_numbers);

          # Order numbers exist in the asset and cpe
          if(hon_res != OT_NEXTMATCH)
          {
            return hon_res;
          }

          var model_name = tolower(asset.modelName);
          
          var cpe_match = pregmatch(pattern:tenable_ot::regexes::models['scalance']['subfamilies'][cpe_family].regex, string:tolower(product));
          if(!empty_or_null(cpe_match))
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('cpe_match: ',obj_rep(cpe_match)));
          else
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'cpe_match is empty or null');
          
          if(!empty_or_null(model_name))
            model_name = str_replace(string:model_name, find:' ', replace:'');

          var model_match = pregmatch(pattern:tenable_ot::regexes::models['scalance']['subfamilies'][cpe_family].regex, string:model_name);
          if(!empty_or_null(model_match))
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('model_match: ',obj_rep(model_match)));
          else
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'model_match is empty or null');
          
          if ( empty_or_null(cpe_match) || empty_or_null(cpe_match[0]) ||
            empty_or_null(model_match) || empty_or_null(model_match[0]) )
            return OT_FAILURE;
            
          # Check cpe with generic series for scalance W/S/M models
          # e.g. scalance_w-700_series_firmware should match on SCALANCE W734-1 RJ45
          if ( 'series' >< cpe && !empty_or_null(cpe_match[1]) && !empty_or_null(model_match[1]))
          {
            # convert cpe generic series to regex
            # w-700 -> w7\d\d
            var series = str_replace(string:cpe_match[1], find:'-', replace:'');
            series = str_replace(string:series, find:'0', replace:'\\d');
            var model_prefix = str_replace(string: model_match[1], find:'-', replace:'');
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('series: ',series, ' model_prefix: ', model_prefix));
            if (preg(string:model_prefix, pattern: series))
              return OT_SUCCESS;
            else
              return OT_FAILURE;
          }
          
          # Model matching
          var i = 0;
          if (len(cpe_match) > 1)
            i = 1;

          for (; i<len(cpe_match); i++)
          {
            # We are stripping the "_", "-"
            cpe_match[i] = preg_replace(pattern:"[_\-]", replace:'', string:cpe_match[i]);

            if(!empty_or_null(model_match[i]))
              model_match[i] = preg_replace(pattern:"[_\-]", replace:'', string:model_match[i]);

            if (cpe_match[i] != model_match[i])
            {
              return OT_FAILURE;
            }
          }

          return OT_SUCCESS;
        }
      }

      namespace simatics7
      {
        # matching CP or CPU version if present in NVD data
        function model_compare(asset, cpe, cpe_family, order_numbers)
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), '; cpe_family: ', cpe_family, '; order_numbers: ', obj_rep(order_numbers)));
          
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          # ######
          # hardwareOrderNumber matching comes first
          # ######
          var s7data = asset.s7;

          if(!empty_or_null(s7data) && typeof(s7data) == 'data')
          {
            s7data = deserialize(s7data);
          }

          var hon_res = tenable_ot::cve::siemens::order_number_compare(data:s7data, regex:tenable_ot::regexes::orderNumberRegex, key:'hardwareOrderNumber', product:product, order_numbers:order_numbers);

          if(hon_res != OT_NEXTMATCH)
          {
            return hon_res;
          }

          # ######
          # Then model matching
          # ######

          var model_regex = tenable_ot::regexes::models["simatics7"].genericModelRegex;

          var model = "";
          var module = "";

          # The model (CPU / CP model) should be retrieved from asset.modelName or s7.moduleName ?
          if(!empty_or_null(asset.modelName))
          {
            model = pregmatch(pattern:model_regex, string:asset.modelName);
          }

          if(!empty_or_null(s7data) && !empty_or_null(s7data['moduleName']))
          {
            module = pregmatch(pattern:model_regex, string:tolower(s7data['moduleName']));
          }

          # Fallback to moduleName if modelName is missing
          if(empty_or_null(model) && !empty_or_null(module))
          {
            asset['modelName'] = s7data['moduleName'];
          }
          
          var ret = tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
          if ( ret != OT_NEXTMATCH ) return ret;

          ### Specific case of series matching ###
          
          # We are trying to match cpe series/subfamily pattern against the asset model
          if(!empty_or_null(asset.modelName))
          {
            asset.modelName = tolower(asset.modelName);
            var subfamilyRegex = tenable_ot::regexes::models["simatics7"].subfamilyRegex;

            # Checking subfamilies like S7-400 H, S7-400 PN/DP, ...
            var _model = pregmatch(pattern:subfamilyRegex, string:asset.modelName);

            var productSerie = NULL;

            if(!empty_or_null(_model) && len(_model) > 1)
            {
              # should be the last capturing group (DP, PN/DP, ...)
              var modelSerie = _model[len(_model)-1];
              
              var _product = pregmatch(pattern:subfamilyRegex, string:product);

              # len(product) > 1 because we have a wilcard applied to a capturing group in subfamilyRegex
              if(!empty_or_null(_product) && len(_product) > 1)
              {
                productSerie = _product[len(_product)-1];
              }

              if(!empty_or_null(modelSerie))
              {
                if(!empty_or_null(productSerie))
                {
                  if(modelSerie == productSerie)
                  {
                    return OT_SUCCESS;
                  } else {
                    return OT_FAILURE;
                  }
                }
              }

              # Here we can have modelSerie null with productSerie null or not null
              if(!empty_or_null(productSerie))
              {
                # if product serie is defined and does not appear in the asset model
                return OT_FAILURE;
              }
            }
          }

          # Note that series seems to refer to CPU only
          if(tolower(asset.type) == "cp" && product !~ "[\-_]c[pm][\-_]")
          {
            return OT_FAILURE;
          }

          return OT_NEXTMATCH;
        }
      }

      namespace siprotec
      {
        # versions may look like v4.94
        # versions may look like V4.94 SP1 HF 1
        function ver_compare_custom(ver, fix)
        {
          if ( tolower(ver[0]) == 'v' )
          {
            ver = substr(ver, 1);
          }
          
          if ( tolower(fix[0]) == 'v' )
          {
            fix = substr(fix, 1);
          }

          # Transform 4.94 SP1 into 4.94.1
          # Transform 4.94 SP1 HF 1 into 4.94.1.1
          if ("SP" >< ver)
          {
            var temp_ver = pregmatch(pattern:"([\d+\.]+)[ _]?SP(\d+)[_ ]?(?:HF[ _]?)?(\d+)?", string:ver);
            if (!empty_or_null(temp_ver) && !empty_or_null(temp_ver[1]) && !empty_or_null(temp_ver[2]))
            {
              ver = temp_ver[1] + "." + temp_ver[2];
              if(!empty_or_null(temp_ver[3]))
                ver = ver + "." + temp_ver[3];
            }
          }

          if ("SP" >< fix)
          {
            var temp_fix = pregmatch(pattern:"([\d+\.]+)[ _]?SP(\d+)[_ ]?(?:HF[ _]?)?(\d+)?", string:fix);
            if (!empty_or_null(temp_fix) && !empty_or_null(temp_fix[1]) && !empty_or_null(temp_fix[2]))
            {
              fix = temp_fix[1] + "." + temp_fix[2];
              if(!empty_or_null(temp_fix[3]))
                fix = fix + "." + temp_fix[3];
            }
          }
          
          return ver_compare(ver:ver, fix:fix, strict:false);
        }

        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["siprotec"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace sicam
      {
        # matching CP or CPU version if present in NVD data
        function model_compare(asset, cpe, cpe_family, order_numbers)
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), '; cpe_family: ', cpe_family, '; order_numbers: ', obj_rep(order_numbers)));

          # Is model value set
          var model = "";
          
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          # ######
          # hardwareNumber matching
          # ######
          return tenable_ot::cve::siemens::order_number_compare(data:asset.sicam, regex:tenable_ot::regexes::orderNumberRegex, key:'hardwareNumber', product:product, order_numbers:order_numbers);
        }
      }

      namespace ruggedcom
      {
        function model_compare(asset, cpe, cpe_family, order_numbers)
        {
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          var asset_profinetcm = asset.profinetCM;

          # We only matter if we have a string to decode (integration api or flatlines)
          if(!empty_or_null(asset_profinetcm) && typeof(asset_profinetcm) == 'data')
          {
            asset_profinetcm = deserialize(asset_profinetcm);
          }

          # ######
          # hardwareNumber matching
          # ######

          var hon_res = tenable_ot::cve::siemens::order_number_compare(data:asset_profinetcm, regex:tenable_ot::regexes::orderNumberRegex, key:'orderNumber', product:product, order_numbers:order_numbers);

          if(hon_res != OT_NEXTMATCH)
          {
            return hon_res;
          }

          # ######
          # Then model matching
          # ######

          var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace ape
      {
        function ver_compare_custom(asset, fix)
        {
          if(!empty_or_null(asset.hardware))
          {
            var hardware = deserialize(asset.hardware);

            if(!empty_or_null(hardware.biosVersion))
            {
              return ver_compare(ver:hardware.biosVersion, fix:fix, strict:false); 
            }
          }
  
          return NULL;
        }
      }

      namespace logo
      {
        # matching CP or CPU version if present in NVD data
        function model_compare(asset, cpe, cpe_family, order_numbers)
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:strcat('asset: ', obj_rep(asset), '; cpe_family: ', cpe_family, '; order_numbers: ', obj_rep(order_numbers)));

          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          # ######
          # checking if we have a models "serie"
          # ######

          if(product =~ "logo.*8[\-_][bec]m")
          {
            return OT_NEXTMATCH;
          }

          # ######
          # model matching
          # ######

          var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace sitop
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace simaticnet
      {
        function model_compare(asset, cpe, cpe_family, order_numbers)
        {
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
          
          var product = tolower(urldecode(estr:dcpe[1].product));

          var asset_profinetcm = asset.profinetCM;

          # We only matter if we have a string to decode (integration api or flatlines)
          if(!empty_or_null(asset_profinetcm) && typeof(asset_profinetcm) == 'data')
          {
            asset_profinetcm = deserialize(asset_profinetcm);
          }

          # ######
          # hardwareNumber matching
          # ######

          var hon_res = tenable_ot::cve::siemens::order_number_compare(data:asset_profinetcm, regex:tenable_ot::regexes::orderNumberRegex, key:'orderNumber', product:product, order_numbers:order_numbers);

          if(hon_res != OT_NEXTMATCH)
          {
            return hon_res;
          }

          # ######
          # Then model matching
          # ######

          var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }

      namespace powerlogicegx
      {
        function model_compare(asset, cpe, cpe_family)
        {
          if(!empty_or_null(asset.modelName))
          {
            asset.modelName = str_replace(string:asset.modelName, find:'-', replace:'');
          }

          var model_regex = tenable_ot::regexes::models['powerlogicegx'].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace sony
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["sony"].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace sprecherautomation 
    {
      # If versions have format "^(\d+\.\d+)[A-Za-z]$" (e.g.8.64b) replace last alpha char
      # with a minor version corresponding to the char. 
      function ver_compare_custom(ver, fix)
      {
        local_var new_ver, new_fix;
        if ( ver =~ "^(\d+\.\d+)[A-Za-z]$" )
        {
          new_ver = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:ver, replace:"\1.");
          new_ver = new_ver + (ord(ver[strlen(ver)-1]) - ord('A'));
          ver = new_ver;
        }

        if (fix =~ "^(\d+\.\d+)[A-Za-z]$")
        {
          new_fix = ereg_replace(pattern:"^(\d+\.\d+)([A-Za-z])$", string:fix, replace:"\1.");
          new_fix = new_fix + (ord(fix[strlen(fix)-1]) - ord('A'));
          fix = new_fix;
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      namespace sprecone
      {
        # Trying to match CPE series patterns (e.g. sprecon-e-c against C96 model) 
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["sprecone"].genericModelRegex;
          var loose_comparison = 0;

          if(!empty_or_null(asset.modelName))
          {
            # If surrounded by "_", we can match the model in cpe
            var model_in_cpe = pregmatch(pattern:"_[a-zA-Z0-9\-]+_", string:cpe);

            if( !empty_or_null(model_in_cpe) && !empty_or_null(model_in_cpe[0]) )
            {
               # Model matching
              asset.modelName = asset.modelName + '_firmware';
            } else {
              # Series matching
              model_regex = tenable_ot::regexes::models["sprecone"].seriesRegex;
              asset.modelName = 'sprecon-e-' + asset.modelName;
              loose_comparison = 1;
            }
          }

          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex, loose_comparison:loose_comparison);
        }
      }
    }

    namespace teltonika
    {
      function ver_compare_custom(ver, fix)
      {
        local_var new_ver, new_fix;
        var teltonika_ver_regex = "[A-Z\d\_]+_([\d\.]{2,})";
        
        if (ver =~ teltonika_ver_regex)
        {
          new_ver = ereg_replace(pattern:teltonika_ver_regex, string:ver, replace:"\1");
          ver = new_ver;
        }

        if (fix =~ teltonika_ver_regex)
        {
          new_fix = ereg_replace(pattern:teltonika_ver_regex, string:fix, replace:"\1");
          fix = new_fix;
        }
  
        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace tridium
    {
      ##
      # Tridium Niagara is a firmware and not a hardware like others here, so we need to look for the 
      # assetBag sent from tenable.ot and use the NiagaraVersionKey as the version to compare. This function
      # will replace the 'firmwareVersion' on the asset object.
      # 
      # @param [asset:string] asset information
      #
      # @return OT_SUCCESS if assetBag contains NiagaraVersionKey
      #         OT_NEXTMATCH if model does not contain NiagaraVersionKey
      ##
      function app_compare(&asset)
      {
        local_var asset_bag;
        
        if (empty_or_null(asset.assetBag))
          return OT_NEXTMATCH;
        
        asset_bag = deserialize(asset.assetBag);
        
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'asset.assetBag: ' + obj_rep(asset.assetBag));
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'asset_bag ' + obj_rep(asset_bag));        
        
        if (empty_or_null(asset_bag) || empty_or_null(asset_bag.NiagaraVersionKey))
          return OT_NEXTMATCH;

        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'NiagaraVersionKey:' + asset_bag.NiagaraVersionKey);
        # version match happens here in t.ot code
        # but, we do that in _is_vulnerable, so return OT_SUCCESS and let that code work
        asset.firmwareVersion = asset_bag.NiagaraVersionKey;
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'asset.firmwareVersion set to NiagaraVersionKey. asset.firmwareVersion:' + obj_rep(asset.firmwareVersion));
        return OT_SUCCESS;
      }

      # For versions that contain the trailing revision part as letter + digit (e.g. 4.4u1, 4.4u2) remove 'u'
      function ver_compare_custom(ver, fix)
      {
        var tridium_version_regex = "u\d+$";
        var tridium_version_prefix = 'u';
        if ( ver =~ tridium_version_regex )
        {
          ver = ver - tridium_version_prefix;
        }
        if ( fix =~ tridium_version_regex )
        {
          fix = fix - tridium_version_prefix;
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace vertiv
    {
      namespace watchdog
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["watchdog"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace wago
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var generic_regex = tenable_ot::regexes::models["wago"].genericModelRegex;
        var series_regex = tenable_ot::regexes::models["wago"].seriesRegex;
        var model_regex = generic_regex;
        var loose_comparison = 0;

        # Some CPEs mention the whole edge or pfc family
        if ( 'edge_controller' >< cpe || cpe =~ 'pfc_?[12]00' )
        {
          # family check
          return OT_NEXTMATCH;
        }

        # Getting cpe product part
        var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);

        if (dcpe[0] != IF_OK)
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
          return OT_FAILURE;
        }
  
        var product = tolower(urldecode(estr:dcpe[1].product));

        # Checking if the cpe product does not match a pattern like 750-841/123-456
        # Lot of cpes only have products like 750-831, 750-852, ...
        if ('series' >< cpe || product !~ "\/\d+-\d+")
        {
          model_regex = series_regex;
          loose_comparison = 1;
        }

        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex, loose_comparison:loose_comparison);
      }

      function ver_compare_custom(ver, fix)
      {

        # Actually specific to Wago, versions may contain urlencoded characters (i.e. parenthesis)
        if ( ver =~ '%[0-9a-fA-F]{2}' )
        {
          ver = urldecode(estr:ver);
        }

        if ( fix =~ '%[0-9a-fA-F]{2}' )
        {
          fix = urldecode(estr:fix);
        }

        # For versions that start with 'fw' (e.g. fw07) remove 'fw'
        var wago_version_regex = "fw\d+";
        var wago_version_prefix = 'fw';
        if ( ver =~ wago_version_regex )
        {
          ver = ver - wago_version_prefix;
        }
        if ( fix =~ wago_version_regex )
        {
          fix = fix - wago_version_prefix;
        }

        # For Wago Controllers 750 versions that contain parentheses (e.g. "\(12\)") remove trailing (\d+)
        wago_version_regex = "(\d+\.?)+ ?\\?\(\d+\\?\)";
        if ( ver =~ wago_version_regex )
        {
          ver = pregmatch(pattern:"(\d+\.?)+", string:ver);
          ver = ver[0];
        }
        if ( fix =~ wago_version_regex )
        {
          fix = pregmatch(pattern:"(\d+\.?)+", string:fix);
          fix = fix[0];
        }

        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace welotec
    {
      function ver_compare_custom(ver, fix)
      {
        var prefix = "r";
        ver = tolower(ver);
        fix = tolower(fix);
        ver = ver - prefix;
        fix = fix - prefix;
  
        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      namespace welotecindustrialrouters
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["welotecindustrialrouters"].genericModelRegex;
          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
        }
      }
    }

    namespace westermo
    {
      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models[tolower(cpe_family)].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }

      namespace westermolynx
      {
        function model_compare(asset, cpe, cpe_family)
        {
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);
  
          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
    
          var product = tolower(urldecode(estr:dcpe[1].product));

          # WEOS (underlying device OS) applies to all Lynx devices
          if (product =~ 'weos'){
            return OT_NEXTMATCH;
          }
  
          return tenable_ot::cve::westermo::model_compare(asset:asset, cpe:cpe, cpe_family:cpe_family);
        }
      }
    }

    namespace yokogawa
    {
      # For versions that start with 'r' (e.g.r6.06.00) remove 'r'
      function ver_compare_custom(ver, fix)
      {
        if ( ver[0] == 'r' )
        {
          ver = substr(ver, 1);
        }
        if ( fix[0] == 'r' )
        {
          fix = substr(fix, 1);
        }        
        return ver_compare(ver:ver, fix:fix, strict:false);
      }
    }

    namespace zebra
    {
      function model_compare(asset, cpe, cpe_family)
      {
        if(!empty_or_null(asset.modelName))
        {
          var modelParts = split(asset.modelName, sep: ' ', keep: FALSE);

          if(len(modelParts) >= 2){
            asset.modelName = modelParts[0] + modelParts[1];
          }          
        }
        var model_regex = tenable_ot::regexes::models["zebra"].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }

    namespace cognex
    {
      namespace insight
      {
        # Fix can be "5.7.4_\(96\)"
        function ver_compare_custom(ver, fix)
        {
          var _fix = pregmatch(pattern:"^[\d\.]+", string:fix);

          if( !empty_or_null(_fix) && !empty_or_null(_fix[0]) )
          {
            fix = _fix[0];
          }

          # Most unlikely to have this pattern in the asset version
          # but relevant for non blocking flatline files
          var _ver = pregmatch(pattern:"^[\d\.]+", string:ver);

          if( !empty_or_null(_ver) && !empty_or_null(_ver[0]) )
          {
            ver = _ver[0];
          }

          return ver_compare(ver:ver, fix:fix, strict:false);
        }
      }
    }

    namespace synology
    {
      namespace diskstation
      {
        function format_version(version)
        {
          # ex of versions we need to handle; 7.1.1-42962-2, 7.1-42661, 7.2-64570 Update 1, DSM 7.1-42962
          var _version = preg_replace(pattern:"^(?i)DSM\s*", replace:'', string:version);

          if( !empty_or_null(_version) ) version = _version;

          _version = preg_replace(pattern:"(?i)\s*UPDATE\s*", replace:'-', string:version);

          if( !empty_or_null(_version) ) version = _version;

          _version = preg_replace(pattern:"[\-_]", replace:'.', string:version);

          if( !empty_or_null(_version) ) version = _version;

          return version;
        }

        function ver_compare_custom(ver, fix)
        {
          fix = tenable_ot::cve::synology::diskstation::format_version(version:fix);
          ver = tenable_ot::cve::synology::diskstation::format_version(version:ver);

          return ver_compare(ver:ver, fix:fix, strict:false);
        }

        function model_compare(asset, cpe, cpe_family)
        {
          var model_regex = tenable_ot::regexes::models["diskstation"].genericModelRegex;
          var dcpe = tenable_ot::cve::decode_cpe_helper(base_cpe:cpe);
  
          if (dcpe[0] != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'decode_cpe failed for cpe: ' + cpe);
            return OT_FAILURE;
          }
    
          var product = tolower(urldecode(estr:dcpe[1].product));

          # Checking if we are generic terms like diskstation or dsm mentioned
          # and that no model is provided -> family match
          if (product =~ '(disk_?station|dsm)' && product !~ model_regex){
            return OT_NEXTMATCH;
          }

          return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);

        }
      }
    }

    namespace qnap
    {
      namespace qutshero
      {
        function ver_compare_custom(ver, fix)
        {
          var prefix = "h";

          ver = tolower(ver);
          fix = tolower(fix);

          ver = ver - prefix;
          fix = fix - prefix;

          return ver_compare(ver:ver, fix:fix, strict:false);
        }
      }
    }

    namespace geovision
    {
      function ver_compare_custom(ver, fix)
      {
        # v3.00 2015-04-23 => 3.00.2015.04.23
        # 1.00_2017_12_15 => 1.00.2017.12.15
        var prefix = "v";

        ver = tolower(ver);
        fix = tolower(fix);

        ver = ver - prefix;
        fix = fix - prefix;

        ver = str_replace(string:ver, find:' ', replace:'.');
        fix = str_replace(string:fix, find:' ', replace:'.');

        ver = str_replace(string:ver, find:'-', replace:'.');
        fix = str_replace(string:fix, find:'-', replace:'.');

        ver = str_replace(string:ver, find:'_', replace:'.');
        fix = str_replace(string:fix, find:'_', replace:'.');

        return ver_compare(ver:ver, fix:fix, strict:false);
      }

      function model_compare(asset, cpe, cpe_family)
      {
        var model_regex = tenable_ot::regexes::models["geovision"].genericModelRegex;
        return tenable_ot::cve::model_matching(asset:asset, cpe:cpe, model_regex:model_regex);
      }
    }
  }
}
