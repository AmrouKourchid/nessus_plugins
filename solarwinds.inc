###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# solarwinds.inc
#
# Revision: 1.3
###

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

##
#  Functions handling enumeration of SolarWinds products via Windows registry.
##
namespace solarwinds
{
  #pragma static(true)
  global_var CORE_CHECKED = FALSE;
  global_var PRODUCT_LIST = [];
  #pragma static(false)
  #pragma const(true)
  global_var ENUMERATED_KEY = "SMB/SolarWinds/Enumerated";
  global_var PRODUCTS_KEY = "SMB/SolarWinds/Products";
  global_var BASE_PREFIX = "SMB/SolarWinds/";
  global_var ORION_CORE_PATH = "SMB/SolarWinds/Orion_Path";
  global_var ORION_CORE_VERSION = "SMB/SolarWinds/Orion_Version";
  #pragma const(false)

  ##
  # Checks registry entries for main path and version of Orion Core Services. The results are cached in KB for use in downstream plugins after the first call.
  #
  # @param [hklm:list] A handle to HKLM hive returned by ``registry_hive_connect()``. Only required for the first call.
  #
  # @return NULL if Orion registry keys were not found, ``{path, version}`` array otherwise.
  #
  # @remark Path and version are stored in the KB under "SMB/SolarWinds/[Orion_Path|Orion_Version]".
  ##
  function get_orion_path_version(hklm)
  {
    var app_name = "SolarWinds (Orion Core|Platform)";

    var kb_path = get_kb_item(ORION_CORE_PATH);
    var kb_version = get_kb_item(ORION_CORE_VERSION);

    if(kb_path) return {"path":kb_path, "version":kb_version};
    if(CORE_CHECKED) return NULL; #No path in KB even though registry was already checked means no Orion Core installed

    CORE_CHECKED = TRUE;
    var key = hotfix_displayname_in_uninstall_key(pattern: app_name);
    if (key == 0 || empty_or_null(key))
      return NULL;

    var instloc = str_replace(string:key, find:'DisplayName', replace:'InstallLocation');
    var verloc = str_replace(string:key, find:'DisplayName', replace:'ProductDisplayName');

    var path = get_registry_value(handle:hklm, item:instloc);
    var version = get_registry_value(handle:hklm, item:verloc);
    dbg::detailed_log(
      lvl: 2,
      src: FUNCTION_NAME,
      msg: "Gathered path and version",
      msg_details: {
        "path": {"lvl": 2, "value": path},
        "version": {"lvl": 2, "value": version}});
    if (empty_or_null(path))
    {
      var alt_instloc = "SOFTWARE\SolarWinds\Orion\Core\InstallPath";
      path = get_registry_value(handle:hklm, item:alt_instloc);
      if (!empty_or_null(path) && empty_or_null(version))
      {
        var alt_verloc = "SOFTWARE\SolarWinds\Orion\Core\ProductDisplayName";
        var reg_version = get_registry_value(handle:hklm, item:alt_verloc);
        if (
          !empty_or_null(reg_version) && "SolarWinds Orion Core" >< reg_version ||
          !empty_or_null(reg_version) && "SolarWinds Platform" >< reg_version
        )
        {
          version = pregmatch(string:reg_version, pattern:"(?:Core Services|Platform)\s([\d\.]+)$");
          if (!empty_or_null(version) && !empty_or_null(version[1]))
            version = version[1];
        }
      }
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Path and version after re-check",
        msg_details: {
          "path": {"lvl": 2, "value": path},
          "version": {"lvl": 2, "value": version}});
    }
    if(empty_or_null(path)) return NULL;

    if(empty_or_null(version)) version = UNKNOWN_VER;
    
    replace_kb_item(name:ORION_CORE_PATH, value:path);
    replace_kb_item(name:ORION_CORE_VERSION, value:version);

    return {"path":path, "version":version};
  }

  ##
  # Returns data about all SolarWinds products found in the registry. This data is stored in KB upon first call for use in downstream plugins.
  #
  # @param [hklm:list] A handle to HKLM hive returned by registry_hive_connect(). Only required if KB has not been filled yet.
  #
  # @return [list] A list of arrays {display_name, name, version, hotfix} - one for each detected product.
  #
  # @remark A list of DisplayNames is stored in KB under "SMB/SolarWinds/Products" upon the first call.
  #
  # @remark Name, version and hotfix info are stored per product under "SMB/SolarWinds/[DisplayName]/(Name|Version|Hotfix)".
  ##
  function enumerate_solarwinds_products(hklm)
  {
    if(!get_kb_item(ENUMERATED_KEY)) _internal_enumerate_solarwinds_products(hklm:hklm);
    replace_kb_item(name:ENUMERATED_KEY, value:TRUE);

    if(!empty_or_null(PRODUCT_LIST)) return PRODUCT_LIST;

    var products = get_kb_list(PRODUCTS_KEY);
    foreach var product (products)
    {
      var name = get_kb_item(strcat(BASE_PREFIX, product, "/Name"));
      var version = get_kb_item(strcat(BASE_PREFIX, product, "/Version"));
      var hotfix = get_kb_item(strcat(BASE_PREFIX, product, "/Hotfix"));
      append_element(var:PRODUCT_LIST, value:{"display_name":product, "name":name, "version":version, "hotfix":hotfix});
    }
    return PRODUCT_LIST;
  }

  ##
  # Retrieves an entry for a single SolarWinds product. Requires KB to be filled by enumerate_solarwinds_products() beforehand.
  #
  # @param [display_name_search:string] A regex used to match DisplayName of the target product.
  # @param [version:string] Optional - an exact version of the product to match.
  #
  # @return NULL if there was no match, a {display_name, name, version, hotfix} array otherwise.
  ##
  function get_single_product(display_name_search, version)
  {
    if(empty_or_null(PRODUCT_LIST)) enumerate_solarwinds_products();

    foreach var product (PRODUCT_LIST)
    {
      if(product.display_name =~ display_name_search && (isnull(version) || version == product.version)) return product;
    }
    return NULL;
  }

  
  ##
  # Enumerates the registry to retrieve information about all SolarWinds products and stores them in the KB.
  #
  # @param [hklm:list] A handle to HKLM hive returned by registry_hive_connect().
  #
  # @return NULL - this function only stores results in the KB.
  #
  # @remark This is called automatically upon the first call to enumerate_solarwinds_products(), it should never be called explicitly.
  ##
  #pragma static(function:true)
  function _internal_enumerate_solarwinds_products(hklm)
  {
    dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Enumerating SolarWinds products");
    var users = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\");
    var product_array = {};
    foreach var user (users)
    {
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Enumerating entries for user",
        msg_details: {
          "user": {"lvl": 3, "value": user}});
      var products = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\" + user + "\Products");
      foreach var product (products)
      {
        var highest_hotfix = 0;
        var product_string = strcat("SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\", user, "\Products\", product);
        var properties_string = product_string + "\InstallProperties";
        var properties =  get_registry_subkeys(handle:hklm, key:properties_string);
        var display_name = get_registry_value(handle:hklm, item:properties_string + "\DisplayName");
        
        if (display_name !~ "^SolarWinds ") continue;
        dbg::detailed_log(
          lvl: 3,
          src: FUNCTION_NAME,
          msg: "DisplayName matched",
          msg_details: {
            "display_name": {"lvl": 3, "value": display_name}});
        set_kb_item(name:PRODUCTS_KEY, value:display_name);

        var matches = pregmatch(string:display_name, pattern:"^SolarWinds\s+(.*?)\s+v?([\d\.]+)");
        var version = UNKNOWN_VER;
        var name = "";
        if(!isnull(matches))
        {
          name = matches[1];
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Name matched",
            msg_details: {
              "Name": {"lvl": 3, "value": name}});
          replace_kb_item(name:strcat(BASE_PREFIX, display_name, "/Name"), value:name);
          version = matches[2];
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Version matched",
            msg_details: {
              "Version": {"lvl": 3, "value": version}});
          replace_kb_item(name:strcat(BASE_PREFIX, display_name, "/Version"), value:version);
        }
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "SolarWinds product found",
          msg_details: {
            "display_name": {"lvl": 2, "value": display_name}});
        var patch_path = product_string + "\Patches\";
        var patches = get_registry_subkeys(handle:hklm, key:patch_path);
        
        foreach var patch (patches)
        {
          var patch_name = get_registry_value(handle:hklm, item:strcat(patch_path, patch, "\DisplayName"));
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Checking patch against name and version",
            msg_details: {
              "patch_name": {"lvl": 3, "value": patch_name},
              "name": {"lvl": 3, "value": name},
              "version": {"lvl": 3, "value": version}});
          if(empty_or_null(patch_name) ||
              "Update for SolarWinds " + name >!< patch_name ||
              version >!< patch_name)
          continue;
          
          var hf_ver = pregmatch(string:patch_name, pattern:"\(Hotfix([\d]+)\)");
          if(empty_or_null(hf_ver) || empty_or_null(hf_ver[1])) continue;
          dbg::detailed_log(
            lvl: 2,
            src: FUNCTION_NAME,
            msg: "Hotfix found",
            msg_details: {
              "patch_name": {"lvl": 2, "value": patch_name}});
          if(empty_or_null(highest_hotfix) || hf_ver[1] > highest_hotfix)
            highest_hotfix = hf_ver[1];
        }
        replace_kb_item(name:strcat(BASE_PREFIX, display_name, "/Hotfix"), value:highest_hotfix);
      }
    }
  }
  #pragma static(function:false)
}
