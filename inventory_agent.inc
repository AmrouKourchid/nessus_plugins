#TRUSTED afaa6fc75c8fdcca9490f10a864f3312dfb902f9a00269f12e37c88402643362f25d5be718c69999d1c8c692bf93a6d9ff8dce6cfaa5d1633aba66efb623687b86b6617df93fedb90184131731277b8fde5e17ac32b05b8917b815713a088c6efefaee51e784f748de51a544d951046da67f8a034a11503343cdcfe360db8576afcf34430274e12527a918984cf013ded6ebf42021baaa2478ffb88d9a0b5746f9d71ebf87f4d896eb4a3f5d373bdbe260214792874946a09e1717fb9dee12f9c6bab9d72e54d286046b1b362a7daa8f758cb521ea320f1f8732471df515d055dc7ea4de064558bb1d0347e14f9c1313b9eafba69e4bff57c679c73f24eaa655fdaed4686364cb8d398cb5315f3ec9bbd9cd008ea5340f4526c3d3f5d0c5d7c00dd338921f6da34d6ee2498352796e424abace2927753c5b32e3df67d30c16de71c890df83cd73be5117256bb30f702ba7c9a3e8f67856ffb71316dd68e07597953b4aff1fcde9bff967d82715e5838e2d9f381c59e114523ca94b8c27dc5dd1197c1025ab7d4f2cb12e26d5b1a84f33392119426346c2f80fe36ae9700c4b6d10fbd313b59992004af2932f3be9f40ecc93ff1f554529930984bf371852bb12e7c94d8b172869b43d2a06e216c2ea1fb470502040547ebdd3e0b04dbbc745ecdeccbbdc63d73ecf037e8dc28f697b55a3b779155a520c2c79822ff350de5c00
#TRUST-RSA-SHA256 17b83c58318e297bd7b1cc53fe8f99e4d27a8af338e1279e5df746801cbb9fd70f4701ac804b3212f5d5b36f47a1dc7b1d3f1a13e5dbb7aefd57851c98199d18fecde6c7e8c5384a9b0e82716f77ad97fe4ed970553ac195d388992eaee39f2ccc5f1948e50b3c3c3ab315c279e7e85cf7e2e3fd16dc6fa64e9b5cf566f6aa21e5482ca50e397b3621240ad6e89f457b718ffdd93be69073927a568c5061d149d007a8e69565a68705e657244103d19f0e7601dc326fa13317fbc59b8250d33cb94fe0a17037dd60682e64c46f21ea3ea97ae1e4f472f1fa49130e5484100b822d514e2375909c89c196e03d20dcf1f96f5582c75980ddac0cb7e914f33435f061fec27c4f0556aeac037704e5dfc8da67fa677636fa6d6e530a7ba62183b894b1255c7cc09ffa0e15067be154e01ff4b92616e1a0a6feb882d804a647d02a7b211bff0fd9b0d944b78ef6e98b88530a067fa199e61fcdfdd6c909a24ac6670fc5d90183b5d0d782ee76993ddaa41f1165cd652c05f3fb82905dfd367e52c1bd12dffac7557730d0636b807179a839b4a721dc579e9372e1dbd6d3ed68ea11079906d27a935dc698e7e9f219ca21eecda5bf45dbbd6b9c434f9db8a85549e71e5d7f0c301504463e7c37b70181a2f6cc0aa05f7856b3902ca1f7ba16d7d64a882d8f72065497819cfda67ede996139d578fce20598cd03dccb1d1efbc73c94a3

###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# inventory_agent.inc
#
# Revision: 1.16
#
###

include("compat_shared.inc");
include('nessusd_product_info.inc');
include('spad_log_func.inc');
include('debug.inc');
include('install_func.inc');
include('rpm.inc');
include('debian_package.inc');
include("hostlevel_funcs.inc");
include("url_func.inc");

namespace inventory_agent
{
  ##
  # Determine which Frictionless Agent template is being used
  #
  # @return 'inventory' for Inventory Agent
  #         'hybrid' for Hybrid Agent
  #         NULL if not a supported Frictionless Agent
  ##
  function get_fa_agent_template_type()
  {
    var template_execution_type = get_preference('template_execution_type');
    if (empty_or_null(template_execution_type))
      template_execution_type = get_kb_item('global_settings/template_execution_type');

    if (empty_or_null(template_execution_type)) return NULL;

    # Determine FA Agent type
    # Inventory Agent
    if ('inventory' >< template_execution_type) return 'inventory';

    # Hybrid Agent
    else if ('hybrid' >< template_execution_type)
    {
      # Check for flag file
      var sep = '/';
      if (platform() == 'WINDOWS') sep = "\\";

      if (isnull(file_stat(nessus_get_dir(N_PLUGIN_DIR) + sep + 'hybrid-full-set.flag')))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'hybrid' template_execution_type set but flag file does not exist.");
        return NULL;  
      }
      return 'hybrid';
    }

    # Catch-all
    else
    {
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Unknown template_execution_type",
        msg_details: {
          "template_execution_type": {"lvl": 1, "value": template_execution_type}});
      return NULL;
    }
  }

  ##
  # Checks if we are running on inventory agent and if not exits with audit.
  #
  # @return NULL
  ##
  function inventory_agent_or_exit()
  {
    if (!nessusd_is_agent())
      exit(0, 'This plugin only runs on Nessus Agents');

    if (ver_compare(ver:nessus_version(), fix:"10.1.0") < 0)
      exit(0, 'This plugin only runs on Nessus Agent versions >= 10.1.0');

    if (isnull(get_fa_agent_template_type()))
      exit(0, 'This plugin requires a Frictionless plugin set to run');

    return NULL;
  }

  ##
  # Generate a product item data structure.
  #
  # @param [name:string] Product item name.
  # @param [properties:string] Array of key/values to store as product item properties.
  # @param [id] Product item id. Should be incremented for each product item of the same name.
  #
  # @return product item suitable for serialization into normalized inventory.
  ##
  function generate_product_item(name, properties, id)
  {
    # Create empty product item
    var item = make_array("type", "product");
    item["properties"] = make_array();

    # Use fa_app_name if set otherwise use the app_name provided.
    if (!isnull(properties["fa_app_name"]))
    {
      item["properties"]["name"] = properties["fa_app_name"];
    }
    else
    {
      item["properties"]["name"] = name;
    }
    item["id"] = id;

    var lower_property;
    # Set properties for product item
    foreach var property (keys(properties))
    {
      lower_property = tolower(property);
      # The "files" and "fa_app_name" properties are not used up stream so they do
      # not need to be added to the structure.
      if (lower_property == "files" || lower_property == "fa_app_name") continue;

      if (lower_property == "version_file" || lower_property == "version_registry" || lower_property == "collect_methods") {
          var deserialized = deserialize(properties[property]);
          if (!isnull(deserialized)) {
            item["properties"][lower_property] = deserialized;
          } else {
            dbg::detailed_log(
              lvl: 3,
              src: FUNCTION_NAME,
              msg: "Failed to deserialize detection details for inventory product",
              msg_details: { app_name: name, property_name: property, property_value: properties[property] }
            );
          }
      } else {
        item["properties"][lower_property] = properties[property];
      }
    }

    return item;
  }

  ##
  # Generate normalized inventory product items from register_install() data.
  #
  # @return [list] List of product items
  ##
  function get_detected_products()
  {
    var product_items = [];
    var installed_kbs = get_kb_list("installed_sw/*");
    if (!empty_or_null(installed_kbs))
    {
      foreach var app (sort(keys(installed_kbs)))
      {
        # Skip remote detections
        if (app =~ "^installed_sw\/\d+\/$")
          continue;
        if (app =~ "^installed_sw\/[^\/]+$")
        {
          var app_name = app - 'installed_sw/';
          var installs = get_installs(app_name:app_name);
          var id = 0;
          var item = NULL;
          foreach var install (installs[1])
          {
            if (install['Managed by OS'] || install['Managed']) continue;

            item = generate_product_item(name: app_name, properties: install, id: id++);
            dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "Found install of " + app_name);
            append_element(var:product_items, value:item);

            # Check for additional file(s) and generate a product item for each additional file if found.
            # Properties from product install are used with any properties from the additional file(s) adding/overwriting existing properties.
            if (!empty_or_null(install["files"]))
            {
              dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "Product install contains additional files. Insert product item for each additional file.");
              foreach var file (install["files"])
              {
                var updated_properties = install;
                foreach var replacement_property (keys(file))
                {
                  updated_properties[tolower(replacement_property)] = file[replacement_property];
                }
                item = generate_product_item(name: app_name, properties: updated_properties, id: id++);

                append_element(var:product_items, value:item);
              }
            }
          }
        }
      }
    }
    else
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"No products registered by register_install() found.");
    }
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:max_index(product_items) + " product installs found.");
    return product_items;
  }

  ##
  # Generate normalized inventory networks block from network data in the KB.
  #
  # @return [list] list of interface arrays respresenting normalized inventory networks block.
  ##
  function get_networks()
  {
    # Build the Network Interface data
    var interfaces = [];
    var iface_list = get_kb_list('Host/iface/id');
    if (empty_or_null(iface_list))
    {
      audit(AUDIT_KB_MISSING, 'Host/iface/id');
    }

    foreach var iface (iface_list)
    {
      # Skip the loopback interface
      if (iface == 'lo')
      {
        continue;
      }
      var interface = make_array();
      if (!empty_or_null(iface))
      {
        var mac = NULL;

        var kb_prefix = 'Host/iface/'+iface;
        mac = get_kb_item(kb_prefix+'/mac');
        if (empty_or_null(mac))
        {
          mac = '';
        }
        var ipv4_address = '';
        var ipv4_keys = get_kb_list(kb_prefix+'/ipv4');
        if (!empty_or_null(ipv4_keys))
        {
          foreach var ipv4 (ipv4_keys)
          {
            # Currently we only get the first address.
            ipv4_address = ipv4;
            break;
          }
        }

        var ipv6_address = '';
        var ipv6_keys = get_kb_list(kb_prefix+'/ipv6');
        if (!empty_or_null(ipv6_keys))
        {
          foreach var ipv6 (ipv6_keys)
          {
            # Currently we only get the first address.
            ipv6_address = ipv6;
          }
        }

        interface['name'] = string(iface);
        interface['mac_address'] = mac;
        interface['ipv4'] = ipv4_address;
        interface['ipv6'] = ipv6_address;
      }

      if (!empty_or_null(interface['ipv4']) || !empty_or_null(interface['ipv6']))
      {
        append_element(var:interfaces, value:interface);
      }
    }

    return interfaces;
  }

  ##
  # Save normalized inventory to appropriate locations based on type of execution.
  #
  # @param [inventory:array] Data structure representing the normalized inventory.
  # @param [is_cli:boolean] Defaults to FALSE. Set to TRUE if used when running via CLI.
  # @param [is_debug:boolean] Defaults to FALSE. Set to TRUE when debugging is enabled.
  #
  # @return NULL
  ##
  function save_normalized_inventory(inventory, is_cli, is_debug)
  {
    if (isnull(is_cli)) is_cli = FALSE;
    if (isnull(is_debug)) is_debug = FALSE;

    if (!empty_or_null(inventory))
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Saving normalized inventory.");
      report_tag_internal(tag:'frictionless_inventory', value:inventory);

      var inventory_json = '';
      if(is_debug || is_cli)
      {
        inventory_json = serialize(inventory);
      }
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Gathered inventory",
        msg_details: {
          "Inventory": {"lvl": 3, "value": inventory_json}});
      if (is_cli)
      {
        var file = 'fa-inventory.json';
        if (file_stat(file))
        {
          unlink(file);
        }
        fwrite(file:file, data:inventory_json);
      }
    }
  }




  ##
  # Populated the installed-sw structured data object with packages data.
  #
  # @param [distro:string] Distibution name
  # @param [installed_sw_packages:object reference] Reference to installed-sw stuctured data object.
  # @param [package_data:array reference] Reference to array of package information.
  #
  # @return [NULL]
  ##
  function populate_install_sw_packages(distro, &installed_sw_packages, &package_data)
  {
    var packages = [];
    var child_pkgs_mapping = {};
    foreach (var pkg in package_data['packages'])
    {
      var add_package = FALSE;
      var pkg_name = pkg.properties.name;
      # Use the version from the installed package. In some rare cases they can differ from the source package version.
      # This will cause those edge cases to list the correct version even if it differes from the source package.
      var version = pkg.properties.version;
      var qualifiers = {};

      if(package_data['type'] == 'rpm')
      {
        # Check if the RPM package version has an epoch.
        # If there is an epoch then the version will be in the format 'VERSION:EPOCH'.
        var possible_epoch = split(version, sep:':', keep:FALSE);
        # If the split results in two items then an epoch was found in the version.
        if(len(possible_epoch) == 2)
        {
          version = possible_epoch[1];
          qualifiers['epoch'] = possible_epoch[0];
        }
      }

      var child_pkg = NULL;
      # If this is a child package use the source package name.
      if(package_data['source_mapping'][pkg_name])
      {
        child_pkg = pkg_name;
        pkg_name = package_data['source_mapping'][child_pkg];
      }

      var purl_type = package_data["type"];
      if(purl_type == "dpkg") purl_type = "deb";
      var purl = generate_purl(type:purl_type, nspace:distro, name:pkg_name, version:version, qualifiers:qualifiers);

      # If we haven't seen this purl before create a child pkg mapping entry and mark it to be added to the package list.
      if(!child_pkgs_mapping[purl])
      {
        child_pkgs_mapping[purl] = [];
        add_package = TRUE;
      }

      # If this is a child package then add it to the list of child packages.
      if(!isnull(child_pkg))
      {
        append_element(var:child_pkgs_mapping[purl], value:child_pkg);
      }
      
      # First time seeing this package add it to the package list.
      if(add_package)
      {
        append_element(var:packages, value:{purl: purl});
      }
    }

    # Populate child packages for each added package.
    for(var i=0; i<len(packages); ++i)
    {
      if(child_pkgs_mapping[packages[i]['purl']] && len(child_pkgs_mapping[packages[i]['purl']]) > 0)
      {
        packages[i]['child_packages'] = child_pkgs_mapping[packages[i]['purl']];
      }
    }

    # Populate installed-sw packages structured data object.
    foreach pkg (packages)
    {
      installed_sw_packages.append('packages', pkg);
    }
  }
}