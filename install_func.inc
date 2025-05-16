#TRUSTED b1dc0bac224a6d721a8b7a88a32a0e1eefe9a0c641c4cb93e188391cad411a84534248da0254fce92041cc9fbe2371b879805e65d130c9e0070ac2b3e817f4dab9727589c1dcb19e2f9b7e3fc0f901ad2bfb5714686c272a7e5d33034b4069d76a92e8c3eb032ec051c8f1308f3199c802881366cf225daa265b979160cc5005fc8f3532525b5c8548f6870894df525551b4039361fa17c216412edc15ab35dd54fea17448334013315230761ff4602ef486360c8950f45aa3331cd4b837a51ff8cca1d9dc353f0720f9dbc4ca0e3df53812979a9d6ab40f2bd481d3c58b0dbc4de035427a82a2754edd40d03cb2d95e0de9a49213df589fbba96582c0ad96c1d4195568977508cdc84944956e725e9a309e3e8c050da3ce45b75550d25ba2698b31dd12b9dba6c2e3c6ce19cb2a292bb81c11eb36ea84f86ecdb57b3d88d0e2b423f9c43b8ace049c149ad3cc4b06c0f1eb9ce42cf2ab6d790cf11449592d22250a204ef4bc5e86dbcabc2eb01664766caa036e18dd5d011996ab7014c80702d15f6665ccf2760fbacee2b49856121aba2367b3041d9100b9f0252f4d77fbc6d50e0f4bd295b9930fc222f871a3cde863707407c3ec469920fca91a1047eeb14bba250f1fa566b84360e858a41ab4e28b8aa0718bf6e71c5a8ea31e48a677386e5ab67c22de63fe573e7b54448eed3d195cef1018f27a4553f1dd0a38f4681a
#TRUST-RSA-SHA256 99a0417dea22aa12c6aefe2f99bbc449ebdcc41db484c559f89874d7ecb60e4d59c5c759d3ef1ae967277de93a24de8209481299735e5f40b4178835e7295dd4b8f54e22021559cc245def69d86ef76a571f71346488288914eaeda70f3094a91dd9398478fe443e472919da10c914effd52c72ca03e8bd7ff1a1bd07cb293b2bae224947da1f05feaff7369294854ccaa3801734a0634e4727b1acf15b9023f18bc0b9db7442ebd0db6be33022e1c3653e7d381f1d342e6c9f82644349a36baea9aef4aa8d88ad937f8099da1d702ef95028b1dcbb5228b84fe56e2a1450733c2b9785fef1b3f81ca003d600c8f36700b0b527e2f8a15c8a7d3626692e796d357ff58a55d9949d92f1ba603d33f341c7ffba296c53d0626af38b1dfc6fa325af7d5dac7f1b78030950e3a42234753058ffb6a25fb52b79f50a0709c487d48b41e84ba023698f71d3a34d60f687781207efd6f8c07355a87ab241d1b019818189fa2ae7990eac19a3fa92397279647dcbdaaf5b0702490c447ecc445530ae4bf390b5d10e8467dc72527fb58ae974e96ae03f35f4d35e6f739297aa5b8e269d44407ce181ed3aed121c608a21b5e6c16771cab8fa9420e590d3032b0e8cce61b869bc4f9bcfb48b58768f40a960af3c9925b5fc3212594abdb96cdbba276a0fa1012a60ce740efd46d2d2aae4791035c1a4fc96a72d1acf6f11fe7ee45771816
#------------------------------------------------------------------------------
##
# (C) Tenable, Inc.
##
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# install_func.inc
#
# Revision: 1.51
#
# @include audit.inc
# @include global_settings.inc
# @include misc_func.inc
# @include string.inc
# @include data_protection.inc
###
#

include("compat_shared.inc");
include("debug.inc");
include("string.inc");
include("cpe_func.inc");

### Constants ###
global_var CPE_KEY                        = '/cpe';
global_var DISPLAY_VERSION_KEY            = '/display_version';
global_var LIST_BULLET                    = '- ';
var PATH_REPORT_KEY                       = 'Path';
global_var PRIORITY_KEY                   = '/priority';
global_var ROOT_KB_KEY                    = 'installed_sw/';
global_var SEPARATOR                      = ';';     # Default separator for lists in KB.
global_var SERVICE_REPORT_KEY             = 'Service';
global_var SOURCE_KEY                     = 'Source';
global_var UNKNOWN_VER                    = "unknown";
global_var VERSION_KEY                    = '/version';
global_var VERSION_REPORT_KEY             = 'Version';
global_var VENDOR_KEY                     = '/vendor';
global_var PRODUCT_KEY                    = '/product';
global_var PRODUCT_VERSION_KEY            = '/product_version';
global_var UPDATE_KEY                     = '/update';
global_var LANG_KEY                       = '/language';
global_var SW_EDITION_KEY                 = '/sw_edition';
global_var TARGET_SW_KEY                  = '/target_sw';
global_var TARGET_HW_KEY                  = '/target_hw';
global_var FA_APP_NAME_KEY                = '/fa_app_name';
global_var VERSION_FILE_KEY               = '/version_file';
global_var VERSION_REGISTRY_KEY           = '/version_registry';
global_var REGISTRY_INSTALL_LOCATIONS_KEY = '/registry_install_locations';
global_var COLLECT_METHODS_KEY            = '/collect_methods';
global_var PLUGIN_ID_KEY                  = '/plugin_id';

### Debug Flag ###
global_var IF_VERBOSE_ERRORS = FALSE;

### get_single_install Flag ###
global_var IF_GSI_CALLED = make_array();

# Return Codes
# Negative values are conditions that should not occur at run-time
# Positive values can occur at run-time and should be handled
# gracefully.
global_var IF_LOWER_PRIORITY  = 2;   # Install is lower priority than existing.
global_var IF_NOT_FOUND       = 1;   # No installs found.
global_var IF_OK              = 0;   # Successful return.
global_var IF_ERROR           = -1;  # General/Unknown/Upstream error.
global_var IF_MISSING_ARG     = -2;  # Missing argument to function.
global_var IF_ARG_BAD_TYPE    = -3;  # Function argument is the wrong type.
global_var IF_UNEXPECTED_NULL = -4;  # Unexpected NULL value encountered.
global_var IF_PARSE_ERROR     = -5;  # Failed to parse input.
global_var IF_MISSING_FUNC    = -6;  # Missing function definition. Indicates missing include.
global_var IF_MUTEX_ARGS      = -7;  # Mutually exclusive arguments.

# Source Priorities
global_var IF_PRIORITY_HIGH   = 1;
global_var IF_PRIORITY_NORMAL = 0;
global_var IF_PRIORITY_LOW    = -1;
global_var IF_PRIORITY_LOWER  = -2;

# Error Templates
global_var IF_ERROR_TEMPLATE = make_list(1, "%s(): Unknown or upstream error occurred.", IF_ERROR);
global_var IF_MISSING_ARG_TEMPLATE = make_list(2, "%s(): missing required argument '%s'.", IF_MISSING_ARG);
global_var IF_ARG_BAD_TYPE_TEMPLATE = make_list(3, "%s(): '%s' arg must be type '%s'.", IF_ARG_BAD_TYPE);
global_var IF_UNEXPECTED_NULL_TEMPLATE = make_list(2, "%s(): '%s' variable is unexpectedly NULL.", IF_UNEXPECTED_NULL);
global_var IF_PARSE_ERROR_TEMPLATE = make_list(2, "%s(): Failure parsing variable '%s'.", IF_PARSE_ERROR);
global_var IF_MISSING_FUNC_TEMPLATE = make_list(3, "%s(): The function '%s' is not defined. Try including '%s'.", IF_MISSING_FUNC);
global_var IF_MUTEX_ARGS_TEMPLATE = make_list(2, "%s(): The arguments '%s' cannot be specified at the same time.", IF_MUTEX_ARGS);

### Globals ###
global_var InstallReport = make_array();   # Report for all installs found.
global_var InstallObjects = make_nested_array('installs', []); # JSON for attaching to results
global_var InstallCount = make_array();    # Number of installs found.

### Functions ###

##
# Increment the InstallCount[app_name]
#
# @param app_name Name of app to increment the install count.
#
# @return int New install count value.
##
function increment_install_count(app_name)
{
  if (isnull(InstallCount[app_name])) InstallCount[app_name] = 1;
  else InstallCount[app_name] += 1;

  return InstallCount[app_name];
}

# Get both and local and remote (combined) installs
#
# @param  string app_name
# @param  int     exit_if_not_found OPTIONAL defaults to FALSE, exits
#                 if no installs of app_name are found.
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. that each
#                          install is an array containing all the data
#                          stored in the KB.
#                          (NULL if ret[0] != IF_OK)
##
function get_combined_installs(app_name, exit_if_not_found)
{
  local_var installs, local_installs, loc_install, remote_installs,
            install, tmp, port, args, func_name, i, discovered_ports;

  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Default value
  if (isnull(exit_if_not_found)) exit_if_not_found = FALSE;

  # report on both local and remote installs
  installs = make_list();

  local_installs = get_installs(app_name: app_name);

  if(local_installs[0] == IF_OK) installs = make_list(installs, local_installs[1]);
  remote_installs = get_kb_list(ROOT_KB_KEY+ '*/' + app_name + '/*' + VERSION_KEY);
  discovered_ports = {};

  if(!isnull(remote_installs))
  {
    foreach install(keys(remote_installs))
    {
       tmp = split(install, sep:'/',  keep:FALSE);
       port = int(tmp[1]);
       if (discovered_ports[port])
         continue;
       discovered_ports[port] = TRUE;
       remote_installs = get_installs(app_name: app_name, port:port);
       if(remote_installs[0] == IF_OK)
       {
         # add port information to array
         for (i=0; i<max_index(remote_installs[1]); i++)
         {
           remote_installs[1][i]["port"] = port;

           ##
           #  CS-38608: remote detection may not be capable
           #   of determining if instance is 'managed'
           #  Attempt to associate local managed instances with
           #   remotely detected instances if version matches
           #
           #  If this is not done, 'unmanaged' remote instances
           #   will incorrectly report critical Vulns
           ##
           foreach loc_install(keys(local_installs[1]))
           {
             if (
                 !empty_or_null(local_installs[1][loc_install]['path']) &&
                 !empty_or_null(local_installs[1][loc_install]['version']) &&
                 !empty_or_null(local_installs[1][loc_install]['Managed'])
                )
             {
               if (local_installs[1][loc_install]['version'] == remote_installs[1][i]['version'])
               {
                 remote_installs[1][i]['Managed'] = local_installs[1][loc_install]['Managed'];
               }
             }
           }
         }
         installs = make_list(installs, remote_installs[1]);
      }
    }
  }

  if(max_index(installs) == 0)
  {
    if(exit_if_not_found) audit(AUDIT_NOT_INST, app_name);
    return make_list(IF_NOT_FOUND);
  }
  else
  {
    return make_list(IF_OK, make_nested_list(installs));
  }
}

##
# Registers an application install in the KB.
#
# Basic info
# @param  string  app_name                  REQUIRED
# @param  string  path                       OPTIONAL  will be base-64 encoded in KB key.
# @param  string  version                    OPTIONAL  defaults to UNKNOWN_VER
# @param  string  display_version            OPTIONAL  used in report if supplied                                                  
# @param  string  product_version            OPTIONAL  Version we would see in a CPE? (possibly redundant)  
# @param  int     port                       OPTIONAL  if supplied, install KB key is 'installed_sw/<port>/<app_name>/<path>/ 
# @param  string  service                    OPTIONAL  the name of the service (e.g. SNMP, SIP), 
# @param  bool    webapp                     OPTIONAL  if TRUE reports path as URL
# @param  string  rep_path                   OPTIONAL  if set appends string to webapp path created by build_url2() 
# @param  string  protocol                   OPTIONAL  IP protocol for port (default: 'tcp')                                       
# @param  int     priority                   OPTIONAL  defaults to IF_PRIORITY_NORMAL
# 
# Additional details (goes into cpe)
# @param  string  cpe                        OPTIONAL  Pre-made CPE describing the product cpe:/a:adobe:acrobat_reader
# @param  string  vendor                     OPTIONAL  Describes person or organization that manufactured or created the product.
# @param  string  product                    OPTIONAL  Describes the most common and recognizable title or name of the product.
# @param  string  update                     OPTIONAL  Describes the particular update, service pack, or point release of the product.
# @param  string  language                   OPTIONAL  [RFC5646] language tag describing the supported language of the product.
# @param  string  sw_edition                 OPTIONAL  Describes how the product is tailored to a particular market or
#                                                      class of end users (ie: Home, Professional, Enterprise, etc)
# @param  string  target_sw                  OPTIONAL  Describes the software environment of the app (ie: OS)
# @param  string  target_hw                  OPTIONAL  Describes the instruction set architecture of the app (ie: x86, x64)
#
# Supplemental info
# @param  array   extra                      OPTIONAL  Array keys must be strings, values may be strings, ints or lists. 
#                                                      Lists will be stored in KB as SEPARATOR separated strings.
# @param  array   extra_no_report            OPTIONAL  like extra but not included in report
#                                                      install KB is 'installed_sw/<port>/<app_name>/<protocol>/'
# @param  array   files                      OPTIONAL  Arry like Extra, but specifically describes related files to this install
# @param  string  fa_app_name                OPTIONAL  Application name used by TVDL checks if it differs from app_name.
# @param  string  version_file               OPTIONAL  JSON serialized version file data.
# @param  string  version_registry           OPTIONAL  JSON serialized version registry data.
# @param  array   registry_install_locations OPTIONAL  Specify install location(s) from the registry related to the product.
# @param  string  collect_methods            OPTIONAL  JSON serialized metadata defining data collection methods.
#
# @remark This function has a side effect of creating KB items to
#         store the install data passed to it. Additionally, it will
#         update a 'installed_sw/<app_name>' key that counts the
#         number of installs of <app_name>.
#
# @return IF_OK if successful
#         IF_ERROR otherwise
##
function register_install(app_name, path, version, display_version, product_version, port, service, webapp, rep_path,
                          protocol, priority, cpe, vendor, product, update, language, sw_edition, target_sw, target_hw,
                          extra, extra_no_report, files, fa_app_name, version_file, version_registry, registry_install_locations,
                          collect_methods)
{
  local_var func_name, args;
  local_var install_kb_key, app_kb_key;
  local_var install_added, proto;
  local_var report_version, report_path, p_extra;
  local_var install_obj = {};
  local_var cpe_part, cpe_parts, cpev23;

  var install_cpe;

  func_name = 'register_install';

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return return_error(IF_MUTEX_ARGS_TEMPLATE, args);
  }

  # Webapp and service are mutually exclusive
  if (!isnull(webapp) && !isnull(service))
  {
    args = make_list(func_name, 'webapp and service');
    return return_error(IF_MUTEX_ARGS_TEMPLATE, args);
  }

  # If app is a webapp, we need a port.
  if (webapp && isnull(port))
  {
    args = make_list(func_name, 'port');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # If 'service' is specified, we need a port.
  if (!isnull(service) && isnull(port))
  {
    args = make_list(func_name, 'port');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(update) && !is_string(update))
  {
    args = make_list(func_name, 'update', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(registry_install_locations) && typeof_ex(registry_install_locations) != 'array')
  {
    args = make_list(func_name, 'registry_install_locations', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(files) && typeof(files) != 'array')
  {
    args = make_list(func_name, 'files', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(sw_edition) && !is_string(sw_edition))
  {
    args = make_list(func_name, 'sw_edition', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(target_sw) && !is_string(target_sw))
  {
    args = make_list(func_name, 'target_sw', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(target_hw) && !is_string(target_hw))
  {
    args = make_list(func_name, 'target_hw', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(cpe) && !is_string(cpe))
  {
    args = make_list(func_name, 'cpe', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Default values.
  if (isnull(version)) version = UNKNOWN_VER;
  if (isnull(webapp)) webapp = FALSE;
  if (isnull(priority)) priority = IF_PRIORITY_NORMAL;
  if (isnull(protocol)) protocol = 'tcp';

  # Increment install count and save in KB.
  increment_install_count(app_name:app_name);

  replace_kb_item(name:ROOT_KB_KEY + app_name, value:InstallCount[app_name]);

  app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return IF_ERROR;
  app_kb_key = app_kb_key[1];

  # Set webapp key and ensure we store a path for root installs
  if (webapp)
  {
    if (path == '') path = '/';
    set_kb_item(name:"www/"+port+"/webapp_installed", value:TRUE);
  }

  # Generate install KB key.
  install_kb_key = make_install_kb_key(app_kb_key:app_kb_key, path:path, service:service, protocol:protocol);
  if (install_kb_key[0] != IF_OK) return IF_ERROR;
  install_kb_key = install_kb_key[1];


  # If we got a cpe string, unbind it to a CPE object
  if (!empty_or_null(cpe))
    install_cpe = cpe::unbind(cpe);

  # If no CPE was provided or the Unbind failed, make a new "blank" CPE
  if (isnull(install_cpe))
    install_cpe = new("cpe::cpe");

  # If additional CPE Values were provided as arguments, apply them to our CPE
  install_cpe.set(
    part: "a", # Default
    vendor: vendor,
    product: product,
    version: version,
    update: update,
    edition: "ANY", # Default
    language: language,
    sw_edition: sw_edition,
    target_sw: target_sw,
    target_hw: target_hw,
    overwrite: FALSE
  );

  # Will be NULL if CPE doesn't have at least Product and Vendor
  cpev23 = install_cpe.to_fs();
  cpev23 = cpe::standardize(cpev23);

  if (install_cpe.part != 'ANY') cpe_part = install_cpe.part;
  if (empty_or_null(vendor) && install_cpe.vendor != 'ANY') vendor = install_cpe.vendor;
  if (empty_or_null(product) && install_cpe.product != 'ANY') product = install_cpe.product;

  # Free up install_cpe now that we're done with it
  delete(install_cpe);

  # Add data to KB.
  install_added =
    add_install_to_kb(
      install_kb_key:install_kb_key,
      vendor:vendor,
      product:product,
      product_version:product_version,
      version:version,
      display_version:display_version,
      language:language,
      update:update,
      cpe:cpe,
      cpev23:cpev23,
      extra:extra,
      extra_no_report:extra_no_report,
      files:files,
      priority:priority,
      sw_edition:sw_edition,
      target_sw:target_sw,
      target_hw:target_hw,
      fa_app_name:fa_app_name,
      version_file:version_file,
      version_registry:version_registry,
      registry_install_locations:registry_install_locations,
      collect_methods:collect_methods
    );

  # Create the structured output
  if (!empty_or_null(vendor) && !empty_or_null(product) && !empty_or_null(cpe_part))
  {
    install_obj = {
      'app_name': app_name,
      'vendor': vendor,
      'product': product,
      'product_version': product_version,
      'version': version,
      'display_version': display_version,
      'language': language,
      'update': update,
      'sw_edition': sw_edition,
      'target_sw': target_sw,
      'target_hw': target_hw,
      'path': path,
      'cpe_part': cpe_part,
      'cpev23': cpev23
    };
    append_element(var:InstallObjects['installs'], value:install_obj);
  }

  if (install_added == IF_LOWER_PRIORITY) return IF_LOWER_PRIORITY;
  else if (install_added != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  # Register service if unknown
  if (!isnull(service) && service_is_unknown(port:port, ipproto:protocol))
  {
    # Replace any spaces with an underscore and lowercase service name
    proto = tolower(str_replace(string:service, find:' ', replace:'_'));
    register_service(port:port, proto:proto, ipproto:protocol);
  }

  # Add install to report.
  if (!isnull(display_version)) report_version = display_version;
  else report_version = version;

  # Build URL path if webapp
  if (webapp)
  {
    if (isnull(rep_path)) p_extra = "";
    else p_extra = rep_path;
    report_path = build_url2(port:port, qs:path + p_extra);

    PATH_REPORT_KEY = 'URL';
  }
  else report_path = path;

  if (
    add_install_to_report(
      app_name:app_name,
      path:report_path,
      service:service,
      version:report_version,
      extra:extra) != IF_OK
    ) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  return IF_OK;
}

##
# Creates a base KB key for an application.
#
# @param app_name string
# @param port     int OPTIONAL
#
# @remark This key does NOT end in a '/'.
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the app KB key
#                          (NULL if ret[0] != IF_OK)
function make_app_kb_key(app_name, port)
{
  local_var func_name, args;
  local_var app_kb_key;

  func_name = "make_app_kb_key";

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # App KB key consists of ROOT + port, if supplied + app_name
  app_kb_key = ROOT_KB_KEY;
  if (!isnull(port)) app_kb_key += port + '/';
  app_kb_key += app_name;

  return make_list(IF_OK, app_kb_key);
}

##
# Creates a base KB key for an install.
#
# @param  string  app_name
# @param  string  path     OPTIONAL local or URL path
# @param  string  service  OPTIONAL service name (e.g. SNMP, SIP)
# @param  string  protocol OPTIONAL IP protocol used by the port
#
# @remark 'path' or 'service' must be specified
# @remark If 'service' is specified, 'protocol' must also be specified
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the install KB key
#                          (NULL if ret[0] != IF_OK)
##
function make_install_kb_key(app_kb_key, path, service, protocol)
{
  local_var func_name, args;
  local_var install_kb_key, b64_path;

  func_name = 'make_install_kb_key';

  # Input validation.
  if (isnull(app_kb_key))
  {
    args = make_list(func_name, 'app_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return make_list(return_error(IF_MUTEX_ARGS_TEMPLATE, args));
  }

  if (!isnull(service) && isnull(protocol))
  {
    args = make_list(func_name, 'protocol');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Base KB key starts with app KB key.
  install_kb_key = app_kb_key + '/';

  # Encode path in base-64 and add to install_kb_key.
  if (!isnull(path))
  {
    b64_path = IF_base64(path);
    if (b64_path[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
    install_kb_key += b64_path[1];
  }

  if (!isnull(service))
  {
    install_kb_key += "service/" + protocol + '/' + service;
  }

  return make_list(IF_OK, install_kb_key);
}

##
# Adds install values to the KB.
#
# @param string  install_kb_key
# @param string  version
# @param string  display_version OPTIONAL
# @param array   extra OPTIONAL
# @param array   extra_no_report OPTIONAL
# @param string  cpe OPTIONAL
# @param string  cpev23 OPTIONAL
# @param int     priority
# @param string  sw_edition OPTIONAL
# @param string  target_sw OPTIONAL
# @param string  target_hw OPTIONAL
# @param string  fa_app_name OPTIONAL
# @param string  version_file OPTIONAL
# @param string  version_registry OPTIONAL
# @param array   registry_install_locations OPTIONAL
# @param string  collect_methods OPTIONAL
#
# @return IF_OK if successful
#         IF_MISSING_ARG if argument is missing
#         IF_ARG_BAD_TYPE if any argument is wrong type
#         IF_ERROR if unknown or upstream error occurs
##
function add_install_to_kb(install_kb_key, vendor, product, product_version, version, display_version,
  language, update, cpe, cpev23, extra, extra_no_report, files, priority, sw_edition, target_sw, target_hw,
  fa_app_name, version_file, version_registry, registry_install_locations, collect_methods)
{
  local_var func_name, args;
  local_var existing_priority, cpe_with_version, cpev22C;

  var install_cpe;

  func_name = 'add_install_to_kb';

  # Input validation.
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(priority))
  {
    args = make_list(func_name, 'priority');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(display_version) && !is_string(display_version))
  {
    args = make_list(func_name, 'display_version', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(vendor) && !is_string(vendor))
  {
    args = make_list(func_name, 'vendor', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(product) && !is_string(product))
  {
    args = make_list(func_name, 'product', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(product_version) && !is_string(product_version))
  {
    args = make_list(func_name, 'product_version', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(update) && !is_string(update))
  {
    args = make_list(func_name, 'update', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(sw_edition) && !is_string(sw_edition))
  {
    args = make_list(func_name, 'sw_edition', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(target_sw) && !is_string(target_sw))
  {
    args = make_list(func_name, 'target_sw', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(target_hw) && !is_string(target_hw))
  {
    args = make_list(func_name, 'target_hw', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(fa_app_name) && !is_string(fa_app_name))
  {
    args = make_list(func_name, 'fa_app_name', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(version_file) && !is_string(version_file))
  {
    args = make_list(func_name, 'version_file', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(version_registry) && !is_string(version_registry))
  {
    args = make_list(func_name, 'version_registry', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(collect_methods) && !is_string(collect_methods))
  {
    args = make_list(func_name, 'collect_methods', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(files) && typeof(files) != 'array')
  {
    args = make_list(func_name, 'files', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(registry_install_locations) && typeof_ex(registry_install_locations) != 'array')
  {
    args = make_list(func_name, 'registry_install_locations', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # If this install is already registered in the KB, only replace the
  # data if this is a higher priority install.
  existing_priority = get_kb_item(install_kb_key + PRIORITY_KEY);
  if (!isnull(existing_priority) && existing_priority > priority)
    return IF_LOWER_PRIORITY;

  # If there is an existing install, we need to over-write the source.
  # If we're not already providing one in 'extra' or 'extra_no_report'
  # set it to UNKNOWN_VER.
  if (!isnull(existing_priority) && isnull(extra[SOURCE_KEY]) && isnull(extra_no_report[SOURCE_KEY]))
    extra[SOURCE_KEY] = UNKNOWN_VER;

  # Add priority to KB.
  replace_kb_item(name:install_kb_key + PRIORITY_KEY, value:priority);

  # Add version to KB.
  replace_kb_item(name:install_kb_key + VERSION_KEY, value:version);

  # If supplied, add the Vendor to the KB
  if (!isnull(vendor))
    replace_kb_item(name:install_kb_key + VENDOR_KEY, value:vendor);

  # If supplied, add the Product name to the KB
  if (!isnull(product))
    replace_kb_item(name:install_kb_key + PRODUCT_KEY, value:product);

  # If supplied, add the Product Version to the KB
  if (!isnull(product_version))
    replace_kb_item(name:install_kb_key + PRODUCT_VERSION_KEY, value:product_version);

  # If supplied, add the display version to the KB.
  if (!isnull(display_version))
    replace_kb_item(name:install_kb_key + DISPLAY_VERSION_KEY, value:display_version);

  # If supplied, add the supported Language to the KB.                                                                      
  if (!isnull(language))
    replace_kb_item(name:install_kb_key + LANG_KEY, value:language);

  # If supplied, add the Update version to the KB.
  if (!isnull(update))
    replace_kb_item(name:install_kb_key + UPDATE_KEY, value:update);

  # If supplied, add the sw_edition to the KB.
  if (!isnull(sw_edition))
    replace_kb_item(name:install_kb_key + SW_EDITION_KEY, value:sw_edition);

  # If supplied, add the target_sw to the KB.
  if (!isnull(target_sw))
    replace_kb_item(name:install_kb_key + TARGET_SW_KEY, value:target_sw);

  # If supplied, add the target_hw to the KB.
  if (!isnull(target_hw))
    replace_kb_item(name:install_kb_key + TARGET_HW_KEY, value:target_hw);

  # If supplied, add the fa_app_name to the KB.
  if (!isnull(fa_app_name))
    replace_kb_item(name:install_kb_key + FA_APP_NAME_KEY, value:fa_app_name);

  # If supplied, add the version_file to the KB.
  if (!isnull(version_file))
    replace_kb_item(name:install_kb_key + VERSION_FILE_KEY, value:version_file);
  
  # If supplied, add the version_registry to the KB.
  if (!isnull(version_registry))
    replace_kb_item(name:install_kb_key + VERSION_REGISTRY_KEY, value:version_registry);

  # If supplied, add the collect_methods to the KB.
  if (!isnull(collect_methods))
    replace_kb_item(name:install_kb_key + COLLECT_METHODS_KEY, value:collect_methods);

  
  # Get the executing plugin ID
  # Skip accessing ENV_PLUGIN in CLI mode, as it ends up in a segfault
  if (nasl_level() >= 81500 && !dbg::CLI_MODE) 
  {
    var env = nasl_environment(flags:ENV_PLUGIN);
    if (!empty_or_null(env['plugin_id']))
    {
      replace_kb_item(name:install_kb_key + PLUGIN_ID_KEY, value:env['plugin_id']);
    }
  }

  if (empty_or_null(cpe))
    cpe = NULL; # Force to nul just in case

  if (!empty_or_null(cpe))
    install_cpe = cpe::unbind(cpe);

  if (isnull(install_cpe))
    install_cpe = new("cpe::cpe");

  install_cpe.set(
    part:"a", # Default
    vendor: vendor,
    product: product,
    version: version,
    update: update,
    edition: "ANY", # Default
    language: language,
    sw_edition: sw_edition,
    target_sw: target_sw,
    target_hw: target_hw,
    overwrite: FALSE
  );

  # Will be NULL if CPE doesn't have at least Product and Vendor
  cpe_with_version = install_cpe.to_uri(extended:FALSE);
  cpe_with_version = cpe::standardize(cpe_with_version);

  cpev22C = install_cpe.to_uri();
  cpev22C = cpe::standardize(cpev22C);

  # Free up our install_cpe now that we're done with it
  delete(install_cpe);

  if (!empty_or_null(cpe_with_version))
    replace_kb_item(name:install_kb_key + CPE_KEY, value:cpe_with_version);

  if (!empty_or_null(cpev22C))
    replace_kb_item(name:install_kb_key + CPE_KEY+"/v22C", value:cpev22C);

  if (!empty_or_null(cpev23))
    replace_kb_item(name:install_kb_key + CPE_KEY+"/v23", value:cpev23);

  if (!empty_or_null(files))
  {
    if (add_files_to_kb(install_kb_key:install_kb_key, files:files) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }

  if (!empty_or_null(extra))
  {
    if (add_extra_to_kb(install_kb_key:install_kb_key, extra:extra) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }

  if (!empty_or_null(extra_no_report))
  {
    if (add_extra_to_kb(install_kb_key:install_kb_key, extra:extra_no_report) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }

  if (!empty_or_null(registry_install_locations))
  {
    if (add_registry_install_locations_to_kb(install_kb_key:install_kb_key, locations:registry_install_locations) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }

  return IF_OK;
}

##
# Adds extra items to the KB.
#
# @param array extra
# @remark This function has the side effect of modifying the KB.
# @remark List values are joined SEPARATOR separated strings.
#
# @return IF_OK if successful
##
function add_extra_to_kb(install_kb_key, extra)
{
  local_var func_name, args;
  local_var key, value;

  func_name = "add_extra_to_kb";

  # Input validation
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Add extra items to KB
  foreach key (keys(extra))
  {
    value = extra[key];

    # Simply ignore NULL values instead of raising an error
    if (isnull(value))
    {
      continue;
    }

    if (!is_string(value) && typeof(value) != 'array' && typeof(value) != 'int')
    {
      args = make_list(func_name, "extra['" + key + "']", 'string/list/int');
      return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
    }

    if (typeof(value) == 'array') value = join(value, sep:SEPARATOR);

    replace_kb_item(name:install_kb_key + '/' + key, value:value);
  }

  return IF_OK;
}

##                                                                                                                      
# Adds File items to the KB.                                                                                           
#                                                                                                                       
# @param  array files                                                                                                    
#
# @remark This function has the side effect of modifying the KB.                                                        
# @remark List values are joined SEPARATOR separated strings.                                                           
#                                                                                                                       
# @return IF_OK if successful                                                                                           
##
function add_files_to_kb(install_kb_key, files)
{
  local_var func_name, args;
  local_var entry, file, attr, value;
  local_var num_added_files;

  func_name = "add_files_to_kb";
  num_added_files = 0;

  # Input validation                                                                                                    
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(files))
  {
    args = make_list(func_name, 'files');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(files) && typeof(files) != 'array')
  {
    args = make_list(func_name,'files', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (max_index(files) <= 0)
  {
    args = make_list(func_name,'files (Empty)');
    return return_error(IF_PARSE_ERROR_TEMPLATE, args);
  }

  # Add file items to KB                                                                                               
  for (var i = 0, il = max_index(files); i < il; i++)
  {
    file = files[i];

    # Simply ignore NULL values instead of raising an error                                                             
    if (isnull(file))
      continue;

    # Let's make sure the entry is actuall an array
    if (!isnull(file) && typeof(file) != 'array')
      continue;

    # Next, check that we have the proper data!
    # Each entry should be an dict with a required key of "path" and any number of additional pairs

    # If there's no Path defined, then move along
    if (empty_or_null(file["path"]))
      continue;

    # If we do have path, but it's not a string,then move along
    if (!isnull(file["path"]) && !is_string(file["path"]))
      continue;

    # Okay, we've got a valid path (nice!) now we need to store the info we have on it
    foreach attr (keys(file))
    {
      value = file[attr];

      if (empty_or_null(value))
        continue;

      if (!is_string(value) && typeof(value) != 'array' && typeof(value) != 'int')
      {
        args = make_list(func_name, "files["+i+"]['"+attr+"']", 'string/list/int');
        return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
      }

      if (typeof(value) == 'array') value = join(value, sep:", ");

      replace_kb_item(name:install_kb_key+'/files/'+num_added_files+'/'+attr, value:value);
    }
    num_added_files++;
  }

  return IF_OK;
}

##
# Adds registry_install_locations items to the KB.
#
# @param string install_kb_key
# @param array locations
# @remark This function has the side effect of modifying the KB.
# @remark List values are joined SEPARATOR separated strings.
#
# @return IF_OK if successful
##
function add_registry_install_locations_to_kb(install_kb_key, locations)
{
  var func_name = "add_registry_install_locations_to_kb";
  var args;

  # Input validation
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(locations))
  {
    args = make_list(func_name, 'locations');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (typeof_ex(locations) != 'array')
  {
    args = make_list(func_name, 'locations', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  foreach var key (keys(locations))
  {
    var value = locations[key];
    if (isnull(value)) continue;

    if (typeof_ex(value) != 'list')
    {
      args = make_list(func_name, "locations['" + key + "']", 'list');
      return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
    }

    value = join(value, sep:", ");
    replace_kb_item(name:install_kb_key + REGISTRY_INSTALL_LOCATIONS_KEY + '/' + key, value:value);
  }

  return IF_OK;
}

##
# Adds the application install to the global report.
#
# @param string   app_name
# @param string   path     OPTIONAL local or URL path
# @param string   service  OPTIONAL service name (e.g. SNMP, SIP)
# @param string   version
# @param array    extra OPTIONAL
#
# @remark 'path' or 'service' must be specified
#
# @return IF_OK if successful
#         IF_MISSING_ARG if argument is missing
#         IF_ARG_BAD_TYPE if any argument is wrong type
#         IF_ERROR if unknown or upstream error occurs
##
function add_install_to_report(app_name, path, service, version, extra)
{
  local_var func_name, args;
  local_var report;
  local_var extra_string, extra_list;
  local_var fields, field_length;

  func_name = 'add_install_to_report';

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return return_error(IF_MUTEX_ARGS_TEMPLATE, args);
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Initialize report if needed.
  report = InstallReport[app_name];
  if (isnull(report)) report = '';

  # Process extra array.
  if (!isnull(extra))
  {
    extra = process_extra(extra);
    if (extra[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
    extra_string = extra[1];
    extra_list = extra[2];
  }
  else
  {
    extra_string = NULL;
    extra_list = NULL;
  }

  # Determine field length.
  if (!isnull(path))
    fields = make_list(PATH_REPORT_KEY, VERSION_REPORT_KEY);

  if (!isnull(service))
    fields = make_list(SERVICE_REPORT_KEY, VERSION_REPORT_KEY);

  if (!isnull(extra_string) && len(extra_string) > 0) fields = make_list(fields, keys(extra_string));
  field_length = maxlen(fields);
  if (field_length == -1) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  # Add string data to report.
  report =
    add_string_data_to_report(
      report:report,
      path:path,
      service:service,
      version:version,
      extra:extra_string,
      field_length:field_length
    );
  if (report[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  report = report[1];

  # Add list data to report.
  if (!isnull(extra_list))
  {
    report =
      add_list_data_to_report(
        report:report,
        extra:extra_list
      );
    if (report[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
    report = report[1];
  }

  # Store report in global variable.
  InstallReport[app_name] = report;

  return IF_OK;
}

##
# Splits the extra array into two arrays, one containing string values
# the other containing list values.
#
# @param  array extra
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is an array with all the string values
#                   ret[2] is an array with all the list values
##
function process_extra(extra)
{
  local_var func_name, args;
  local_var extra_string, extra_list;
  local_var key, value;
  local_var ret;

  func_name = 'process_extra';

  # Accept argument anonymously.
  if (isnull(extra)) extra = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Initialize return values.
  extra_string = make_array();
  extra_list = make_array();

  # Iterate through the array and split into two.
  foreach key (keys(extra))
  {
    value = extra[key];

    # Simply ignore NULL values instead of raising an error
    if (isnull(value))
    {
      continue;
    }
    else if (is_string(value))
    {
      extra_string[key] = value;
    }
    else if (typeof(value) == 'array')
    {
      extra_list[key] = value;
    }
    else if (typeof(value) == 'int')
    {
      extra_string[key] = string(value);
    }
    else
    {
      args = make_list(func_name, "extra['" + key + "']", 'string/list');
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }
  }

  # Build return, can't use make_list because it will flatten
  # extra_string and extra_list. When 5.0 is out of support, replace
  # with make_list2().
  ret[0] = IF_OK;
  ret[1] = extra_string;
  ret[2] = extra_list;

  return ret;
}

##
# Adds top block of string data to install report.
#
# @param string   report
# @param string   path     OPTIONAL local or URL path
# @param string   service  OPTIONAL service name (e.g. SNMP, SIP)
# @param string   version
# @param array    extra OPTIONAL
# @param int      field_length
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_string_data_to_report(report, path, service, version, extra, field_length)
{
  local_var func_name, args;
  local_var format_string;

  func_name = 'add_string_data_to_report';

  # Input validation.
  if (isnull(report))
  {
    args = make_list(func_name, 'report');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return make_list(return_error(IF_MUTEX_ARGS_TEMPLATE, args));
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(field_length))
  {
    args = make_list(func_name, 'field_length');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (typeof(field_length) != 'int')
  {
    args = make_list(func_name, 'field_length', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  format_string = '\n  %-' + field_length + "s : %s";

  # Add path or service and protocol along with version to report.
  if (!isnull(path))
  {
    report += vsprintf(args:make_list(PATH_REPORT_KEY, path), format:format_string);
  }

  if (!isnull(service))
  {
    report += vsprintf(args:make_list(SERVICE_REPORT_KEY, service), format:format_string);
  }

  report += vsprintf(args:make_list(VERSION_REPORT_KEY, version), format:format_string);

  # Add string data from extras to report.
  if (!isnull(extra))
  {
    local_var key, value;

    foreach key (sort(keys(extra)))
    {
      value = extra[key];
      if (!is_string(value))
      {
        args = make_list(func_name, "extra['" + key + "']", "string");
        return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
      }

      report += vsprintf(args:make_list(key, value), format:format_string);
    }
  }

  report += '\n';

  return make_list(IF_OK, report);
}

##
# Adds bottom block of list data to install report.
#
# @param string   report
# @param array    extra
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_list_data_to_report(report, extra)
{
  local_var func_name, args;

  func_name = 'add_list_data_to_report';

  # Input validation.
  if (isnull(report))
  {
    args = make_list(func_name, 'report');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Add list data from extras to report.
  local_var key, value;

  foreach key (sort(keys(extra)))
  {
    local_var element;

    value = extra[key];
    if (typeof(value) != 'array')
    {
      args = make_list(func_name, "extra['" + key + "']", "list");
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }

    report += '\n  ' + key + ' :';
    foreach element (sort(value)) report += '\n    ' + LIST_BULLET + element;
    report += '\n';
  }

  return make_list(IF_OK, report);
}

##
# Generates apps installed report.
#
# @param  string  app_name OPTIONAL if NULL all installs InstallReport will be reported.
# @param  string  extra OPTIONAL extra data to be appended to report
##
function generate_install_report(app_name, extra)
{
  local_var report;
  # If app_name was not provided, report every installed app.
  # Otherwise, report only on the specified app_name.
  if (isnull(app_name))
  {
    local_var app_count, temp;

    report = '';
    app_count = len(InstallReport);

    foreach var app_name_it (keys(InstallReport))
    {
      # If there is more than one app, add a header with the app name.
      if (app_count > 1) report += '\n--- ' + app_name_it + ' ---\n';

      # Add the header to the report and check the value.
      temp = add_header_to_report(app_name_it);
      if (temp[0] != IF_OK) return IF_ERROR;
      report += temp[1];
    }
    if (report == '') return IF_NOT_FOUND;
  }
  else
  {
    report = add_header_to_report(app_name);
    if (report[0] == IF_NOT_FOUND) return IF_NOT_FOUND;
    else if (report[0] != IF_OK) return IF_ERROR;
    report = report[1];
  }

  # Add extra data if it exists.
  if (!isnull(extra)) report += '\n' + extra + '\n';

  return report;
}

##
# Reports detected installs.
#
# @param  string  app_name OPTIONAL if NULL all installs in
#                 InstallReport will be reported.
# @param  int     port OPTIONAL defaults to 0
# @param  string  extra OPTIONAL extra data to be appended to report
# @param  string  protocol OPTIONAL protocol for report
# @param  string  report_override OPTIONAL for setting custom report
#
# @return IF_OK if successful
#         IF_NOT_FOUND if no install report for that app
#         IF_ERROR otherwise
##
function report_installs(app_name, port, extra, protocol, report_override)
{
  local_var func_name, args;
  local_var report;
  local_var env, plugin_id;
  local_var attachment, attachments, count;
  local_var install, key;

  func_name = 'report_installs';

  # Input Validation
  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (!isnull(extra) && !is_string(extra))
  {
    args = make_list(func_name, 'extra', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Default Value
  if (isnull(port)) port = 0;

  if (isnull(report_override))
  {
    report = generate_install_report(app_name:app_name, extra:extra);
  }
  else
  {
    if (app_name && !InstallCount[app_name]) report = IF_NOT_FOUND;
    else report = report_override;
  }

  if (report == IF_ERROR || report == IF_NOT_FOUND) return report;

  if (report_verbosity > 0)
  {
    report = data_protection::sanitize_user_paths(report_text: report);
    security_note(extra:report, port:port, proto:protocol);
  }
  else
  {
    security_note(port:port, proto:protocol);
  }

  # Silently continue even if report_tag_internal() fails to be called.
  report_software_inventory(port:port, protocol:protocol);

  return IF_OK;
}

##
# Reports software inventory data.
#
# @param  int     port OPTIONAL Defaults to 0
# @param  string  protocol OPTIONAL Defaults to tcp
#
# @return IF_OK if successful
#         IF_ERROR otherwise
#
# @remark This function should only be called after all calls to register_install() in a given plugin. 
#         register_install() builds the global InstallObjects which this function relies on.
#         This function WILL NOT run if nasl is running in CLI mode.
##
function report_software_inventory(port, protocol)
{
  # Environment requirements
  if (nasl_level() < 81500 || dbg::CLI_MODE) # Accessing ENV_PLUGIN in CLI mode ends in a segfault
    return IF_ERROR;
  
  var env = nasl_environment(flags:ENV_PLUGIN);
  if (empty_or_null(env['plugin_id']))
    return IF_ERROR;

  # Input validation
  if (!isnull(port) && typeof(port) != 'int')
    return IF_ERROR;
  
  # Default values
  if (isnull(port)) port = 0;
  if (empty_or_null(protocol)) protocol = 'tcp';

  # Report
  report_tag_internal(
    tag:strcat('installed-sw:', env['plugin_id'], ':', port, ':', protocol), 
    value:InstallObjects
  );

  return IF_OK;
}

##
# Adds header to report if install count is greater than 1.
#
# @param string app_name
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_header_to_report(app_name)
{
  local_var func_name, args;
  local_var report, count;

  func_name = 'add_header_to_report';

  # Allow argument to be passed anonymously.
  if (isnull(app_name)) app_name = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Retrieve report and exit if either is NULL.
  report = InstallReport[app_name];
  count = InstallCount[app_name];

  if (isnull(report) || isnull(count)) return make_list(IF_NOT_FOUND);

  # Add header to report if install count is greater than 1.
  if (count > 1) report =
    '\nNessus detected ' + count + ' installs of ' + app_name + ':\n' + report;

  return make_list(IF_OK, report);
}

##
# Retrieves all installs of an application/cpe.
#
# @param  string  app_name
# @param  int     port OPTIONAL limits search to remote installs found
#                 on port
# @param  bool    service OPTIONAL if true return service installs (default: true)
# @param  bool    webapp  OPTIONAL if true return webapp installs (default: true)
# @param  int     exit_if_not_found OPTIONAL defaults to FALSE, exits
#                 if no installs of app_name are found.
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. that each
#                          install is an array containing all the data
#                          stored in the KB.
#                          (NULL if ret[0] != IF_OK)
##
function get_installs(app_name, port, service, webapp, exit_if_not_found)
{
  local_var func_name, args;
  local_var app_kb_key, install_kb_keys;
  local_var installs;
  local_var i, ret;

  func_name = 'get_installs';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Default value
  if (isnull(exit_if_not_found)) exit_if_not_found = FALSE;

  app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  app_kb_key = app_kb_key[1];

  # Get a list of KB keys for each install.
  install_kb_keys = find_installs_by_key(app_kb_key:app_kb_key, service:service, webapp:webapp);
  if (install_kb_keys[0] == IF_NOT_FOUND)
  {
    if (exit_if_not_found)
    {
      if (isnull(port)) audit(AUDIT_NOT_INST, app_name);
      else audit(AUDIT_NOT_DETECT, app_name, port);
    }
    else return make_list(IF_NOT_FOUND);
  }
  else if (install_kb_keys[0] != IF_OK)
    return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));

  install_kb_keys = install_kb_keys[1];

  # Populate install data.
  installs = get_install_data_from_keys(install_kb_keys);

  if (installs[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  installs = installs[1];

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = installs;

  return ret;
}

##
# Returns a single install of app, branches if there are multiple.
#
# @param  string  app_name
# @param  int     port OPTIONAL
# @param  bool    exit_if_unknown_ver OPTIONAL if TRUE, will exit if
#                 version == UNKNOWN_VER. Defaults to FALSE.
# @param  bool    service OPTIONAL if true return service installs (default: true)
# @param  bool    webapp  OPTIONAL if true return webapp installs (default: true)
#
# @remark This function calls get_installs() w/ exit_if_not_found set
#         to TRUE and will exit if there are no installs.
# @remark This function assumes that if looking for an app on several
#         ports, you are branching over the ports as well. That is to
#         say, it does not account for iterating over ports but then
#         branching over installs and will break. Consider it enforced
#         consistency.
#
# @return array single install
##
function get_single_install(app_name, port, exit_if_unknown_ver, combined, service, webapp)
{
  local_var func_name, args;
  local_var installs, install;

  func_name = 'get_single_install';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (isnull(combined)) combined = FALSE;

  if (isnull(exit_if_unknown_ver)) exit_if_unknown_ver = FALSE;

  # This function should only be called once per plugin or you'll end
  # up potentially forking a LOT.
  if (IF_GSI_CALLED[app_name])
    exit(1, "get_single_install() should only be called once per app to avoid excessive forking.");

  IF_GSI_CALLED[app_name] = TRUE;

  if(combined)
    installs = get_combined_installs(app_name:app_name, exit_if_not_found:TRUE);
  else
    installs = get_installs(
      app_name:app_name, port:port, service:service, webapp:webapp, exit_if_not_found:TRUE);

  if (installs[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  install = branch(installs[1]);
  if (isnull(port)) port = install['port'];

  if (exit_if_unknown_ver && install['version'] == UNKNOWN_VER)
  {
    if (!isnull(port))
    {
      # Service
      service = get_kb_list('installed_sw/' + port + '/' + app_name + "/service/*/*/version");
      if (!empty_or_null(service))
        audit(AUDIT_SERVICE_VER_FAIL, app_name, port);

      # Webapp
      if (!empty_or_null(install['path']))
        audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name,build_url2(qs:install['path'], port:port));
      else
        audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
    }
    else audit(AUDIT_UNKNOWN_APP_VER, app_name);
  }

  return install;
}

##
# Finds all installs under the app KB key.
#
# @param  string  app_kb_key
# @param  bool    service OPTIONAL if true return service installs (default: true)
# @param  bool    webapp  OPTIONAL if true return webapp installs (default: true)
#
# @remark if service or webapp are not specified return all installs 
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of install KB keys for installs
#                          of app_name (NULL if ret[0] != IF_OK)
##
function find_installs_by_key(app_kb_key, webapp, service)
{
  local_var func_name, args;
  local_var install_kb_version_keys, install_kb_keys;
  local_var key, key_split, ret;

  func_name = 'find_installs_by_key';

  # Allow anonymous argument
  if (isnull(app_kb_key)) app_kb_key = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(app_kb_key))
  {
    args = make_list(func_name, 'app_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Defaults
  if (isnull(webapp)) webapp = true;
  if (isnull(service)) service = true;

  # Search by version since every install is guaranteed to have this
  # key. Then just strip out VERSION_KEY to get the install KB key.
  install_kb_version_keys = get_kb_list(app_kb_key + '/*' + VERSION_KEY);
  if (empty_or_null(install_kb_version_keys))
    return make_list(IF_NOT_FOUND);

  # Process install keys and add to 
  install_kb_keys = make_list();
  foreach key (sort(keys(install_kb_version_keys)))
  {
    key_split = split(key, sep:'/', keep:FALSE);

    if
    (
      isnull(pregmatch(string: key, pattern: "\/files\/[0-9]*"+VERSION_KEY)) &&
      (
        webapp && service || # skip checks if all were specified / none were passed to this func
        webapp  && key_split[1] =~ "^[0-9]+$" && key_split[3] != 'service' || # webapp
        service && key_split[1] =~ "^[0-9]+$" && key_split[3] == 'service' # service
      )
    )
      install_kb_keys = make_list(install_kb_keys, key - VERSION_KEY);
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = install_kb_keys;

  return ret;
}

##
# Retrieves data associated with install keys passed in.
#
# @param  list install_kb_keys
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. each install is
#                          an array containing install data.
#                          (NULL if ret[0] != IF_OK)
##
function get_install_data_from_keys(install_kb_keys)
{
  local_var func_name, args;
  local_var installs, install, install_kb_key, install_kb_list, install_kb_key_split;
  local_var i, kbs, key, top_key, file_data, file_key_split, file_num, file_attr;
  local_var temp, ret;

  func_name = 'get_install_data_from_keys';

  # Allow anonymous argument
  if (isnull(install_kb_keys)) install_kb_keys = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(install_kb_keys))
  {
    args = make_list(func_name, 'install_kb_keys');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(install_kb_keys) != 'array')
  {
    args = make_list(func_name, 'install_kb_keys', 'list');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  installs = make_list();
  i = 0;

  # Get all KBs associated with each install_kb_key and then store the
  # values in an array per install, indexed by the top-level key name.
  foreach install_kb_key (install_kb_keys)
  {
    # Get all KBs for the install.
    install_kb_list = install_kb_key + '/*';
    kbs = get_kb_list(install_kb_list);
    install = make_array();
    file_data = make_list();

    install_kb_key_split = split(install_kb_key, sep:'/', keep:FALSE);

    # Service
    #  KB Format: register_install/<port>/<app>/service/<protocol>/<service>
    if (install_kb_key_split[1] =~ '^[0-9]+$' && install_kb_key_split[3] == 'service')
    {
      install['protocol'] = install_kb_key_split[4];
      install['service']  = install_kb_key_split[5];
    }
    # Local or webapp with a path
    else
    {
      # Decode path from install_key and store it in array.
      temp = get_path_from_kb_key(install_kb_key);
      if (temp[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
      install['path'] = temp[1];
    }

    foreach key (keys(kbs))
    {
      # Associated file data will be re-constructed into a list of arrays
      if (!isnull(pregmatch(string:key, pattern:"\/files\/[0-9]*\/")))
      {
        file_key_split = split((key-install_kb_key+'/'), sep:'/', keep:FALSE);
        file_num = int(file_key_split[2]);
        file_attr = file_key_split[3];

        # Make a new file entry if we need to
        if (isnull(file_data[file_num]))
        {
          file_data[file_num] = make_array();
        }

        file_data[file_num][file_attr] = kbs[key];
      } else {
        # We just want the top-level key as the array key.
        top_key = key - (install_kb_key + '/');

        install[top_key] = kbs[key];
      }
    }

    if (max_index(file_data) > 0)
      install['files'] = file_data;

    installs[i] = install;
    i++;
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = installs;

  return ret;
}

##
# Returns the path associated with an install KB key.
#
# @param  string install_kb_key [description]
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the base64-decoded path associated
#                          w/ the KB key
#                          (NULL if ret[0] != IF_OK)
##
function get_path_from_kb_key(install_kb_key)
{
  local_var func_name, args;
  local_var pattern, match, path, port_match;

  func_name = 'get_path_from_kb_key';

  # Accept argument anonymously.
  if (isnull(install_kb_key)) install_kb_key = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  pattern = ROOT_KB_KEY + "(?:\d+/)?.+/(.*)";
  match = pregmatch(string:install_kb_key, pattern:pattern, icase:FALSE);
  if (isnull(match))
  {
    args = make_list(func_name, 'install_kb_key');
    return make_list(return_error(IF_PARSE_ERROR_TEMPLATE, args));
  }

  # A Base64-encoded path will not contain '/'
  path = IF_base64_decode(match[1]);
  if (path[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));

  # Check for webapp by looking for a port in 'install_kb_key'
  # If we have one and the www/port/webapp_installed key is set
  # Check for root installs and return and empty value for the path
  # Otherwise return the path as is
  port_match = pregmatch(pattern:'installed_sw/([0-9]+)/', string:install_kb_key);

  if (!isnull(port_match) && !empty_or_null(port_match[1]))
  {
    port_match = port_match[1];
    if (get_kb_item('www/' + port_match + '/webapp_installed'))
    {
      if (path[1] == '/') path[1] = '';
    }
  }
  return make_list(IF_OK, path[1]);
}

##
# Returns the number of installs of 'app_name'.
#
# @param  string  app_name
# @param  bool    exit_if_zero OPTIONAL, if TRUE will exit w/ audit if
#                              install count is 0.
#
# @return int   < 0 if error occurs
#               = 0 if no installs found
#               > 0 if 1 or more installs found
##
function get_install_count(app_name, exit_if_zero)
{
  local_var func_name, args;
  local_var count;

  func_name = 'get_install_count';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Default Value
  if (isnull(exit_if_zero)) exit_if_zero = FALSE;

  count = get_kb_item(ROOT_KB_KEY + app_name);
  if (isnull(count) || count == 0)
  {
    if (exit_if_zero) audit(AUDIT_NOT_INST, app_name);
    else return 0;
  }

  return count;
}

##
# Encodes a string to base-64 in a 'KB-safe' way.
#
# @param string str string to encode
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the encoded string
#                          (NULL if ret[0] != IF_OK)
##
function IF_base64(str)
{
  local_var func_name, args;
  local_var b64;

  func_name = 'IF_base64';

  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(str))
  {
    args = make_list(func_name, 'str');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  b64 = base64(str:str);

  b64 = str_replace(string:b64, find:'=', replace:'$');
  b64 = str_replace(string:b64, find:'/', replace:'&');

  return make_list(IF_OK, b64);
}

##
# Decodes a 'KB-safe' base64 string back to ASCII.
#
# @param string str string to decode
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the decoded string
#                          (NULL if ret[0] != IF_OK)
##
function IF_base64_decode(str)
{
  local_var func_name, args;

  func_name = 'IF_base64';

  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(str))
  {
    args = make_list(func_name, 'str');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  str = str_replace(string:str, find:'$', replace:'=');
  str = str_replace(string:str, find:'&', replace:'/');

  return make_list(IF_OK, base64_decode(str:str));
}

##
# Returns error code for given template and prints error.
#
# @param  list  error_template defined in header
# @param  list  args
#
# @return int   error corresponding to error_template or IF_ERROR if
#               error occurs within this function
##
function return_error(error_template, args)
{
  # Allow arguments to be passed anonymously.
  if (isnull(error_template)) error_template = _FCT_ANON_ARGS[0];
  if (isnull(args)) args = _FCT_ANON_ARGS[1];

  # Input validation.
  if (isnull(error_template))
  {
    err_print("return_error(): missing required argument 'error_template'.");
    return IF_ERROR;
  }

  if (isnull(args))
  {
    err_print("return_error(): missing required argument 'args'.");
    return IF_ERROR;
  }

  if (typeof(error_template) != 'array' || len(error_template) != 3)
  {
    err_print("return_error(): An invalid error template was passed.");
    return IF_ERROR;
  }

  if (typeof(args) != 'array' || len(args) != error_template[0])
  {
    err_print("return_error(): The number of args passed does not match the error template for " +
      "error code: " + error_template[2] + ". (Expected " + error_template[0] +
      ", received " + len(args) + ")");
    return IF_ERROR;
  }

  # Print error if verbose.
  if (IF_VERBOSE_ERRORS || dbg::DBG_LOG_LEVEL > 0) err_print(vsprintf(args:args, format:error_template[1]));

  return error_template[2];
}

# Copy of build_url() in http_misc_func.inc to avoid dependency
# requirement.
function build_url2(port, host, qs, username, password)
{
  local_var t, url, p, n;

  t = get_port_transport(port);
  p = "";
  if (t > ENCAPS_IP)
  {
    url = "https://";
    if (port != 443) p = ':' + port;
  }
  else
  {
    url = "http://";
    if (port != 80) p = ':' + port;
  }

  if (strlen(host) > 0)
    n = host;
  else
  {
    if (get_kb_item("DNS/invalid_hostname"))
    n = get_host_ip();
    else
    {
      n = get_host_name();
      if (n =~ "^([0-9]+\.)+in-addr\.arpa$")
      n = get_host_ip();
    }
  }

  if (! isnull(username) || ! isnull(password))
  {
    url += username;
    if (! isnull(password))
    url += ":" + password;
    url += "@";
  }
  url = url + n + p;
  if (strlen(qs) > 0 && qs[0] == '/') url = url + qs;
  else url = url + '/' + qs;
  return url;
}

##
# Standardize CPE ID
#
# @param  string  cpe ID to standardize
#
# @remark This is just a start, more standardizations will be added at a later date.
#
# @return standardized CPE ID string 
##
function standardize_cpe(cpe)
{
  var func_name = "standardize_cpe";

  if (isnull(cpe)) return NULL;

  cpe = str_replace(string:cpe, find:' ', replace:'_');     # Replace spaces with underscores
  cpe = tolower(cpe);                                       # Lowercase

  # [RFC2234] ABNF grammar reqs

  # Escape special chars with '\'
  # ?, *, -,  

  return cpe;
}

##
# Construct a valid CPE String based on the data provided
#
# @param  [cpe_ver:string]     REQUIRED  Valid version of CPE to construct (22 URI, 22C URI, 23 Formatted String)
# @param  [base_cpe:string]    OPTIONAL  A CPE String (URI or Formatted String) to use as a base
# @param  [part:string]        OPTIONAL  Type of the product ('a' for applications, 'o' for operating systems, 'h' for hardware)
# @param  [vendor:string]      REQUIRED  Name of the product vendor (OPTIONAL if we have base_cpe)
# @param  [product:string]     REQUIRED  Name of the product (OPTIONAL if we have base_cpe)
# @param  [version:string]     OPTIONAL  Version of the installed product
# @param  [update:string]      OPTIONAL  Current update of the product
# @param  [edition:string]     OPTIONAL  Current edition of the product
# @param  [language:string]    OPTIONAL  RFC5646 formatted Language specification
# @param  [sw_edition:string]  OPTIONAL  Software edition that describes the target audience  
# @param  [target_sw:string]   OPTIONAL  Target Software environment for the product
# @param  [target_hw:string]   OPTIONAL  Target Hardware environment for the product
# @param  [other:string]       OPTIONAL  Additional CPE 2.3 info
#
# @return standardized CPI 2.2 URI or CPE 2.3 Formatted String
##
function construct_cpe(cpe_ver, base_cpe, part, vendor, product, version, update, edition, language,
                       sw_edition, target_sw, target_hw, other)
{
  var func_name = "construct_cpe";

  var cpe22_prefix = "cpe:/";
  if ('x-cpe' >< base_cpe) cpe22_prefix = "x-cpe:/";

  var cpe23_prefix = "cpe:2.3:";
  if ('x-cpe' >< base_cpe) cpe23_prefix = "x-cpe:2.3:";

  var new_cpe = "";
  var new_extended  = "";
  var have_ext_attrs, have_data = FALSE;
  var match, args, base_cpe_data, ret;
  var lesser_values = ["*", "ANY", "NA"];

  #var valid_cpe_vers = make_list(
  #  "22",   #CPE v2.2
  #  "22C",  #CPE v2.2 + Packed extended args
  #  "23"    #CPE v2.3
  #);

  var new_cpe_data = make_list(
    "*", # 0 part
    "*", # 1 vendor
    "*", # 2 product
    "*", # 3 version
    "*", # 4 update
    "*", # 5 edition
    "*"  # 6 language
  );

  var new_cpe_extended = make_list(
    "*", # 0 sw_edition
    "*", # 1 target_sw
    "*", # 2 target_hw
    "*"  # 3 Other
  );

  if (isnull(cpe_ver))
  {
    args = make_list(func_name, 'cpe_ver');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (empty_or_null(base_cpe) && (isnull(vendor) || isnull(product)))
  {
    args = make_list(func_name, 'vendor or product');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Validate input
  #if cpe_ver isn't null, and either isn't a string or not a valid option...
  if (!isnull(cpe_ver) && !is_string(cpe_ver))
  {
    args = make_list(func_name, 'cpe_ver', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(base_cpe) && !is_string(base_cpe))
  {
    args = make_list(func_name, 'base_cpe', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(part) && !is_string(part))
  {
    args = make_list(func_name, 'part', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(vendor) && !is_string(vendor))
  {
    args = make_list(func_name, 'vendor', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(product) && !is_string(product))
  {
    args = make_list(func_name, 'product', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(version) && !is_string(version))
  {
    args = make_list(func_name, 'version', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(update) && !is_string(update))
  {
    args = make_list(func_name, 'update', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(edition) && !is_string(edition))
  {
    args = make_list(func_name, 'edition', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(language) && !is_string(language))
  {
    args = make_list(func_name, 'language', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(sw_edition) && !is_string(sw_edition))
  {
    args = make_list(func_name, 'sw_edition', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(target_sw) && !is_string(target_sw))
  {
    args = make_list(func_name, 'target_sw', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(target_hw) && !is_string(target_hw))
  {
    args = make_list(func_name, 'target_hw', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }
  if (!isnull(other) && !is_string(other))
  {
    args = make_list(func_name, 'other', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (cpe_ver != "22" && cpe_ver != "22C" && cpe_ver != "23") {
    args = make_list(func_name, 'cpe_ver');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Defaults
  if (empty_or_null(part))
    part = 'a';

  if (version == UNKNOWN_VER)
    version = NULL;

  # If a base CPE was provided, let's get its data!
  if (!empty_or_null(base_cpe))
  {
    base_cpe_data = decode_cpe(base_cpe:base_cpe);
    if (base_cpe_data[0] == IF_OK)
    {
      base_cpe_data = base_cpe_data[1];

      # Now that we in theory have some cpe data, we should check that it lines up with the other info passed
      # After discussion, our current paradigm will be as follows:
      # Data found in the base CPE supercedes data passed as params
      # Example: The base CPE says Version should be 1.01,
      # and the Version param we passed to this func says it should be 1.24,
      # We ignore the Version passed as a param, and go with what was in the CPE (1.01)

      # Populate our new CPE with the data from the base!                                                                
      new_cpe_data[0] = base_cpe_data["part"];
      new_cpe_data[1] = base_cpe_data["vendor"];
      new_cpe_data[2] = base_cpe_data["product"];
      new_cpe_data[3] = base_cpe_data["version"];
      new_cpe_data[4] = base_cpe_data["update"];
      new_cpe_data[5] = base_cpe_data["edition"];
      new_cpe_data[6] = base_cpe_data["language"];

      new_cpe_extended[0] = base_cpe_data["sw_edition"];
      new_cpe_extended[1] = base_cpe_data["target_sw"];
      new_cpe_extended[2] = base_cpe_data["target_hw"];
      new_cpe_extended[3] = base_cpe_data["other"];
    }
    # else, we couldn't parse out any attributes for some reason
  }

  # Fill in the values provided!
  # If we were given specific attribute values, fill them in!
  if (!empty_or_null(part) && contains_element(var:lesser_values, value:new_cpe_data[0]))
    new_cpe_data[0] = part;
  if (!empty_or_null(vendor) && contains_element(var:lesser_values, value:new_cpe_data[1]))
    new_cpe_data[1] = vendor;
  if (!empty_or_null(product) && contains_element(var:lesser_values, value:new_cpe_data[2]))
    new_cpe_data[2] = product;
  if (!empty_or_null(version) && contains_element(var:lesser_values, value:new_cpe_data[3]))
    new_cpe_data[3] = version;
  if (!empty_or_null(update) && contains_element(var:lesser_values, value:new_cpe_data[4]))
    new_cpe_data[4] = update;
  if (!empty_or_null(edition) && contains_element(var:lesser_values, value:new_cpe_data[5]))
    new_cpe_data[5] = edition;
  if (!empty_or_null(language) && contains_element(var:lesser_values, value:new_cpe_data[6]))
    new_cpe_data[6] = language;

  if (!empty_or_null(sw_edition) && contains_element(var:lesser_values, value:new_cpe_extended[0]))
    new_cpe_extended[0] = sw_edition;
  if (!empty_or_null(target_sw) && contains_element(var:lesser_values, value:new_cpe_extended[1]))
    new_cpe_extended[1] = target_sw;
  if (!empty_or_null(target_hw) && contains_element(var:lesser_values, value:new_cpe_extended[2]))
    new_cpe_extended[2] = target_hw;
  if (!empty_or_null(other) && contains_element(var:lesser_values, value:new_cpe_extended[3]))
    new_cpe_extended[3] = other;

  # Next, we need to check for ANYs and NAs and convert them to * and - respectively
  for (var ch = 1, cl = max_index(new_cpe_data); ch < cl; ch++)
  {
    if (preg(string:new_cpe_data[ch], pattern:"^ANY$", icase:TRUE))
      new_cpe_data[ch] = "*";

    if (preg(string:new_cpe_data[ch], pattern:"^NA$", icase:TRUE))
      new_cpe_data[ch] = "-";
  }

  # Check the Extended Attributes too
  for (var ex = 0, exl = max_index(new_cpe_extended); ex < exl; ex++)
  {
    if (preg(string:new_cpe_extended[ex], pattern:"^ANY$", icase:TRUE))
      new_cpe_extended[ex] = "*";

    if (preg(string:new_cpe_extended[ex], pattern:"^NA$", icase:TRUE))
      new_cpe_extended[ex] = "-";
  }

  # Now! We have our data, it's all validated, so lets put together this cpe!

  # Wellll, we really only want to put it all together if we actually have data, so check that first
  have_data = FALSE;
  for (ch = 1, cl = max_index(new_cpe_data); ch < cl; ch++)
  {
    if (new_cpe_data[ch] != "*")
    {
      have_data = TRUE;
      break;
    }
  }

  # Check the extended attributes too
  for (ex = 0, exl = max_index(new_cpe_extended); ex < exl; ex++)
  {
    if (new_cpe_extended[ex] != "*")
    {
      have_data = TRUE;
      break;
    }
  }

  # If we don't actually have any attribute data to make a CPE with, bail
  if (have_data == FALSE)
  {
    return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  }

  # Start assembling our CPE Formatted String!
  if (cpe_ver == "23")
    new_cpe = cpe23_prefix; # CPE 2.3 Formatted String
  else
    new_cpe = cpe22_prefix; # CPE 2.2 URI

  # First, the extended attributes. We do these first because if they'll overwrite Edition in 22C

  # Only 22C and 23 have the extended attributes represented
  if (cpe_ver != "22")
  {
    for (var ext = 0, extl = max_index(new_cpe_extended); ext < extl; ext++)
    {
      if (cpe_ver == "22C")
        new_extended += "~";
      else
        new_extended += ":";

      # URI uses "nothing" to represent unspecified or ANY attributes, so skip
      if (cpe_ver == "22C" && new_cpe_extended[ext] == "*")
        continue;

      new_extended += new_cpe_extended[ext];
      have_ext_attrs = TRUE;
    }

    # if we're making a 22C CPE, store the "packed" extended attributes in the Edition spot!
    if (cpe_ver == "22C" && have_ext_attrs == TRUE)
    {
      if (new_cpe_data[5] != "*")
        new_cpe_data[5] = "~"+new_cpe_data[5]+new_extended;
      else
        new_cpe_data[5] = "~"+new_extended;
    }
  }

  for (var a = 0, al = max_index(new_cpe_data); a < al; a++)
  {
    if (a != 0)
      new_cpe += ":";

    # URI uses "nothing" to represent unspecified or ANY attributes, so skip
    if (cpe_ver != "23" && new_cpe_data[a] == "*")
      continue;

    new_cpe += new_cpe_data[a];
  }

  if (cpe_ver == "23")
    new_cpe = new_cpe + new_extended;

  # Now let's trim off any trailing empty attributes!
  if (cpe_ver != "23")
  {
    # First let's tack on an ending "anchor" of sorts
    new_cpe += "ENDOFCPE";
    # Wait, why not just match to $?
    # Well! that would work for the match, but then when we go to do the substring and grab the index of the match
    # The $ isn't in there (natrually). Meaning if we have correctly empty attributes "::" those will get picked up by
    # stridx and would incorrectly be cut out

    match = pregmatch(string: new_cpe, pattern: ":*ENDOFCPE");
    if (!isnull(match))
      new_cpe = substr(new_cpe, 0, stridx(new_cpe, match[0]) - 1);
  }

  # Put it all together and ship it!
  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = new_cpe;
  return ret;
}

##
# Parses a given CPE URI or Formatted String into an array of values for easy managing
#
# @param  [base_cpe:string]  OPTIONAL  A CPE URI string to parse
#
# @return an Array of key:value pairs representing the data described by the CPE
##
function decode_cpe(base_cpe)
{
  var func_name = "decode_CPE";

  var cpe22_prefix = "cpe:/";
  if ('x-cpe' >< base_cpe) cpe22_prefix = "x-cpe:/";

  var cpe23_prefix = "cpe:2.3:";
  if ('x-cpe' >< base_cpe) cpe23_prefix = "x-cpe:2.3:";

  var packed_pattern = "(~([^~])*){5}";
  var match, args, base_attrs, packed_attrs, unpacked_attrs, ret;
  var valid_cpe_regex = "([xX]-)?[cC][pP][eE]:(\/([AHOaho]?(:[A-Za-z0-9\s\._\-~%]*){0,6})|2.3:[AHOaho]?(:[A-Za-z0-9\s\*\._\-~%]+){10})";
  var cpe_data = { # Our basic CPE data template!
    "cpe_ver":    "*", # Either cpe:/ or cpe:2.3:
    "part":       "*",
    "vendor":     "*",
    "product":    "*",
    "version":    "*",
    "update":     "*",
    "edition":    "*", # (Legacy)
    "language":   "*",
    "sw_edition": "*", # (CPE 2.3)
    "target_sw":  "*", # (CPE 2.3)
    "target_hw":  "*", # (CPE 2.3)
    "other":      "*"  # (CPE 2.3)
  };
  var data_index = make_list(
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other"
  );

  if (empty_or_null(base_cpe))
  {
    args = make_list(func_name, 'base_cpe');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Check if were provided a valid CPE (if any)
  if (!isnull(base_cpe))
  {
    if (!is_string(base_cpe))
    {
      args = make_list(func_name, 'base_cpe', 'string');
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }

    match = pregmatch(string:base_cpe, pattern:valid_cpe_regex);
    if (isnull(match))
    {
      args = make_list(func_name, 'base_cpe');
      return make_list(return_error(IF_PARSE_ERROR_TEMPLATE, args));
    }
  }

  # If the cpe prefix is dedected, remove it

  if (cpe22_prefix >< substr(base_cpe, 0, strlen(cpe22_prefix)))
  {
    cpe_data["cpe_ver"] = "22"; # Store the CPE version!
    base_cpe = substr(base_cpe, strlen(cpe22_prefix));
  }

  if (cpe23_prefix >< substr(base_cpe, 0, strlen(cpe23_prefix)))
  {
    cpe_data["cpe_ver"] = "23"; # Store the CPE version! 
    base_cpe = substr(base_cpe, strlen(cpe23_prefix));
  }

  # okay, so! Before we can split out the attributes we need to check if there are any blank ones
  # For CPE 2.2, we can see cpe:/a:hp:openview_network_manager:7.51::~~~linux~~ Where "::" denotes a blank value
  base_cpe = str_replace(string:base_cpe, find:"::", replace:":*:");

  # Split out the attrs                                                                                               
  base_attrs = split(base_cpe, sep:':', keep:FALSE);

  if (!empty_or_null(base_attrs[0]))
    cpe_data["part"] = base_attrs[0];

  for (var i = 1, il = max_index(base_attrs); i < il; i++)
  {
    if (!empty_or_null(base_attrs[i]) && base_attrs[i] != "*")
    {
      # For compatibility, we may see CPE2.2 names that include "packed" extra values
      # Looks like ~Edition~SW_Edition~Target_SW~Target_HW~Other
      # Must always have all 5 '~'s, so if we only have some attributes it'll look something like:
      # ~~~linux~~ (Here we only have a Target_SW value
      # All the Packed atributes take place of the value of Edition, so we'll need to check as we parse the attrs                               

      match = pregmatch(string:base_attrs[i], pattern:packed_pattern, icase:FALSE);

      # If we indeed have packed attributes, we'll need to unpack and process them!                                       
      if (cpe_data["cpe_ver"] != 23 && !isnull(match))
      {
        #update the cpe_ver to 22c
        cpe_data["cpe_ver"] = "22C";
        packed_attrs = base_attrs[i];
        packed_attrs = substr(packed_attrs, 1);

        # Fill out any empty values with *s. Want everything to have a value for easy processing                          
        #packed_attrs = str_replace(string:packed_attrs, find:"~~", replace:"~BLANK~");

        # The last ~ too! if there's now value, it'll just be ~
        #if (packed_attrs[strlen(packed_attrs)-1] == '~')
        #  packed_attrs += "BLANK";

        unpacked_attrs = split(packed_attrs, sep:'~', keep:FALSE);

        # Edition
        if (!empty_or_null(unpacked_attrs[0]) && unpacked_attrs[0] != "*" && unpacked_attrs[0] != "~")
          cpe_data["edition"] = unpacked_attrs[0];
        # sw_edition
        if (!empty_or_null(unpacked_attrs[1]) && unpacked_attrs[1] != "*" && unpacked_attrs[1] != "~")
          cpe_data["sw_edition"] = unpacked_attrs[1];
        # target_sw                                                                                                   
        if (!empty_or_null(unpacked_attrs[2]) && unpacked_attrs[2] != "*" && unpacked_attrs[2] != "~")
          cpe_data["target_sw"] = unpacked_attrs[2];
        # target_hw
        if (!empty_or_null(unpacked_attrs[3]) && unpacked_attrs[3] != "*" && unpacked_attrs[3] != "~")
          cpe_data["target_hw"] = unpacked_attrs[3];
        # other
        if (!empty_or_null(unpacked_attrs[4]) && unpacked_attrs[4] != "*" && unpacked_attrs[4] != "~")
          cpe_data["other"] = unpacked_attrs[4];
      }
      else # Regular non-packed attribute, so carry on as normal!
      {
        cpe_data[data_index[i]] = base_attrs[i];
      }
    }
  }

  # Before we wrap up, lets convert *s to ANY and -s to NA
  for (i=0, il=max_index(data_index); i<il; i++)
  {
    if (cpe_data[data_index[i]] == "*")
      cpe_data[data_index[i]] = "ANY";

    if (cpe_data[data_index[i]] == "-")
      cpe_data[data_index[i]] = "NA";
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = cpe_data;
  return ret;
}

