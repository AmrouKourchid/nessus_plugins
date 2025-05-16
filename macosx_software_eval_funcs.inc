#TRUSTED 4349f109cb8c028fe4ae80364289f5258c57675b90aab9c4167905189692e79abada88f81aceb27ed6bef2861442bbc43fbdf537de088f99335b18982cdb1d65d72f5b0efb134c1a29b8e278cf5ae8ce329c85d363c593bb70eaf0728f15a07a4df2ae0835494f2de750b835b3cce37f0f3000a25d9e204a4cc03f0037cf99bc5d7143ce0a643adf300aedf57d1e75aed1d03904a115ea4cd12b90a7ae119b6a77d70f6b6936fbede1c81c04fc1e39c265aac2d0de3b372f6715635d7f5d2a970ba5152a14f2457b9f129daef04204c092464e1af462051ae184e0507ccf9f5fbba6308a6387e9f45cbb843734eaa7ff3a70e10c40614f53d0f8310d01dcfb8fbc643fd676c30bcefd42d31ac2d9fbc0d8f97afe4685600d1b0e16d47bf31ea29886b0b779494e9bd007de807736bb12f899ba6cfd88a8b9112c90fbf0b32d3e902c5ecc4aab1da9233de8db7e21f2ab5dbc2890c1a5db46577523ca76ec988a9ed1bdd1acc4cbaab4e200d2e4f09d031fbf3e8bbc3325f66da28e0e62ae45fa58d5bd6b1f720761860851bb6a2400597b87c8f7d26491dc758b097a645422b60fdef47f0bd0a41fabf5b13e974c5bd62eacaf67d748173544eb4e881f22274195f6be23b24e1326745da8c3e6540b72f2032180f98ac5c8173c9faf531076e9bc7e8a1a14bc308f7e57e787a3f45ac11799c0404744c785413900dfe2f844c5
#TRUST-RSA-SHA256 84d70242da80765d09daa92d3e5b4d481efb9631694685dbbddefc47ef8b045260f360faf96d6323245b5b6105361717230ea70e86b89385563eb2711c757fcad65929bbb4b5174b7041fa9ca5aad6236159edc2fa6ed87096241adc804735184e9900417038db80336abdf8c7e5a5d130cdad4a7cc9bb8c158335033ebf473d93ab25e9435b1d82813ad6890157fd34d656f989633686f1b78beb1143dc4cfc3e2ee1546cae65ef7f054a98b281c20f0e083a5211db4f0f7f9a810a0773b57e36728197a8c5d39f998b1e91c07e44cd9301bfcbe806a3073b3ddd451edcb92725f60ed9492f6e13012578ae39eeaffa51dcb220e0219e5087fd87fa30d64a0a9c6f8570d54a9ddd6c807ecbf82d4b79f1167347c569b1922d94152591e4e1c95b1114c403a0faf80a924cd91fb0f3c1ecb90de54f5f15f2b283a881bfca192b7fc529dfd9c47fdc760ed921124fa054cda5acc57cee65af02a1aadd3e85a9d8cede2bbe13261bac23b91e69463591f07f155eee7383cacc2eccbc2b7e947d1fa8a1367e3934470900981564af9d6ec515277bb77c7196df7b0f22b2f1b949c6f98830bf0263788402777f571f37ac00c22f72d0bce821d6e5683e321859628f09dc6a8545078d0117529190d377dcf29b28601bdb377addfc8bc097e742c2bf9095d7abfb7704ff37aaa735c3e369c27781af65760f8cea42a8cd6c273e9aeb
###
# MacOS software enumeration functions.
#
# @license
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.22
###

include("compat_shared.inc");
include("install_func.inc");

##
# Check system_profiler, homebrew, or macports package name against an array of whitelisted
# regex patterns
#
# @param  [package:string] Package to check against whitelist.
# @param  [skip:list] List of regex patterns to skip from consideration in package name.
# @remark  arguments are "skip". This function will check system_profiler, homebrew, or
# @remark  macports package name against an array of whitelisted regex patterns.
#
# @return [bool] Returns ``TRUE`` if package is in the skip array and ``FALSE`` if not.
##
function osx_check_whitelist(package, skip)
{
  local_var bl;

  # Check whitelist array to skip package
  foreach bl (skip)
  {
    if (!isnull(package) && package =~ bl)
    {
      return TRUE;
    }
  }
  return FALSE;
}

##
# Get enumerated software from applications KB cache.
#
# @return [list|NULL] List of arrays of enumerated software and associated data.
##
function osx_get_enumerated_software()
{
  var sys_profiler = get_kb_item("MacOSX/packages/sys_profiler");
  if (isnull(sys_profiler)) return NULL;

  var applications = split(sys_profiler, sep:"|", keep:false);
  if (isnull(applications)) return NULL;

  var software = [];

  foreach var app_record (applications)
  {
    var name = NULL;
    var version = NULL;
    var location = NULL;
    var signed_by = NULL;
    var match = NULL;

    match = pregmatch(pattern:'^Application: (.+?)(?: \\(Preview\\))?\\037', string:app_record, icase:true);

    # RES-70660: Exclude the apps registered by Parallels Desktop under ~/Application (Parallels)/
    # RES-173430: Also exclude the apps that look like Parallels Desktop specifically under CloudStorage such as OneDrive.
    if (!empty_or_null(match) && !empty_or_null(match[1]) && app_record !~ "Location:\s+/Users/[0-9a-z-A-Z]+(/Library/CloudStorage/.*?)?/Applications \(Parallels\)/")
    {
      name = match[1];

      match = pregmatch(pattern:"Version: (.*?)\037", string:app_record, icase:true);
      if (!empty_or_null(match) && !empty_or_null(match[1]))
      {
        # Versions may appear surrounded by " "
        version = trim(match[1], chars:' "');
      }

      match = pregmatch(pattern:"Location: (.*?)\037", string:app_record, icase:true);
      if (!empty_or_null(match) && !empty_or_null(match[1]))
      {
        location = match[1];
      }

      match = pregmatch(pattern:"Signed by: (.*?)\037", string:app_record, icase:true);
      if (!empty_or_null(match) && !empty_or_null(match[1]))
      {
        signed_by = match[1];
      }

      append_element(var:software, value:{
        application: name,
        version: version,
        location: location,
        signed_by: signed_by
      });
    }
  }

  return software;
}

##
# Find a managed package as seen by system_profiler, homebrew, or macports
#
# @param  [package:string] Package to search for and register
# @param  [vendor:string|NULL] Vendor name to register with ``register_install()``
# @param  [product:string|NULL] Product name to register with ``register_install()``
# @param  [cpe:string|NULL] CPE to register with ``register_install()``
# @param  [icase:bool|NULL] Search for package case insensitive (Optional, defaults to TRUE)
# @param  [register_install_kb:bool|NULL] Whether to register with ``register_install()`` (Optional, defaults to TRUE)
# @param  [partial:bool|NULL] Search for partial package matches
# @param  [preview:bool|NULL] Search for for the 2022 preview package matches
# @param  [starts_with:bool|NULL] Search for package matches that start with the arg (Optional, defaults to FALSE)
# @param  [single:bool|NULL] Save everything under the passed package name (Optional, defaults to FALSE)
# @param  [extra_no_report:array|NULL] Array keys must be strings, values may be strings, ints or lists. Not included in report.
# @param  [extra:array|NULL] Array keys must be strings, values may be strings, ints or lists. Included in report.
# @param  [install_name:string|NULL] Name to use when calling ``register_install()``. Requires single = TRUE. (Optional, defaults to package if not provided)
# @param  [skip:list|NULL] List of regex patterns to skip from consideration in package name
# @param  [fa_app_name:string|NULL] App name for frictionless agents
#
# @remark  arguments are "package", "cpe", and "icase". This function will search for a
# @remark  package in the named var, and if found, returns a list of everything matching
# @remark  the pattern in "package" and registers the install.
#
# @remark if register_install_kb is set to FALSE, this function will store the findings in an array 
# @remark called found_installs with each new path found being a key and will return this array instead
#
# @return [list|array|bool|NULL]  Returns a list of all packages found, FALSE if not found, NULL for anything else if register_install_kb is TRUE (default)
#                                 Returns an array of all matching applications found if register_install_kb is FALSE, or FALSE if not found
##

function osx_find_installs(package, vendor, product, cpe, icase, partial, preview, starts_with, single, extra_no_report, extra, install_name, skip, fa_app_name, register_install_kb)
{
  local_var return_val,pkg_app,pkg_version,pkg_location,sys_pkg,port_pkg;
  local_var AppPattern,package_list,pkg_record,pkg_field,field,pkg_count;
  local_var brew_pkg,found_packages,found_installs,func_name;
  local_var application_attributes,app_attribute,app_attr_match,extra_NR,args;

  func_name = 'osx_find_installs';

  return_val = NULL;
  found_packages = make_list();
  found_installs = {};
  if (isnull(package))
  {
    err_print('osx_find_installs(): missing required arg : "package"');
    return NULL;
  }

  if (isnull(icase)) icase = TRUE;
  if (isnull(partial)) partial = FALSE;
  if (isnull(starts_with)) starts_with = FALSE;
  if (isnull(preview)) preview = FALSE;
  if (isnull(single)) single = FALSE;
  if (isnull(install_name)) install_name = package;
  if (isnull(skip)) skip = [];
  if (isnull(register_install_kb)) register_install_kb = TRUE;

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }
  if (isnull(extra_no_report)) extra_no_report = make_array('os', 'mac');
  if(isnull(extra)) extra = {};

  sys_pkg = get_kb_item_or_exit("MacOSX/packages/sys_profiler");
  brew_pkg = get_kb_item("MacOSX/packages/homebrew");
  port_pkg = get_kb_item("MacOSX/packages/macports");

  # Process applications found by system_profiler first - this should always be populated,
  # if not then something has gone horribly wrong, stop here, do not pass GO.
  # redundant or just being safe?
  if (isnull(sys_pkg)) return NULL;

  package_list = split(sys_pkg, sep:"|", keep:FALSE);
  if (isnull(package_list)) return NULL;

  if (partial)
    AppPattern = '^Application: (.*?'+package+'.*?)\\037';
  else if (starts_with)
    AppPattern = '^Application: ('+package+'.*?)\\037';
  else if (preview)
    AppPattern = '^Application: ('+package+') \\(Preview\\)';
  else
    AppPattern = '^Application: ('+package+')\\037';

  pkg_count = 0;

  foreach pkg_record (package_list)
  {
    # grab extra_no_report as passed to function or default os => mac
    extra_NR = extra_no_report;

    pkg_app = NULL;
    pkg_version = NULL;
    pkg_location = NULL;

    pkg_count++;
    pkg_app = pregmatch(pattern:AppPattern, string:pkg_record, icase:icase);

    # RES-70660: Exclude the apps registered by Parallels Desktop under ~/Application (Parallels)/
    # RES-173430: Also exclude the apps that look like Parallels Desktop specifically under CloudStorage such as OneDrive.
    if (!empty_or_null(pkg_app) && !empty_or_null(pkg_app[1]) && pkg_record !~ "Location:\s+/Users/[0-9a-z-A-Z]+(/Library/CloudStorage/.*?)?/Applications \(Parallels\)/")
    {
      # Check package name against user provided whitelist
      if (osx_check_whitelist(package:pkg_app, skip:skip)) continue;

      pkg_location = pregmatch(pattern:"Location: (.*?)\037", string:pkg_record, icase:TRUE);
      pkg_version = pregmatch(pattern:"Version: (.*?)\037", string:pkg_record, icase:TRUE);

      if (empty_or_null(pkg_version) || empty_or_null(pkg_version[1]))
        pkg_version[1] = "unknown";
      if (empty_or_null(pkg_location) || empty_or_null(pkg_location[1]))
        pkg_location[1] = "/Unknown" + pkg_count + "/";

      # versions may appear surrounded by " "
      pkg_version[1] = trim(pkg_version[1], chars:' "');

      # Take rest of the attributes returned by system_profiler and store them in extra_no_report
      application_attributes = split(pkg_record, sep:raw_string(0x1F), keep:FALSE);
      if (!empty_or_null(application_attributes))
      {
        foreach app_attribute (application_attributes)
        {
          if ((app_attribute !~ "^Application: ") &&
             (app_attribute !~ "^Version: ") &&
             (app_attribute !~ "^Location: "))
          {
            app_attr_match = pregmatch(pattern:"(.*?): (.*)",string:app_attribute);
            if (!empty_or_null(app_attr_match))
              extra_NR[app_attr_match[1]] = app_attr_match[2];
          }
        }
      }
      if (register_install_kb == TRUE)
      {
        if (single)
        {
          extra_NR["name"] = pkg_app[1];
          register_install(
            app_name:install_name,
            vendor:vendor,
            product:product,
            path:pkg_location[1],
            version:pkg_version[1],
            cpe:cpe,
            fa_app_name:fa_app_name,
            extra_no_report:extra_NR,
            extra:extra
          );
        }
        else
          register_install(
            app_name:pkg_app[1],
            vendor:vendor,
            product:product,
            path:pkg_location[1],
            version:pkg_version[1],
            cpe:cpe,
            fa_app_name:fa_app_name,
            extra_no_report:extra_NR,
            extra:extra
          );
      }
      else
      {
        # If register_install_kb is FALSE, store the app details in the found_installs list
        found_installs[pkg_location[1]]['path'] = pkg_location[1];
        found_installs[pkg_location[1]]['version'] = pkg_version[1];
      }
      found_packages = list_uniq(make_list(found_packages,pkg_app[1]));
    }
  }

  if (max_index(found_packages) == 0)
    return_val = FALSE;
  else
    return_val = found_packages;

  # Process applications found and managed by homebrew
  if (!isnull(brew_pkg))
  {
    package_list = split(brew_pkg,sep:"|", keep:FALSE);

    foreach pkg_record (package_list)
    {
      # grab extra_no_report as passed to function or default os => mac
      extra_NR = extra_no_report;

      pkg_app = NULL;
      pkg_location = NULL;
      pkg_version = "unknown";

      pkg_field = split(pkg_record, sep:' ', keep:FALSE);

      if (empty_or_null(pkg_field)) continue;

      #counter to use for paths in case its not registered correctly
      pkg_count++;
      pkg_app = pkg_field[0];
      pkg_version = pkg_field[1];

      # if package is found, then location is in the location
      # MacOSX/homebrew/cellar"+"/"+pkg_app+pkg_version
      # $ brew info openssl | grep $Cellar
      #   /usr/local/Cellar/openssl/1.0.1j_1 (431 files, 15M)

      if (preg(string:pkg_app,pattern:package, icase:icase))
      {
        # Check package name against user provided whitelist
        if (osx_check_whitelist(package:pkg_app, skip:skip)) continue;

        pkg_location = get_kb_item("MacOSX/homebrew/cellar");
        if (!empty_or_null(pkg_location))
          pkg_location = pkg_location + "/" + pkg_app + "/" + pkg_version;
        else
          pkg_location = "Unknown" + "/";

        if (register_install_kb == TRUE)
        {
          if (single)
          {
            extra_NR["name"] = pkg_app;
            register_install(
              app_name:install_name,
              vendor:vendor,
              product:product,
              path:pkg_location,
              version:pkg_version,
              cpe:cpe,
              extra_no_report:extra_NR,
              extra:extra
            );
          }
          else
            register_install(
              app_name:pkg_app,
              vendor:vendor,
              product:product,
              path:pkg_location,
              version:pkg_version,
              cpe:cpe,
              extra_no_report:extra_NR,
              extra:extra
            );
        }
        else
        {
          # If register_install_kb is FALSE, store the app details in the found_installs list
          found_installs[pkg_location]['path'] = pkg_location;
          found_installs[pkg_location]['version'] = pkg_version;
        }

      # Append to found_packages list
      found_packages = list_uniq(make_list(found_packages,pkg_app));
      } 
    }

    # return_val is defaulted to FALSE, so if found_packages is already
    # defined and populated, simply update the return_val
    if (max_index(found_packages) != 0)
      return_val = found_packages;

  } # End homebrew processing

  # Process applications found and managed by MacPorts
  if (!isnull(port_pkg))
  {
    package_list = split(port_pkg,sep:"|", keep:FALSE);

    foreach pkg_record (package_list)
    {
      # grab extra_no_report as passed to function or default os => mac
      extra_NR = extra_no_report;

      pkg_app = NULL;
      pkg_location = NULL;
      pkg_version = NULL;

      pkg_field = split(pkg_record, sep:' ',keep:FALSE);

      if (empty_or_null(pkg_field)) continue;

      if (preg(string:pkg_field[0],pattern:package,icase:icase))
      {
        # Check package name against user provided whitelist
        if (osx_check_whitelist(package:pkg_field[0], skip:skip)) continue;

        # we only look for macports in the default location at this point
        pkg_location = "/opt/local";

        # The version in pkg_field[1] may be in the format
        #  @5.12.4_0+perl5_16 where the 'variant' after the '+'
        # is optional

        pkg_version = pregmatch(string:pkg_field[1],pattern:"^@([^+]+)(\+(.+))?$",icase:TRUE);
        if (empty_or_null(pkg_version))
          pkg_version = "unknown";

        if (!empty_or_null(pkg_version[3]))
          extra["Variant"] = pkg_version[3];
        else
          extra["Variant"] = "None";

        pkg_app = ereg_replace(pattern:"^\s*([^\s].*[^\s]|[^\s])\s*$", replace:"\1", string:pkg_field[0]);

        if (register_install_kb == TRUE)
        {
          if (single)
          {
            extra_NR["name"] = pkg_app;
            register_install(
              app_name:install_name,
              vendor:vendor,
              product:product,
              path:pkg_location,
              version:pkg_version[1],
              extra:extra,
              cpe:cpe,
              extra_no_report:extra_NR
            );
          }
          else
            register_install(
              app_name:pkg_app,
              vendor:vendor,
              product:product,
              path:pkg_location,
              version:pkg_version[1],
              extra:extra,
              cpe:cpe,
              extra_no_report:extra_NR
            );
        }
        else
        {
          # If register_install_kb is FALSE, store the app details in the found_installs list
          found_installs[pkg_location]['path'] = pkg_location;
          found_installs[pkg_location]['version'] = pkg_version[1];
        }
        # Append to found packages list
        found_packages = list_uniq(make_list(found_packages,pkg_field[0]));
      }
    }

    if (max_index(found_packages) !=0)
      return_val = found_packages;

  } # End MacPorts processing
  if (register_install_kb == FALSE && !empty_or_null(found_installs))
    return found_installs;
  else
    return return_val;
}
