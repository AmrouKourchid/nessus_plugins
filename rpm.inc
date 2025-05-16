#TRUSTED 651c42ea1dc18f0c449f282bcc19a89d3f5ca65abb16dd418d04a293002587405133ce345d94b915897adf149cb11640c1eebf2e20ce37931ba25d73a5c4cdd60fea4faea38dbbdbc606f0d53ff6ea11ea0268a79381769a62bacdba752f886077230e4733e3905e1fca51562fce12faff1767592df57759fef9ff73e6ce6f80cede57d52822d4a4659ce8b4a960eb698861d41873401643bd0f08939769711ac34c9f2db4427c09be1f9c69406fbc25427b90cc9783adb93c5b77b4cc00b41ca4f97124779c918d3ec751a370ee3d31e80fe4124781c488b3fdd2d7a4af6d357b8a92885bfd5acd93a09268c4f60afde48cafa28144dca908b90ea4caaefe09704718fe436d3e8eabf8fc489a9b462dd2789cb8b057e927cac71624f2cebf9f5ea9d76757e2fd368b3ff6c2631adf7530eee196bab606fef3282620280c3c58ba694e23d9fb84307713d972086408ff9f32270dbfa065bd7fa2e384ec3c33f7ed183e404456664f8782eac52d88245e38eec4280ead4c491fe5a57784df3873884e4bdddb9124857f568af8b77a11d45c66cf96897187544d9457fee30e6d98d72ccdf6de64b068430a6bb39f171f71185119928011822ceea28f1647d43f136d4180b984ad04910b2886edbf1aa53cb441e5ec9d1949528205b3736b39d5c47e5e192d38678f2c380e2e963ed3c12031d1773826dd2af48a20abc606340301
#TRUST-RSA-SHA256 1651d08d282ae02a6d95d5886b193192a7ef6b3b50a9250770be4363c26770c21f28a8aa4652a2822d87b17dcf525816a0a58cbf8f706508c7642c294af3742b7539c4e26dd9e626824007363add385dd95129d5593b3884eb331865366f82637753093b7a817832788401915ea506a409b2d7f142307909425728e86c52b0d631c5a3d533460ee33853ea0b261ef283677941fb35e52d9577e851b33c0300bd683461f36338c8f0ff1da0b040f6a387979cc167a6429f324f474049cfb8044e1e9833581fadf8649cde221610abd9b500bafccd3ac103bbf436f2daef70a1d7bb2a4e5065b10286938b8c2f9aabd5371100d79998f195fd99ffd9e54e6a845faa30fd994dbc4254ec41f945d2e73d42207ac9eec0f03178a3c815b5d6a87c6bfb21a8a24917686ffa7f5ffff18efa477bc6ec4ac7186518ecaf99e02b580ba97fbe3c29255f64857ea11eb2ff555f0331a2d9fe664f4c48b0325516db614a7428b33cbb8dfabeb8cdf9f903d23f7507b28da9eb6d89804374b817f931339c91754973bdfd0bad06307adf7e3979af2161a4a82a32c1bfcccc9d038aa42fc3f24b6bdc60c75a60b636dc9d7449de89ab3d0a96166f0064af6275e094be021915664fec89c0a230ec5cb78a997a073dba07418a0cb249b1fdd802163d8e57be844e26d8cc6cb53a857fc7684cbfe2065fdc0039087bda02cbc466f06797e6044a
# -*- Fundamental -*-

###
# Functions supporting RPM based package checks
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# rpm.inc
# Revision: 1.163
#
###

include("compat_shared.inc");
include_if("patch_log.inc", 80502);
include_if("patch_globals.inc", 80502);
include("os_security_patch_funcs.inc");
include("url_func.inc");
include("structured_data.inc");
include("lists.inc");

# Internal use globals 
global_var __pkg_tests, __rpm_report, __unpatched_packages, __rpm_report_obj;
##
# List storage of all remote packages found and checked
##
__pkg_tests = [];

##
# String containing all affected package reporting
##
__rpm_report = '';

##
# Structured report object
##
__rpm_report_obj = NULL;


##
# List storage of all remote packages found and checked
##
__unpatched_packages = [];

##
# Array containing parsed list of rpm-list lines by packagename;
##
global_var __rpm_list_array = NULL;

##
# Flag for determining which vers_cmp function to use
##
global_var rpm_spec_vers_cmp_flag = FALSE;

##
# Regex pattern for checking for architecture patterns to remove from uname -r
##
global_var __arch_pat = "(\.(x86_64|i[3-6]86|s390x?|aarch64|arm(64)?|ia64))$";

##
# Exit message to use if applicable repo/extras is not enabled
##
global_var AFFECTED_REPO_NOT_ENABLED = 'The repositories impacted by this advisory ' + '\n' +
'were not found to be enabled on this host.';

##
# Regex pattern for checking for packages which, although not marked as kernel,
# are kernel modules and require being treated as kernel packages for fixups.
##
var __extra_kernel_packages_pattern = "^dlm-kmp-default-";

##
# Changes rpm-list so that only a single copy of each package that
# begins with "kernel-", the latest, appears in the rpm-list
#
# @anonparam [First:list] rpms, joined with newlines as in most rpm-list KB entries
#
# @remark Only applies to kernel packages, and any packages indicated in
#         __extra_kernel_packages_pattern.
#
# @return [string] Revised copy of rpm-list with only the latest kernel packages
##
function fixup_rpm_list()
{
  local_var lines, line;
  local_var ret;
  local_var key;
  local_var array;
  local_var rpm;
  local_var kernel_maj_min;
  local_var maj_min;

  kernel_maj_min = split(get_kb_item("Host/uname/major_minor"), sep:'.', keep:FALSE);

  lines = split(_FCT_ANON_ARGS[0], keep:FALSE);
  foreach line ( lines )
  {
    if (preg(string:line, pattern:"^(vz)?kernel-") ||
       ( !isnull(__extra_kernel_packages_pattern) &&
       preg(string:line, pattern:__extra_kernel_packages_pattern))
    )
    {
      rpm = parse_rpm_name(rpm:line);
      # If the version doesn't begin with #.#, skip attempting to match the major/minor
      if(!isnull(kernel_maj_min) && max_index(kernel_maj_min) > 0 &&
         preg(string:rpm["version"], pattern:"^\d+\.\d+"))
      {
        maj_min = split(rpm["version"], sep:'.', keep:FALSE);
        if ( maj_min[0] != kernel_maj_min[0] || maj_min[1] != kernel_maj_min[1]) continue;
      }

      if ( isnull(array[rpm["name"]])) array[rpm["name"]] = line;
      else
      {
        if ( rpm_cmp(rpm:line, reference:array[rpm["name"]], check_epoch:TRUE, rc_precedence:FALSE) > 0 )
        {
          array[rpm["name"]] = line;
        }
      }
    }
    else ret += line + '\n';
  }

  foreach key ( keys(array))
  {
    ret += array[key] + '\n';
  }
  return ret;
}

##
# Parses rpm-list so that an array is created where the packagename
# key points to a list of applicable rpm-list package lines
#
# @param [rpms:list] rpms, joined with newlines as in most rpm-list KB entries
#
# @remark Edits contents of __rpm_list_array
#
# @return [NULL] NULL
##
function populate_rpm_list_array(rpms)
{
  local_var lines, package, my_rpm, package_name, tmp;
  if (isnull(rpms) || !strlen(rpms)) return NULL;
  lines = split(rpms, sep:'\n', keep:0);
  __rpm_list_array = make_array();
  foreach package (lines)
  {
    # TMUX can add extra newline chars to command outputs, specifically to the rpm-list
    # empty_or_null check to make sure we are not trying to add empty lines to __rpm_list_array 
    if (!empty_or_null(package))
    {
      my_rpm = parse_rpm_name(rpm:package);
      package_name = os_security_patch::regex_sanitize_package_name(my_rpm["name"]);
      if (isnull(__rpm_list_array[package_name]) || (isnull(max_index(keys(__rpm_list_array[package_name])))))
      {
        __rpm_list_array[package_name] = [package];
      }
      else
      {
        # The following doesn't work yet. One day it might.
        # append_element(var:__rpm_list_array[package_name], value:package);
        # Until then, this is messy, but works and is faster than make_list()
        tmp = __rpm_list_array[package_name];
        append_element(var:tmp, value:package);
        __rpm_list_array[package_name] = tmp;
      }
    }
  }
  return NULL;
}

##
# Returns list of matching package from key in __rpm_list_array
#
# @param [package_name:string] package name to return matching rpm lines for
#
# @remark Relies on __rpm_list_array being constructed previously
#
# @return [NULL|list] NULL if no package_name or no matching package names exist in __rpm_list_array or
#         list of rpm lines associated with package_name
##
function fetch_rpm_lines(package_name)
{
  if (isnull(package_name) || !strlen(package_name)) return NULL;
  if (isnull(__rpm_list_array) || (isnull(max_index(keys(__rpm_list_array))))) return NULL;
  if (isnull(__rpm_list_array[package_name]) || (isnull(max_index(keys(__rpm_list_array[package_name]))))) return NULL;
  return __rpm_list_array[package_name];
}

##
# If string begins with "rhel#" (insensitive) change it to "el"
#
# @anonparam [First:string] from part of an rpm version string
#
# @return [string] anonymous parameter with "rhel" changed to "el" if it began with "rhel#"
##
function filter_rh_inconstency()
{
 local_var a;
 a = _FCT_ANON_ARGS[0];
 if ( tolower(a) =~ "^rhel[0-9.]+$" )
  a = ereg_replace(pattern:"^rhel", replace:"el", string:a, icase:TRUE);

 return a;
}

##
# Adds package to __pkg_tests list
#
# @anonparam [First:string] A full rpm name from target system
##
function pkg_tests_add()
{
 local_var array;
 array = split(chomp(_FCT_ANON_ARGS[0]), sep:'|', keep:FALSE);
  __pkg_tests = make_list(__pkg_tests, array[0]);
}

##
# Sorts and uniques entries in __pkg_tests list, returns as string
#
# @return [list] Sorted, unique list of rpms from __pkg_tests in a string separated by " / "
##
function pkg_tests_get()
{
  local_var p, s, pkg_tests_unique, pkg_tests_array, package;

  if (max_index(__pkg_tests) == 0) return NULL;
  pkg_tests_array = make_array();
  pkg_tests_unique = make_list();
  foreach package (__pkg_tests)
    if (!pkg_tests_array[package]++) pkg_tests_unique = make_list(pkg_tests_unique, package);
  pkg_tests_unique = sort(pkg_tests_unique);

  s = "";
  foreach p (pkg_tests_unique)
    s += " / " + p;
  return substr(s, 3);
}


##
# Adds package name to __unpatched_packages list
#
# @anonparam [First:string] A package name from target system
# @anonparam [Second:list] CVEs relevant to the checked package
# @return [NULL] NULL
##
function unpatched_packages_add()
{
  var package = _FCT_ANON_ARGS[0];
  var cves = _FCT_ANON_ARGS[1];

  if(isnull(cves))
    cves = [];

  if (!empty_or_null(package) && typeof_ex(cves) == "list")
    append_element(var:__unpatched_packages, value:[package, cves]);

  return NULL;
}


##
# Comparator function for __unpatched_packages array.
#
# @anonparam [First:list]  An __unpatched_packages 2-tuple [package, [cves]]
# @anonparam [Second:list] An __unpatched_packages 2-tuple [package, [cves]]
#
# @return [int] Returns 1 if First package name is < Second's package name; 0 otherwise
##
function pkg_lt()
{
  return _FCT_ANON_ARGS[0][0] < _FCT_ANON_ARGS[1][0];
}

##
# Sorts and uniques entries in __unpatched_packages, returns as bulleted multiline string
#
# @return [list] Sorted, unique list of [package, [cves]] 2-tuples
##
function unpatched_packages_get()
{
  var p, s, unpatched_packages_unique, package;

  if (max_index(__unpatched_packages) == 0)
    return NULL;

  unpatched_packages_unique = collib::remove_duplicates(__unpatched_packages);
  unpatched_packages_unique = collib::merge_sort(unpatched_packages_unique, comparator:@pkg_lt);

  return unpatched_packages_unique;
}


##
# Produces unpatched packages report text and reports as structured data for atomic findings.
#
# @return [string] Unpatched package reporting string
##
function unpatched_packages_report()
{
  var output = 'The following packages were identified as being present on the remote host:\n';
  var packages, package, cves, p_name;
  var pkg_list = [];

  packages = unpatched_packages_get();

  foreach package(packages)
  {
    p_name = package[0];
    cves = package[1];

    if(!empty_or_null(cves))
      rpm_structured_report(package:p_name, cves:cves);

    append_element(var:pkg_list, value:p_name);
  }

  report_structured_data();

  foreach p_name (pkg_list)
    output += ' - ' + p_name + '\n';

  return output;
}


##
# Adds text to to __rpm_report string indicating an affected package
#
# @param [package:string] Affected package install string
# @param [reference:string] Fixed package install string
##
function rpm_report_add(package, reference)
{
 local_var array;
 array = split(package, sep:'|', keep:FALSE);
 package = array[0];
 __rpm_report += 'Remote package installed : ' + package + '\n' +
                 'Should be                : ' + reference + '\n\n';
}

##
# Build the structured report object
#
# @param [package:string] The detected version of the package
# @param [reference:string] The fixed version of the package (optional)
# @param [epoch:string] The epoch for the fixed package (optional)
# @param [arch:string] The architecture that this specific check was for (optional)
# @param [cves:list] CVEs relevant to the checked package
##
function rpm_structured_report(package, reference, epoch, arch, cves)
{
  var fixed_obj, fix_purl, fixed_version;
  var detected_obj, detected_version;
  var package_name, package_purl, qualifiers;
  var cve, distro, fixes;
  var fix_type = "rpm";

  if (empty_or_null(arch))
    arch = 'any';

  distro = get_kb_list("Host/*/rpm-list");
  if(!isnull(distro))
  {
    distro = keys(distro);
    distro = distro[0];
  }

  if(!empty_or_null(distro))
    distro = ereg_replace(string:distro, pattern:"Host/([^/]*)/rpm-list", replace:"\1");

  if(!empty_or_null(distro))
  {
    var fix_available = FALSE;
    distro = tolower(distro);
    qualifiers = {};
    if(!empty_or_null(arch))
      qualifiers["arch"] = arch;
    if(!empty_or_null(epoch))
      qualifiers["epoch"] = epoch;

    detected_obj = parse_rpm_name(rpm:package);
    if(detected_obj['version'])
      detected_version = detected_obj['version'] + '-' + detected_obj['release'];
    package_name = detected_obj['name'];

    package_purl = generate_purl(type:fix_type, nspace:distro, name:package_name, version:detected_version, qualifiers:qualifiers);
    if(!empty_or_null(reference))
    {
      fix_available = TRUE;
      fixed_obj = parse_rpm_name(rpm:reference);
      fixed_version = fixed_obj['version'] + '-' + fixed_obj['release'];

      fix_purl = generate_purl(type:fix_type, nspace:distro, name:package_name, version:fixed_version, qualifiers:qualifiers);
      fixes = [{'fix_type':fix_type, 'value':fix_purl}];
    }
    else
    {
      fixes = [];
    }

    var vuln = {
      "fix_available": fix_available,
      "fixes": fixes,
      "identifier": package_purl,
      "all_vulnerabilities": TRUE
    };

    if(!empty_or_null(cves))
    {
      vuln.all_vulnerabilities = FALSE;
      foreach cve (cves)
      {
        if(empty_or_null(vuln.vulnerabilities))
          vuln.vulnerabilities = [cve];
        else
          append_element(var:vuln.vulnerabilities, value:cve);
      }
    }

    if(isnull(__rpm_report_obj))
      __rpm_report_obj = new structured_data_vuln_reporting();

    __rpm_report_obj.append("vulnerability", vuln);

  }
}

##
# Adds text to to __rpm_report string indicating a reboot is required
#
# @param [package:string] Affected package install string
# @param [reference:string] Fixed package install string
# @param [uname:string] uname -r, the current running kernel level
##
function rpm_report_reboot(package, reference, uname)
{
  local_var array;
  array = split(package, sep:'|', keep:FALSE);
  package = array[0];
  if (package == reference)
    __rpm_report += 'Package ' + package + ' is installed.\n';
  else
    __rpm_report += 'Installed package ' + package + ' is greater than ' + reference + '.\n';
  __rpm_report += 'However, according to uname -r, the current running kernel level is ' + uname + '.\n' +
                  'This system requires a reboot to begin using the patched kernel level.\n\n';
}


##
# Reports structured vulnerability data as internal XML tags
##
function report_structured_data()
{
  if(!isnull(__rpm_report_obj))
  {
    __rpm_report_obj.report_internal();
    __rpm_report_obj = NULL;
  }
}


##
# Returns __rpm_report string
#
# @return [string|NULL] __rpm_report prepended by a \n if __rpm_report has string
#           length
#         NULL otherwise
##
function rpm_report_get()
{
  report_structured_data();

  if ( strlen(__rpm_report))
    return '\n' + __rpm_report;
  else
    return NULL;
}

##
# Parses name, version, release, and other necessary flags out of rpm
#
# @param [rpm:string] rpm string to parse
# @param [yank:string] optional string to remove from rpm
#
# @return [array] my_rpm array containing key-values about rpm package
##
function parse_rpm_name(rpm, yank)
{
  local_var elems, num, i, name;
  local_var my_rpm, pat, ep_str, cf_str, sat_str, scl_str;

  if (isnull(rpm)) rpm = '';

  pat = "^(\S*).*$";
  rpm = ereg_replace(string:rpm, pattern:pat, replace: "\1");

  pat = "md[kv]20[01][0-9]\.[0-9]$";
  rpm = ereg_replace(string: rpm, pattern: pat, replace: "");
  yank = ereg_replace(string: yank, pattern: pat, replace: "");

  elems = split(rpm, sep:"|", keep:0);
  if ( max_index(elems) > 1 )
  {
    my_rpm["epoch"] = elems[1];
    #my_rpm["keyid"] = elems[2];
    rpm = elems[0];
  }
  elems = split(rpm, sep:"-", keep:0);
  if (isnull(elems)) elems = [''];
  num = max_index(elems);
  name = elems[0];
  for ( i = 1; i < num - 2 ; i ++ )
  {
    name += "-" + elems[i];
  }

  my_rpm["name"]     = name;
  if (num < 2)
    my_rpm["version"] = '';
  else if (num == 2 && elems[num - 1] =~ "(\d+(\.\d+)+)")
    my_rpm["version"] = elems[num -1];
  else
    my_rpm["version"]  = elems[num - 2];
  if (num < 3)
    my_rpm["release"] = '';
  else
    my_rpm["release"]  = elems[num - 1];
  my_rpm["jpp_flag"] = "0";
  my_rpm["sat_flag"] = "0";
  my_rpm["cf_flag"]  = "0";
  my_rpm["scl_flag"] = "0";

  cf_str = pregmatch(string:my_rpm["release"], pattern:"^.*cf$");
  if (!isnull(cf_str)) {
    my_rpm["cf_flag"] = "1";
  }

  sat_str = pregmatch(string:my_rpm["release"], pattern:"^.*sat$");
  if (!isnull(sat_str)) {
    my_rpm["sat_flag"] = "1";
  }

  scl_str = pregmatch(string:my_rpm["release"], pattern:"^.*\.alt$");
  if (!isnull(scl_str)) {
    my_rpm["scl_flag"] = "1";
  }

  if ( "jpp" >< my_rpm["release"]) {
    my_rpm["jpp_flag"] = "1";
  }

  my_rpm["ep_flag"] = "0";
  if ( ".ep" >< my_rpm["release"]) {
    ep_str = pregmatch(string:my_rpm["release"], pattern:"^.*\.ep(\d+)\..*$");
    if (!isnull(ep_str))
      my_rpm["ep_flag"] = ep_str[1];
  }

  if ( yank ) {
    my_rpm["version"]  -= yank;
    my_rpm["release"] -= yank;
    my_rpm["epoch"] -= yank;
  }

  return my_rpm;
}

##
# Returns ord() value of anonymous parameter, added 255 if it's
#   between 0 and 9, and returning 0 if it's a space
#
# @anonparam [First:char] a single character
#
# @return [char] normalized character value
##
function normalize_value()
{
 local_var val;

 val = _FCT_ANON_ARGS[0];

 if ( val == ord(" ")) return 0;
 if ( val >= ord("0") && val <= ord("9"))
  val += 255;
 return val;
}

##
#Compares strings a and b and returns based on which
#   is greater textwise if applicable
#
# @param [a:string] version string piece
# @param [b:string] version string piece
#
# @remark Compares normalized ord data to determine which is greater
# @remark Fills in shorter strings with \0s
#
# @return [int] -1 RPM_OLDER if normalized a < normalized b
#          0 RPM_EQUAL if normalized a == normalized b
#          1 RPM_NEWER if normalized a > normalized b
##
function generic_str_cmp(a,b)
{
 local_var n, i, val_a, val_b;
 local_var retval;


 if ( strlen(a) < strlen(b))
   a = a + crap(data:'\x00', length:strlen(b) - strlen(a));
 else if ( strlen(a) > strlen(b))
   b = b + crap(data:'\x00', length:strlen(a) - strlen(b));

 n = strlen(a);
 retval = 0;
 for ( i = 0 ; i < n ; i ++ )
 {
   val_a = normalize_value(ord(a[i]));
   val_b = normalize_value(ord(b[i]));
   if ( val_a > val_b )
  return 1;
   else if ( val_a < val_b )
  return -1;
 }

 return 0;
}

##
#Compares strings a and b and returns based on which
#   has an lower numeric portion or feeds into generic_str_cmp
#   if it's purely non-digit
#
# @param [a:string] version string piece
# @param [b:string] version string piece
#
# @remark Calls generic_str_cmp if no digits at front/back of both
#
# @return [int] -1 RPM_OLDER if a starts with a digit and b doesn't ||
#                         a's digits in front are < b's digits
#                           in front ||
#                         a's digits in back are < b's digits
#                           in back ||
#                         a normalized < b normalized
#          0 RPM_EQUAL if a and b's digits are equal
#          1 RPM_NEWER if b starts with a digit and a doesn't ||
#                         b's digits in front are < a's digits
#                           in front ||
#                         b's digits in back are < a's digits
#                           in back ||
#                         b normalized < a normalized
##
function nondigit_vers_cmp(a,b)
{
 local_var bigna, bignb;
 local_var aa, ab;
 local_var s;

 if ( a =~ "^[0-9]" && b !~ "^[0-9]" )
  return 1;
 else if ( b =~ "^[0-9]" && a !~ "^[0-9]" )
  return -1;

 if ( a =~ "^[0-9]" && b =~ "^[0-9]" )
 {
  aa = pregmatch(string:a, pattern:"^([0-9]*)(.*)$");
  ab = pregmatch(string:b, pattern:"^([0-9]*)(.*)$");
  # This should never happen
  if (isnull(aa) || isnull(ab)) return NULL;
  bigna = bn_dec2raw(aa[1]);
  a = aa[2];

  bignb = bn_dec2raw(ab[1]);
  b = ab[2];
  s = 1;
 }
 else if (a =~ "^[^0-9]+[0-9]+$" && b =~ "^[^0-9]+[0-9]+$" )
 {
  aa = pregmatch(string:a, pattern:"^([^0-9]*)([0-9]*)$");
  ab = pregmatch(string:b, pattern:"^([^0-9]*)([0-9]*)$");
  # This should never happen
  if (isnull(aa) || isnull(ab)) return NULL;
  bigna = bn_dec2raw(aa[2]);
  a = aa[1];

  bignb = bn_dec2raw(ab[2]);
  b = ab[1];
  s = 2;
  if ( a < b )
  return -1;
  else if ( a > b )
  return 1;
 }
 else
 {
  return generic_str_cmp(a:a,b:b);
 }

 if ( strlen(aa[s]) && strlen(ab[s]))
 {
   if (bn_cmp(key1:bigna, key2:bignb) != 0)
     return bn_cmp(key1:bigna, key2:bignb);
 }

 if ( strlen(a) != 0 && strlen(b) == 0 ) return 1;
 if ( strlen(b) != 0 && strlen(a) == 0 ) return -1;

 if ( a < b )
  return -1;
 else if ( a > b )
  return 1;
 else
  return 0;
}

##
#Compares version strings a and b and returns based on which
#   is lower
#
# @param [a:string] version string with . separator
# @param [b:string] version string with . separator
#
# @remark If rpm_spec_vers_cmp_flag is enabled, this function will
#           instead call rpm_spec_vers_cmp() with its arguments
#
# @remark As it goes through different octets, it throws away the
#           largest identical parts ending in nondigits as it can
#
# @return [int] -1 RPM_OLDER if an octet of a < that octet of b ||
#                         a == b for all a octets but b has more
#          0 RPM_EQUAL if a and b are equal
#          1 RPM_NEWER if if an octet of b < that octet of a ||
#                         a == b for all b octets but a has more
##
function vers_cmp(a, b)
{
 local_var array_a, array_b, i, max;
 local_var digit_mode_a, digit_mode_b;
 local_var elem_a, elem_b, j, la, lb, j0;

 if (rpm_spec_vers_cmp_flag)
 {
   return rpm_spec_vers_cmp(a:a, b:b);
 }

 array_a = split(tolower(a), sep:".", keep:0);
 array_b = split(tolower(b), sep:".", keep:0);

 if ( max_index(array_b) < max_index(array_a))
  max = max_index(array_a);
 else
  max = max_index(array_b);

 for ( i = 0 ; i < max ; i ++ )
 {
  digit_mode_a = 1;
  digit_mode_b = 1;
  if ( max_index(array_a) <= i ) return -1;
  if ( max_index(array_b) <= i ) return 1;

  array_a[i] = filter_rh_inconstency(array_a[i]);
  array_b[i] = filter_rh_inconstency(array_b[i]);

  elem_a = array_a[i];
  elem_b = array_b[i];
  la = strlen(elem_a);
  lb = strlen(elem_b);
  j0 = -1;
  for (j=0; j<la && j<lb; j++)
  {
   if (elem_a[j] != elem_b[j]) break;
   if (elem_a[j] !~ "[0-9]") j0 = j;
  }
  if (j0 >= 0)
  {
   j0 ++;

   if (j0 >= la)
     array_a[i] = "";
   else
    array_a[i] = substr(elem_a, j0);

   if (j0 >= lb)
     array_b[i] = "";
   else
    array_b[i] = substr(elem_b, j0);
  }

  if ( array_a[i] !~ "^[0-9]+$" ) digit_mode_a = 0;
  if ( array_b[i] !~ "^[0-9]+$" ) digit_mode_b = 0;

  if ( digit_mode_a && digit_mode_b )
      {
       # int() casting fails miserably against numbers greater than max_int 2147483647.
       # int of a and int of b would both be max_int. Subtraction would be similarly useless.
       # Use the bignumber functions.
       if ( bn_raw2dec(array_a[i]) != bn_raw2dec(array_b[i]))
         return bn_cmp(key1:bn_dec2raw(array_a[i]), key2:bn_dec2raw(array_b[i]));
      }
  else if ( array_a[i] != array_b[i] )
     {
        if ( nondigit_vers_cmp(a:array_a[i], b:array_b[i]) < 0 )
    return -1;
  else
    return  1;
     }
 }

 return 0;
}

##
# Compares version strings a and b and returns based on which
#   is lower if rc version should have precedence over 
#   the version of the release, e.g. runc-1.0.0-1.rc92.el7.x86_64.rpm
#   should be regarded as newer than 
#   runc-1.0.0-19.rc5.git4bb1fe4.0.4.el7.x86_64.rpm.
#
# @param [a:string] version string with . separator
# @param [b:string] version string with . separator
#
# @return [int] -1 RPM_OLDER if an octet of a < that octet of b ||
#                         a == b for all a octets but b has more
#          0 RPM_EQUAL if a and b are equal
#          1 RPM_NEWER if if an octet of b < that octet of a ||
#                         a == b for all b octets but a has more
##
function rc_precedence_vers_cmp(a, b)
{ 
 local_var array_a, array_b;
 local_var match;
 local_var rc_a, rc_b;

 array_a = split(tolower(a), sep:".", keep:0);
 array_b = split(tolower(b), sep:".", keep:0);

 if ( max_index(array_b) < 2 || max_index(array_a) < 2 ||
      array_a[0] !~ "^[0-9]+$" || array_b[0] !~ "^[0-9]+$" )
   return vers_cmp(a:a, b:b);
 
 match = pregmatch(string:array_a[1], pattern:"^rc([0-9]+)$");
 if (isnull(match))  return vers_cmp(a:a, b:b);
 rc_a = int(match[1]);

 match = pregmatch(string:array_b[1], pattern:"^rc([0-9]+)$");
 if (isnull(match))  return vers_cmp(a:a, b:b);
 rc_b = int(match[1]);

 if ( rc_a < rc_b )
   return -1;
 else if ( rc_a > rc_b )
   return 1;
 else
   return vers_cmp(a:a, b:b);
}

##
# Return codes for rpm_cmp and rpm_check
##
global_var RPM_OLDER   = -1;
global_var RPM_EQUAL    = 0;
global_var RPM_NEWER    = 1;
global_var RPM_MISMATCH = 2;

##
# Return codes for _check_release_strings()
##
global_var RELEASE_MISMATCH = -2;
global_var RELEASE_MISSING = -3;
global_var RPMS_MISSING = -4;

##
# Compares the rpm and reference and returns based on which
#   is greater if applicable
#
# @param [rpm:string] complete rpm string from system's rpm list
# @param [reference:string] complete rpm string passed from plugin
# @param [yank:string] string of data to -= remove from version string and epoch
# @param [epoch:string] optional epoch value to compare rpm argument against
# @param [check_epoch:boolean] optional flag to cause function to check epochs 
#              instead of ignoring epoch differences in packages.
# @param [require_epoch_match:boolean] optional flag to signal version comparison should only
#              be performed if the installed package and reference package epoch values match.
#              Can only be used when check_epoch == TRUE. 
# @param [rc_precedence:boolean] optional flag to give precedence to the rc version over 
#              the version of the release, e.g. runc-1.0.0-1.rc92.el7.x86_64.rpm
#              should be regarded as newer than 
#              runc-1.0.0-19.rc5.git4bb1fe4.0.4.el7.x86_64.rpm
#
# @remark Default behavior is to return RPM_EQUAL if the major versions
#              for rpm and reference are different, treating as entirely
#              different packages.
# @remark Default behavior is to ignore differences in epoch; most 
#              advisories do not include the epoch for a fix package,
#              even though epoch values are present.
#
# @return [int] -1 RPM_OLDER if rpm and reference are for same package and
#              rpm's epoch < epoch and check_epoch true, or
#              rpm's version < reference version or
#              rpm's release < reference release (if versions equal)
#          0 RPM_EQUAL if rpm and reference package/version/release are
#              all equal
#          1 RPM_NEWER if rpm and reference are for same package and
#              rpm's epoch > epoch and check_epoch true, or
#              rpm's version > reference version or
#              rpm's release > reference release (if versions equal)
#          2 RPM_MISMATCH if rpm and reference are for different packages
#              or if one or more supplied flags for each do not match
##
function rpm_cmp(rpm, reference, yank, epoch, check_epoch, require_epoch_match, rc_precedence)
{
 local_var my_rpm, my_reference, eq, ep;

 my_rpm = parse_rpm_name(rpm:rpm, yank:yank);
 my_reference = parse_rpm_name(rpm:reference, yank:yank);

 if (my_rpm["name"] != my_reference["name"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["ep_flag"] != my_reference["ep_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["jpp_flag"] != my_reference["jpp_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["sat_flag"] != my_reference["sat_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["cf_flag"] != my_reference["cf_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["scl_flag"] != my_reference["scl_flag"])
 {
   return RPM_MISMATCH;
 }

 if (check_epoch)
 {
  if (require_epoch_match == TRUE)
  {
    if (int(my_rpm["epoch"]) != int(epoch))
      return RPM_NEWER;
  }
  else 
  {
    eq = int(my_rpm["epoch"]) - int(epoch);
    if (eq < 0) return RPM_OLDER;
    if (eq > 0) return RPM_NEWER;
  }
 }

 # for the redhat release package, only compare like versions
 # e.g. compare redhat-release-3ES-a.b.c and redhat-release-3ES-x.y.z,
 #      but not redhat-release-3ES-a.b.c and redhat-release-3WS-x.y.z
 if (
   my_reference["name"] == "redhat-release" &&
   my_rpm["version"] != my_reference["version"]
 )
 {
   return RPM_MISMATCH;
 }
 else
 {
   # nb: versioning for the perl-Module-Build package is not ordered
   # numerically (eg, 0.40 > 0.3500)
   if (my_reference["name"] == "perl-Module-Build")
   {
     if (my_rpm["version"] =~ "^0\.[0-9]{4}($|[^0-9])" || my_reference["version"] =~ "^0\.[0-9]{4}($|[^0-9])")
     {
       my_rpm["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_rpm["version"]);
       my_reference["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_reference["version"]);
     }
     else if (my_rpm["version"] =~ "^0\.[0-9]{5}($|[^0-9])" || my_reference["version"] =~ "^0\.[0-9]{5}($|[^0-9])")
     {
       my_rpm["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_rpm["version"]);
       my_reference["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_reference["version"]);
     }
   }

   eq = vers_cmp(a:my_rpm["version"], b:my_reference["version"]);
   if (eq > 0) return RPM_NEWER;
   if (eq < 0) return RPM_OLDER;
 }

 if (rc_precedence)
   eq = rc_precedence_vers_cmp(a:my_rpm["release"], b:my_reference["release"]);
 else
   eq = vers_cmp(a:my_rpm["release"], b:my_reference["release"]);
 if (eq > 0) return RPM_NEWER;
 if (eq < 0) return RPM_OLDER;
 return RPM_EQUAL;
}

##
# Combs through the potential release strings and rpm_lists to identify
#              the release and rpm-list on system, if applicable
#
# @param [release:string] optional argument to compare release string on system
#              against
#
# @remark Default behavior is to return an array containing keys for
#              "parsed_release" and "rpm-list". In the case of errors
#              (which will cause the calling functions to return 0)
#              we return an integer less than 0. 
#
# @return [array|int] array with keys "parsed_release" and "rpm-list" if a valid
#              release and rpm-list were found
#         -2 RELEASE_MISMATCH if release argument and parsed_release
#              don't match
#         -3 RELEASE_MISING if unable to parse release
#         -4 RPMS_MISSING if the "rpm-list" for a "parsed_release" is
#              null or empty
##
function _check_release_strings(release)
{
  var parsed_release;
  var regex_results;
  var results;

  var rh_release = get_kb_item("Host/RedHat/release");
  var ala_release = get_kb_item("Host/AmazonLinux/release");
  var suse_release = get_kb_item("Host/SuSE/release");
  var mdk_release = get_kb_item("Host/Mandrake/release");
  var ovs_release = get_kb_item("Host/OracleVM/release");
  var centos_release = get_kb_item("Host/CentOS/release");
  var mlos_release = get_kb_item("Host/McAfeeLinux/release");
  var xenserver_release = get_kb_item("Host/XenServer/release");
  var euler_release = get_kb_item("Host/EulerOS/release");
  var virtuozzo_release = get_kb_item("Host/Virtuozzo/release");
  var photon_release = get_kb_item("Host/PhotonOS/release");
  var zte_cgsl_release = get_kb_item("Host/ZTE-CGSL/release");
  var alma_release = get_kb_item("Host/AlmaLinux/release");
  var rocky_release = get_kb_item("Host/RockyLinux/release");
  var kylin_release = get_kb_item("Host/KylinOS/releaseidentifier");
  var mariner_release = get_kb_item("Host/CBLMariner/release");
  var azure_linux_release = get_kb_item("Host/AzureLinux/release");
  var alibaba_linux_release = get_kb_item("Host/Alibaba/release");

  var rhel_pattern = "Red Hat Enterprise Linux.*release ([3-9])(\D|$)";
  var fedora_pattern = "Fedora release ([7-9]|[1-3][0-9]|4[0-1])(\D|$)";
  var fedora_core_pattern = "Fedora Core release ([1-6])(\D|$)";
  var ol_pattern = "Oracle .*Linux .*release ([3-9])(\D|$)";
  var sl_pattern = "Scientific Linux release ([3-8])(\D|$)";
  var centos_pattern = "CentOS(?: Stream)?(?: Linux)? release ([6-9])(\D|$)";
  var centos_old_pattern = "CentOS release ([3-5])(\D|$)";
  var euler_pattern = "EulerOS release ([1-2]\.[0-9])(\D|$)";
  var virtuozzo_pattern = "Virtuozzo Linux release ([6-9])\.[0-9](\D|$)";
  var photon_pattern = "VMware Photon (?:Linux|OS) ([1-5]\.[0-9])(\D|$)";
  var zte_cgsl_pattern = "^CGSL (MAIN|CORE) ([3-6])\.[0-9]+(\s+\(.+?\))?$";
  var alma_pattern = "AlmaLinux release ([8-9])(\D|$)";
  var rocky_pattern = "Rocky(?: Linux)? release ([8-9])(\D|$)";
  var kylin_pattern = "KylinServerV([0-9]+)(?:SP([0-9]+))?";
  var mariner_pattern = "CBL-Mariner (\d+.\d+)(?:\D|$)";
  var azure_linux_pattern = "Azure Linux (\d\.\d+)([0-9.]*)(?:\D|$)";
  var alibaba_linux_pattern = "Alibaba Cloud Linux release (\d)(?:\D|$)";

  if(!isnull(ala_release) && strlen(ala_release) > 0 && (
     stridx(ala_release, "ALA") == 0 || stridx(ala_release, "AL2-") == 0 || stridx(ala_release, "AL-20") == 0 ))
    parsed_release = ala_release;
  else if("MDK" >< mdk_release)
    parsed_release = mdk_release;
  else if(!isnull(ovs_release) && strlen(ovs_release) > 0 && stridx(ovs_release, "OVS") == 0 &&
          !isnull(regex_results = pregmatch(pattern:"^(OVS\d+\.\d+)\.", string:ovs_release)))
    parsed_release = regex_results[1];
  else if ( "SLED" >< suse_release || "SLES" >< suse_release || "SUSE" >< suse_release )
    parsed_release = suse_release;
  else if ( "MLOS" >< mlos_release )
    parsed_release = mlos_release;
  else if ( "XS" >< xenserver_release )
    parsed_release = xenserver_release;
  else if("CoreOS" >< rh_release && !isnull(regex_results = pregmatch(pattern:rhel_pattern, string:rh_release)))
    parsed_release = "RHCOS" + regex_results[1];
  else if("CoreOS" >!< rh_release && !isnull(regex_results = pregmatch(pattern:rhel_pattern, string:rh_release)))
    parsed_release = "RHEL" + regex_results[1];
  else if(pgrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:rh_release))
    parsed_release = "RHEL2.1";
  else if(!isnull(regex_results = pregmatch(pattern:fedora_pattern, string:rh_release)))
    parsed_release = "FC" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:fedora_core_pattern, string:rh_release)))
    parsed_release = "FC" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:ol_pattern, string:rh_release)))
    parsed_release = "EL" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:sl_pattern, string:rh_release)))
    parsed_release = "SL" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:centos_pattern, string:centos_release)))
    parsed_release = "CentOS-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:centos_old_pattern, string:centos_release)))
    parsed_release = "CentOS-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:euler_pattern, string:euler_release)))
    parsed_release = "EulerOS-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:virtuozzo_pattern, string:virtuozzo_release)))
    parsed_release = "Virtuozzo-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:photon_pattern, string:photon_release)))
    parsed_release = "PhotonOS-" + regex_results[1];
  else if(pgrep(pattern:zte_cgsl_pattern, string:zte_cgsl_release))
    parsed_release = "ZTE " + zte_cgsl_release;
  else if(!isnull(regex_results = pregmatch(pattern:alma_pattern, string:alma_release)))
    parsed_release = "Alma-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:rocky_pattern, string:rocky_release)))
    parsed_release = "Rocky-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:kylin_pattern, string:kylin_release)))
    parsed_release = "Kylin-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:mariner_pattern, string:mariner_release)))
    parsed_release = "CBLMariner-" + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:azure_linux_pattern, string:azure_linux_release)))
    parsed_release = "Azure Linux " + regex_results[1];
  else if(!isnull(regex_results = pregmatch(pattern:alibaba_linux_pattern, string:alibaba_linux_release)))
    parsed_release = "Alibaba Linux " + regex_results[1];


  if (isnull(parsed_release) || strlen(parsed_release) < 1)
    return RELEASE_MISSING;

  if (!isnull(release) && strlen(release) > 0)
  {
    if(release == "ALA")
    {
      if(stridx(parsed_release, "ALA") != 0)
        return RELEASE_MISMATCH;
    }
    else if(release == "AL2")
    {
      if(stridx(parsed_release, "AL2-") != 0)
        return RELEASE_MISMATCH;
    }
    else if(stridx(release, "AL-20") == 0)
    {
      if(stridx(parsed_release, release + "-") != 0)
        return RELEASE_MISMATCH;
    }
    else
    {
      if(release != parsed_release)
        return RELEASE_MISMATCH;
    }
  }

  var rpms, keys;
  rpms = get_kb_list("Host/*/rpm-list");
  keys = keys(rpms);
  if(!isnull(keys))
    rpms = rpms[keys[0]];

  if(isnull(rpms) || strlen(rpms) < 1)
    return RPMS_MISSING;

  results["rpm-list"] = rpms;
  results["parsed_release"] = parsed_release;
  return results;
}

##
# Combs through the rpm list for the appropriate package from the
#              reference arguments, and compares the results,
#              adding them to the report and test values if appropriate.
#
# @param [reference:string] complete rpm string passed from plugin
# @param [yank:string] string of data to -= remove from version string and epoch
# @param [release:string] OS level identifier to check against before checking package
# @param [epoch:string] optional epoch time to compare rpms against
# @param [require_epoch_match:boolean] optional flag to signal vuln checking should only
#              be performed if the installed and reference package epoch values match.
# @param [cpu:string] optional argument to specify that the target machine should
#              be a specific architecture and which that is.
# @param [sp:int] optional SuSE or RedHat service pack to specify the target
#              machine should be.
# @param [allowmaj:boolean] This argument no longer does anything but to avoid having to update
#              every existing plugin, we will keep it as a function parameter
# @param [rpm_list:list] optional copy of rpm-list to use instead of the one on
#              the remote system
# @param [rpm_spec_vers_cmp:boolean] optional flag to force rpm_spec_vers_cmp to be
#              run instead of standard/legacy vers_cmp if it resolves as truthy
# @param [el_string:boolean] optional flag to perform an additional check for a
#              specific string within the release string portion of the
#              reference packagename
# @param [rc_precedence:boolean] optional flag to give precedence to the rc version over 
#              the version of the release, e.g. runc-1.0.0-1.rc92.el7.x86_64.rpm
#              should be regarded as a version newer than 
#              runc-1.0.0-19.rc5.git4bb1fe4.0.4.el7.x86_64.rpm
#
# @param [cves:list] optional list of CVEs that apply to package being checked
#
# @remark Default behavior is to return RPM_EQUAL if the major versions
#              for rpm and reference are different, treating as entirely
#              different packages.
#              __pkg_tests and __rpm_report will be modified if a reference
#              is found and lesser version on machine, respectively.
#
# @return [int] 1 if reference package found on machine of lesser version
#         0 if reference is for certain kernel files in some situations
#              or service pack mismatch or cpu mismatch
#              or unknown/inapplicable release
#              or missing rpm list
#              or package not found on target machine
#              or package found doesn't have supplied el_string
#              or package found on target machine of >= versions than
#              reference
##
function rpm_check(reference, yank, release, epoch, require_epoch_match, cpu, sp, allowmaj, rpm_list, rpm_spec_vers_cmp, el_string, rc_precedence, cves)
{
  var rh_sp, suse_sp, euler_sp, virtuozzo_sp, zte_cgsl_sp, kylin_sp;
  var rpms, package, lines, e, my_rpm, my_cpu, my_reference, rpm_results, check_epoch;
  var kernel_package_ok_flag, non_kernel_package_report_flag, is_kernel_package;
  var kernel_package_reboot_flag, uname_r, uname_package, ksplice_used, vuln_kernel_packages;
  var matching_kernel_packages_count;

  if ( "kernel-doc" >< reference ) return 0;

  rh_sp = get_kb_item("Host/RedHat/minor_release");
  suse_sp = get_kb_item("Host/SuSE/patchlevel");
  euler_sp = get_kb_item("Host/EulerOS/sp");
  kylin_sp = get_kb_item("Host/KylinOS/sp");
  virtuozzo_sp = get_kb_item("Host/Virtuozzo/minor_release");
  zte_cgsl_sp = get_kb_item("Host/ZTE-CGSL/minor_release");

  uname_r = get_kb_item("Host/uname-r");
  if (!isnull(uname_r) && strlen(uname_r))
  {
    # Strip newlines that may be added by TNUX
    if (pregmatch(pattern:'^\n' , string:uname_r))
    {
      uname_r = chomp(uname_r);
      uname_r = preg_replace(pattern:'^\n' , replace:'' , string:uname_r );
    }
    # Different OSes require different modifications.
    if (preg(pattern:"^(PhotonOS-|SUSE|SLES|SLED)", string:release))
    {
      # PhotonOS/SUSE/openSUSE require the final - section of uname_r removed.
      uname_r = ereg_replace(string:uname_r, pattern:"\-[a-zA-Z0-9_]+$", replace:'');
    }
    else if (preg(pattern:"^Virtuozzo-", string:release))
    {
      # Virtuozzo requires No Change to occur to uname_r
    }
    else
    {
      # All others need the final . section of uname_r removed, if it matches an architecture pattern.
      if (preg(pattern:__arch_pat, string:uname_r))
      {
        uname_r = ereg_replace(string:uname_r, pattern:__arch_pat, replace:'');
      }
    }
  }

  if (preg(pattern:"^(SUSE|SLES|SLED|ZTE CGSL)", string:release))
  {
    # At this time SUSE/openSUSE/ZTE NewStart CGSL do not contain levels of detail in uname -r sufficient to perform uname checks accurately.
    uname_r = NULL;
  }

  if (get_kb_item("Host/ksplice/kernel-cves"))
    ksplice_used = TRUE;

  # Change this when other distros use SP too
  if ( !isnull(sp) && (
       ( !isnull(euler_sp) && sp != int(euler_sp)) ||
       ( !isnull(suse_sp) && sp != int(suse_sp)) ||
       ( !isnull(rh_sp) && sp != int(rh_sp)) ||
       ( !isnull(virtuozzo_sp) && sp != int(virtuozzo_sp)) ||
       ( !isnull(kylin_sp) && sp != int(kylin_sp)) ||
       ( !isnull(zte_cgsl_sp) && sp != int(zte_cgsl_sp))
  ))
    return 0;

  if ( ! isnull(cpu))
  {
    my_cpu = get_kb_item("Host/cpu");
    # my_cpu returns a newline
    # 1270164212 1 Host/cpu=x86_64\n
    my_cpu = chomp(my_cpu);

    if ( my_cpu != cpu )
    {
      if (my_cpu =~ "i[3-6]86" && cpu =~ "i[3-6]86")
      {
        if (int(substr(my_cpu, 1)) < int(substr(cpu, 1))) return 0;
      }
      else return 0;
    }
  }

  rpm_results = _check_release_strings(release:release);

  if ( typeof(rpm_results) == "int" || isnull(rpm_results)) return 0;
  if (isnull(rpm_results["rpm-list"]))
    return 0;
  else
    rpms = rpm_results["rpm-list"];

  if (rpm_list && strlen(rpm_list) > 0)
    rpms = rpm_list;

  # Currently, only run epoch checks on Fedora Core machines
  # or when epoch is manually supplied.
  # Modify this when plugins and OSes both support epoch values.
  if (stridx(rpm_results["parsed_release"], "FC") == 0 ||
      !isnull(epoch))
    check_epoch = TRUE;
  else
    check_epoch = FALSE;

  if (check_epoch == TRUE)
  {
    if (!isnull(require_epoch_match))
      require_epoch_match = TRUE;
    else 
      require_epoch_match = FALSE;
  }

  # Currently, only run the new rpm-spec version compare function
  # on ZTE CGSL, or when that flag is is manually supplied.
  # Modify this when changing more OSes to run the new function.
  if (stridx(rpm_results["parsed_release"], "ZTE CGSL") == 0 || rpm_spec_vers_cmp)
    rpm_spec_vers_cmp_flag = TRUE;
  else
    rpm_spec_vers_cmp_flag = FALSE;

  if (preg(pattern:"^(vz)?kernel-", string:reference))
  {
    is_kernel_package = TRUE;
  }
  else
  {
    is_kernel_package = FALSE;
  }

  # Assemble a proper list of rpms by matching package name, unless 
  if (isnull(__rpm_list_array))
  {
    # In case multiple packages including kernel are used, apply fixup logic always.
    rpms = fixup_rpm_list(rpms);
    populate_rpm_list_array(rpms:rpms);
  }

  my_reference = parse_rpm_name(rpm:reference, yank:yank);
  lines = fetch_rpm_lines(package_name:os_security_patch::regex_sanitize_package_name(my_reference["name"]));
  if (!lines) return 0;

  #lines = split(package, sep:'\n', keep:0);
  vuln_kernel_packages = {};
  matching_kernel_packages_count = 0;
  foreach package (lines)
  {
    e =  rpm_cmp(rpm:package, reference:reference, yank:yank, epoch:epoch, check_epoch:check_epoch, require_epoch_match:require_epoch_match, rc_precedence:rc_precedence);
    my_rpm = parse_rpm_name(rpm:package, yank:yank);
    # Check the two cases for if the package name matches the reference
    if (e != RPM_MISMATCH)
    {
      pkg_tests_add(package);
    }
    else
    {
      my_reference = parse_rpm_name(rpm:reference, yank:yank);
      if (my_rpm["name"] == my_reference["name"])
      {
        pkg_tests_add(package);
      }
    }
    # If we have an el_string, check to ensure it's within the release string.
    if (!isnull(el_string) && strlen(el_string))
    {
      if (!preg(pattern:el_string, string:my_rpm["release"]))
      {
        continue;
      }
    }
    # Keep count of kernel packages that got past the el_string check for later.
    if ( is_kernel_package ) matching_kernel_packages_count++;
    # Add to the report if it's older
    if ( e == RPM_OLDER)
    {
      rpm_report_add(package:package, reference:reference);
      rpm_structured_report(package:package, reference:reference, epoch:epoch, arch:cpu, cves:cves);

      if ( !is_kernel_package )
      {
        non_kernel_package_report_flag = TRUE;
        if (nasl_level() >= 80502)
        {
          patch::log_finding(
            prod_name      : my_rpm["name"] + "-" + my_rpm["version"],
            prod_family_id : patch::FAM_RPM,
            location       : "rpm",
            version        : package,
            missing        : reference
          );
        }
      }
      else
      {
        vuln_kernel_packages[package] = my_rpm;
      }
    }
    else if ((e == RPM_NEWER || e == RPM_EQUAL) && is_kernel_package && !ksplice_used)
    {
      # If the uname -r is lower than the version-revision in package,
      # we need to flag the user for needing a reboot.
      # Skip this if ksplice is being used.
      if (!isnull(uname_r) && strlen(uname_r))
      {
        my_rpm = parse_rpm_name(rpm:reference, yank:yank);
        uname_package = my_rpm["name"] + "-" + uname_r;
        e =  rpm_cmp(rpm:uname_package, reference:reference, yank:yank, epoch:epoch, check_epoch:check_epoch, rc_precedence:rc_precedence);
        if (e == RPM_OLDER)
        {
          rpm_report_reboot(package:package, reference:reference, uname:uname_r);
          kernel_package_reboot_flag = 1;
        }
        else
        {
          kernel_package_ok_flag = 1;
        }
      }
      else
      {
        kernel_package_ok_flag = 1;
      }
    }
    else if (e != RPM_MISMATCH)
      # If it's not older and not a mismatch, note that at least one package was okay.
      # This will prevent reporting, but only for kernel- packages.
      kernel_package_ok_flag = 1;
  }

  if ( !is_kernel_package )
  {
    # If any single non-kernel package was RPM_OLDER, return 1 so we can report.
    if ( non_kernel_package_report_flag ) return 1;
    return 0;
  }
  else
  {
    # If any single kernel package was neither RPM_OLDER or RPM_MISMATCH, return 0 so we don't report.
    # However, if the current running kernel is lower version than the highest kernel package level,
    # the scanned system is vulnerable and requires a reboot.
    if ( kernel_package_reboot_flag ) return 1;
    if ( kernel_package_ok_flag ) return 0;
    # We need a defeat now that kernel packages can mismatch due to el_string.
    if ( matching_kernel_packages_count < 1 ) return 0;

    if (nasl_level() >= 80502)
    {
      foreach package (keys(vuln_kernel_packages))
      {
        my_rpm = vuln_kernel_packages[package];
        patch::log_finding(
          prod_name      : my_rpm["name"] + "-" + my_rpm["version"],
          prod_family_id : patch::FAM_RPM,
          location       : "rpm",
          version        : package,
          missing        : reference
        );
      }
    }
    # This guilty-until-proven-innocent design should never be used again.
    return 1;
  }
}

##
# Checks if a specific rpm string exists within a system's rpm list
#
# @param [rpm:string] rpm name (ie: python-devel-), anchored to left
# @param [release:string] OS release release number (ie: RHEL6)
# @param [rpm_list:list] optional copy of rpm-list to use instead of the one on
#              the remote system
#
# @remark A complete rpm is not required, it is fed into a
#              start anchored regex, partial packages allowed
#
# @return [int] 1 if rpm installed and Host OS release == release
#         0 otherwise
##
function rpm_exists(rpm, release, rpm_list)
{
  local_var rpms, rpm_results;

  rpm_results = _check_release_strings(release:release);
  if ( typeof(rpm_results) == "int" || isnull(rpm_results)) return 0;

  if (isnull(rpm_results["rpm-list"]))
    return 0;
  else
    rpms = rpm_results["rpm-list"];

  if (rpm_list && strlen(rpm_list) > 0)
    rpms = rpm_list;

  if ( egrep(pattern:"^" + os_security_patch::regex_sanitize_package_name(rpm), string:rpms))
    return 1;
  else
    return 0;
}


##
# Checks if a specific package name exists within a system's rpm list
# for marking as a vulnerable but unpatched package
#
# @param [package:string] package name, without version
# @param [release:string] OS release release number (ie: RHEL6)
# @param [rpm_list:list] optional copy of rpm-list to use instead of the one on
#              the remote system
# @param [cves:list] CVEs relevant to the checked package
#
# @return [boolean] TRUE if rpm installed and Host OS release == release
#         FALSE otherwise
##
function unpatched_package_exists(package, release, rpm_list, cves)
{
  if ( rpm_exists(rpm:package + "-[0-9]", release:release, rpm_list:rpm_list))
  {
    unpatched_packages_add(package, cves);
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}


##
# Determines if string consists of only (and at least one) digits
#
# @param [value:string] string to check
#
# @return [boolean] TRUE if value is only digits [0-9]
#         FALSE otherwise
##
function _rpm_isnum(value)
{
  if (preg(pattern:"^[0-9]+$", string:value))
    return TRUE;
  return FALSE;
}

##
# Determines if string consists of only (and at least one) uppercase and lowercase letters
#
# @param [value:string] string to check
#
# @return [boolean] TRUE if value is only upper or lowercase letters
#         FALSE otherwise
##

function _rpm_isalpha(value)
{
  if (preg(pattern:"^[a-zA-Z]+$", string:value))
    return TRUE;
  return FALSE;
}

##
# Breaks rpm version strings into an ordered list of number and alpha sections
#
# @param [version:string] rpm version string
#
# @remark All non-numbers-or-alphas are ignored
#
# @return [list|NULL] NULL if version is empty or NULL, or an integer section of a < that integer
#         list of rpm-significant number/alpha strings, in the order originally seen
##
function _rpm_spec_parse(version)
{
  local_var i, version_len, mode, previous_mode, value, previous_values, return_list;
  if (isnull(version))
    return NULL;
  version_len = strlen(version);
  if (!version_len)
    return NULL;
  previous_mode = "none";
  previous_values = "";
  return_list = [];
  for ( i = 0 ; i < version_len ; i ++ )
  {
    value = version[i];
    if (_rpm_isalpha(value:value)) mode = "alpha";
    else if (_rpm_isnum(value:value)) mode = "num";
    else mode = "ignore";

    if (previous_mode == "none") previous_mode = mode;
    if (mode != previous_mode)
    {
      if (previous_mode != "ignore")
      {
        append_element(var:return_list, value:previous_values);
      } 
      previous_values = "";
    }
    previous_mode = mode;
    if (mode != "ignore")
      previous_values += value;
  }
  # Append the final previous_values at end of string.
  if (strlen(previous_values))
    append_element(var:return_list, value:previous_values);
  return return_list;
}

##
# Compares version strings a and b and returns based on which
#    is lower according to the rpm specifications
#
# @param [a:string] rpm version string
# @param [b:string] rpm version string
#
# @remark All non-numbers-or-alphas are ignored as separators
# @remark Number sections are newer than alpha sections
# @remark Lowercase letters are newer than uppercase letters
#
# @return [int] Negative number below -1 if an integer section of a < that integer
#                                     section of b by two or more
#                     -1 RPM_OLDER if a section of a < that section of b ||
#                                     a == b for all a sections but b has more sections
#                      0 RPM_EQUAL if a and b are functionally equal according to rpm
#                      1 RPM_NEWER if a section of b < that section of a ||
#                                     a == b for all b sections but a has more sections
#         Positive number above 1 if an integer section of a < that integer
#                                     section of b by two or more
##
function rpm_spec_vers_cmp(a, b)
{
  local_var array_a, array_b, i, max;
  local_var elem_a, elem_b;

  if (a == b) return 0;

  array_a = _rpm_spec_parse(version:a);
  array_b = _rpm_spec_parse(version:b);

  if ( max_index(array_b) < max_index(array_a))
    max = max_index(array_a);
  else
    max = max_index(array_b);

  for ( i = 0 ; i < max ; i ++ )
  {
    if ( max_index(array_a) <= i ) return -1;
    if ( max_index(array_b) <= i ) return 1;

    elem_a = array_a[i];
    elem_b = array_b[i];

    # filter_rh_inconstency equivalent
    if ( tolower(elem_a) == "rhel" ) elem_a = "el";
    if ( tolower(elem_b) == "rhel" ) elem_b = "el";

    if (elem_a == elem_b) continue;
    if (_rpm_isalpha(value:elem_a) && _rpm_isnum(value:elem_b)) return -1;
    if (_rpm_isnum(value:elem_a) && _rpm_isalpha(value:elem_b)) return 1;
    if (_rpm_isnum(value:elem_a) && _rpm_isnum(value:elem_b))
    {
       if ( bn_raw2dec(elem_a) == bn_raw2dec(elem_b)) continue;
       return bn_cmp(key1:bn_dec2raw(elem_a), key2:bn_dec2raw(elem_b));
    }
    # Both alpha
    if (elem_a < elem_b) return -1;
    if (elem_a > elem_b) return 1;
  }
  return 0;
}

# RedHat-specific functions section

##
# Returns text explaining the package method of detection, issues
# behind it, and how to properly set up 'yum updateinfo list security
# updates'.
#
# @return [string] caveat block
##
function redhat_report_package_caveat()
{
  local_var caveat;
  caveat =
"NOTE: The vulnerability information above was derived by checking the
package versions of the affected packages from this advisory. This
scan is unable to rely on Red Hat's own security checks, which
consider channels and products in their vulnerability determinations.";
  return caveat;
}

##
# Returns text explaining the yum-updateinfo method of detection,
# and which RHSA to apply to resolve the issue.
#
# @return [string] caveat block
##
function redhat_report_yum_caveat(rhsa)
{
  local_var caveat;
  if (isnull(rhsa)) rhsa = 'the necessary updates';
  caveat =
"NOTE: The vulnerability information above was derived from the use of
the 'yum updateinfo list security updates' command to determine which
Red Hat security advisories apply to this system. Apply
" + rhsa + " to resolve this vulnerability.
";

  return caveat;
}

##
# Returns text explaining the repository method of detection, issues
# behind it, and lets the user know they should scan with an account
# that has the required permissions to read this file.
#
# @return [string] caveat block
##
function redhat_report_repo_caveat()
{
  local_var caveat = report_repo_caveat();
  return caveat;
}

##
# Returns text explaining the repository method of detection, issues
# behind it, and lets the user know they should scan with an account
# that has the required permissions to read this file.
#
# @return [string] caveat block
##
function centos_report_repo_caveat()
{
  local_var caveat = report_repo_caveat();
  return caveat;
}

##
# Returns text explaining the repository method of detection, issues
# behind it, and lets the user know they should scan with an account
# that has the required permissions to read this file.
#
# @return [string] caveat block
##
function report_repo_caveat()
{
  local_var caveat;
  local_var os = "Red Hat";
  if (get_kb_item("Host/AmazonLinux/release"))
    os = "Amazon Linux Extras";
  if (get_kb_item("Host/CentOS/release"))
    os = "CentOS";
  caveat =
"NOTE: The vulnerability information above was derived by checking the
package versions of the affected packages from this advisory. This
scan would normally rely on checking for the presence of specific
installed and enabled " + os + " repositories, but either no repositories
were found in the repository directory, the repository files were empty
or missing, or the scan account lacked permissions to access them.
Please ensure that the repository files are populated and the scanning
account has permissions to examine the files in /etc/yum.repos.d/.";
  return caveat;
}

##
# Checks which packages in yum-updateinfo relate to the RHSA,
# determines which fix packages are associated with that RHSA,
# determines which installed packages are associate with those fix
# packages, and compiles the data together to be returned as a string.
#
# @param [rhsa:string] string to determine what RHSA the vulnerability applies
#
# @return [string|NULL] NULL if yum_updateinfo isn't present or
#                 rhsa is NULL or empty or
#                 rhsa is not present in yum_updateinfo or
#                 rpm-list is not present
#         string containing package reports plus descriptive caveat
#                otherwise
#
##

function redhat_generate_yum_updateinfo_report(rhsa)
{
  local_var yum_updateinfo, rhsa_pattern, rhsa_lines, rhsa_line;
  local_var fix_packages, fix_to_installed_array;
  local_var rpms, fixup_flag, fixed_rpm, package_name, fixed_parsed;
  local_var rpm_list_matches, rpm_list_lines, rpm_line, rpm_line_parsed;
  local_var installed_rpm, rpm_report, fixed_rpm_trimmed;
  fix_to_installed_array = make_array();
  yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
  rpms = get_kb_item("Host/RedHat/rpm-list");
  if (isnull(rhsa) || strlen(rhsa) < 1) return NULL;
  if (isnull(yum_updateinfo) || strlen(yum_updateinfo) < 1) return NULL;
  if (isnull(rpms) || strlen(rpms) < 1) return NULL;
  if (rhsa >!< yum_updateinfo) return NULL;
  rhsa_pattern = "^" + rhsa + "\s+[a-zA-Z]+/Sec\.\s+(.*)$";
  rhsa_lines = egrep(pattern:rhsa_pattern, string:yum_updateinfo, icase:TRUE);
  rhsa_lines = split(rhsa_lines, sep:'\n', keep:0);
  foreach rhsa_line (rhsa_lines) {
    fixed_rpm = pregmatch(pattern:rhsa_pattern, string:rhsa_line, icase:TRUE);
    if (!isnull(fixed_rpm)) {
      fixed_rpm = fixed_rpm[1];

      # These yum-updateinfo lines always include a .x86_64 or .noarch
      # or .x686 that we have traditionally trimmed out
      fixed_rpm_trimmed = ereg_replace(string:fixed_rpm, pattern:"\.[^\.]+$", replace:'');
      if ( !isnull(fixed_rpm_trimmed)) {
        fixed_rpm = fixed_rpm_trimmed;
      }

      fixed_parsed = parse_rpm_name(rpm:fixed_rpm);
      package_name = fixed_parsed["name"];

      # Fixup if necessary
      if ( package_name =~ "^kernel-" && isnull(fixup_flag)) {
        rpms = fixup_rpm_list(rpms);
        fixup_flag = 1;
      }
      # If we Ever start using this function again, change this to start using a combination of
      # populate_rpm_list_array() and fetch_rpm_lines(). Right now we don't, so don't stress over this edge case.
      rpm_list_lines = egrep(pattern:"^" + os_security_patch::regex_sanitize_package_name(package_name) + "-[0-9]", string:rpms);
      #rpm_list_lines = egrep(pattern:"^" + os_security_patch::regex_sanitize_package_name(package_name), string:rpms);

      rpm_list_matches = split(rpm_list_lines, sep:'\n', keep:0);
      foreach rpm_line (rpm_list_matches)
      {
        rpm_line_parsed = parse_rpm_name(rpm:rpm_line);
        if (rpm_line_parsed["name"] == package_name)
        {
          fix_to_installed_array[fixed_rpm] = rpm_line;
        }
      }
    }
  }
  if (keys(fix_to_installed_array)) {
    foreach fixed_rpm (sort(keys(fix_to_installed_array))) {
      rpm_report_add(package:fix_to_installed_array[fixed_rpm], reference:fixed_rpm);
    }
  }
  rpm_report = rpm_report_get();
  # This should never happen. We are forcing it to happen as a safety precaution
  # to avoid weird NULL output in the report text.
  if (isnull(rpm_report)) rpm_report = 'Unable to determine installed/fixed package versions for\n' + rhsa + ', even though it is reported by Red Hat as being\nunpatched.\n\n';
  return rpm_report + redhat_report_yum_caveat(rhsa:rhsa);
}
