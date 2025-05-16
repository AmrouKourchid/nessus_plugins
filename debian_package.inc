#TRUSTED a5c9c492f205e6afcd52d1fab1f1520a8170a5903540851cc463da0540e05d80e7890e134fb228b87063028308604111cd09057ecb4956c502e4b5b3e384d0ab5d1b9e588ff40bc2ce05729c2d64ad428409c7c9704247563bfaadcc42636f705f16cfe3473776275781fda3f343084d184aa9fbb1367dec8ed279dec61e31269076593c0007750db6c52ece7caad62d208f0e794add578e04cdcf012e03624f6cb9a84ed3166b4d6651e0a3640603f60be57ecfd7cfce0c1ba61a59e5a3b2fd20373e171380ed87a7f1bb5dec4fcca5094300097b17480923c0db0c1c69e49be20df38853b7e2d8dec2fe2524655cd0ee294ddc98bd4b7e5ab076c73ac9d89ce836942035b184361256ce572186541b72334b2b94fe152a42a31f7a4c72a73820af0c52f3e9408fc77136b8a8a5c3a582dac57dce9882832eaa9754cf5af1a6cf0afacf19c20d9ce1fe077069dbdc28b3c5d5275737c23ed9e2d742c8e0be24892e9e4d71292d865de01d71e38a2c2a9b312b182156b76b59cd696896a82777b2cb8e735aa8433d4758ba3e80cb6e2b15d3621246c3f184f1531114cb46420585b589d14a0b29e44e1c7e69614620fbbfd98008f2ea5ac69bb931fcf2964f56248f3900e26015fb57479b4629a4078548eeaaf66aff75e278cfabbf9509a1767697e3bc977bf4c5cfe71d1019a60a9c5e7763c7e794d5ff9d231254babee239
#TRUST-RSA-SHA256 9d93d2bb543fef313ca662e8df34484aa0bc705a7486615fabac7122ff2268bdadf431f0c87cf075685c80573aa544593341a031a560e1885d030a8e3286e3f872bc48d8e25a96d2fa0a16ee43af9b049d57930de02909fa2e401fd02e560d032bff71ba7e9237cf98816b1766cabd3191b217f7377168a0a263cc02bda07d65348d3f530a4e2db17909cc0b6515e943b0b1b490fd0a4ab242e9d2c5d2a44632d9621c23dedf55453af551deec8b40916a0fbf50dbe8522b68cd1574056bec6b57d4fc82aa174d253e81506393cbd0f7b854250cfe4b18a8379873f5cdb4251f08299c76b5b724effb03477657b6a522b6c08ddae85345c4278f35b167fe96dc0769db5cb00bac80cb709be18f527b590decf42556d5cebad22aec97b2e0a1ee35fb15dc3b8a900f97b1bd5a13a8b0451d0ff388f556efdb5696f71dd20a88a792aa714aeb0d6e999e5295cc952aff016ce6cdb11c0aaff90944775bcf7ba18abc876fad4c04a79b1d1a4c78d514f356277e9e993aed4364ecd3dda420b63de071850ec87a8e9e22e12cb0f9010f2fc7bdb54551b3842df7afcf531482b00bb7dfbb9719bb22cd0e492c3b0407d619696baf8206d7586f1366634309397a9b05f5e602ffab1f541d8caa35b1190c1329e43014bf4753922c223536fed9b5beee3e5a8c8446cd385bf75adc2dfab4e2e90804c2c873e9cccdec65b6272563421c
# -*- Fundamental -*-
###
# Functions for comparing and reporting the packages of Debian based Linux distros.
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# debian_package.inc
# Revision: 1.49
###

# http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
# [epoch:]upstream_version[-debian_revision]

include("compat_shared.inc");
include("vcf.inc");
include("url_func.inc");
include("structured_data.inc");

##
# Internal value for storing report text
##
var deb_report = '';

##
# Internal storage for structured reports
##
var __deb_report_obj = NULL;

##
# Legacy value for storing report text from Ubuntu
# Kept so that if it is pre-populated it can be copied to deb_report
##
var _ubuntu_report = '';

##
# List storage of all remote packages found and checked
##
var _deb_pkg_tests = [];

##
# Storage value for package list kb so we only need to fetch once.
##
var dpkg_l;

##
# Storage value for if dpkg_l has been fixed up for linux packages.
##
var dpkg_fixup_flag;

##
# Array storage of all modified dpkg-l entries to point to their original versions
##
var _deb_dpkg_edits = {};

##
# Stores unpatched packages found to exist on the target
##
var _deb_unpatched_pkgs = {};

# Flag for indicating whether or not the linux package caveat about
# upgrading kernel version needs to be included
##
var _linux_package_flag;

##
# Flag for indicating whether or not the ESM package caveat is needed in the report
##
var requires_esm = 0;

##
# Translation array for determining what kinds of release candidate
# types are greater than others
##
var _rc_type_array = {
  "rc": 3,
  "beta": 2,
  "alpha": 1
};

##
# Return discovered vulnerable but unpatched packages in human readable form.
#
# @return [string|NULL] Returns an unpatched vuln report on success, NULL otherwise.
##
function report_unpatched_pkgs()
{
  var pkg, rep;

  rep = "";

  if(isnull(_deb_unpatched_pkgs) || len(_deb_unpatched_pkgs) == 0)
    return NULL;

  for(pkg of keys(_deb_unpatched_pkgs))
    rep += " - " + pkg + '\n';

  return rep;
}

##
# Creates and returns a plugin report for unpatched vulns on Debian or Ubuntu.
#
# @return [string] Plugin report text.
##
function unpatched_deb_pkg_report()
{
  var output = 'The following packages were identified as being present on the remote host:\n';
  output += report_unpatched_pkgs();
  output += '\nThe vendor has acknowledged the vulnerability but no solution has been provided.\n' +
    'Refer to the vendor for remediation guidance.\n\n';
  return output;
}

##
# Add unpatched packages discovered on the target host to internal storage.
#
# @param [package:string] Package name with version for reporting.
# @param [release:string] Release version of the Debian based OS.
#
# @return [boolean] TRUE if successful, FALSE otherwise.
##
function deb_add_unpatched_pkgs(package, release)
{
  if(empty_or_null(package))
    return FALSE;

  _deb_unpatched_pkgs[package] = release;

  return TRUE;
}

##
# Determines whether a package on the indicated OS release exists on the target
# for unpatched vulnerability checks.
#
# @param [prefix:string] The package prefix - i.e. the package name
# @param [release:string] A Debian based OS release number - i.e. 12 for "bookworm"
# @param [min:string] (optional) Minimum affected version in the indicated release.
#
# @return [boolean] Returns TRUE if the package was found on the target, FALSE otherwise.
##
function unpatched_deb_pkg_exists(prefix, release, min)
{
  if(!dpkg_l)
    dpkg_l = get_kb_item("Host/Debian/dpkg-l");

  if(empty_or_null(dpkg_l) || isnull(prefix) || isnull(release))
    return 0;

  if(prefix =~ "^linux-")
  {
    if(!dpkg_fixup_flag)
    {
      dpkg_l = _fixup_debian_dpkg_list(dpkg_l);

      if(isnull(dpkg_l))
        return 0;

      dpkg_fixup_flag = 1;
    }

    # Trim down supplied prefix to match the fixups
    # bpo format
    prefix = _fixup_debian_pkg_name(name:prefix);
  }

  var prefix_escaped = ereg_replace(string:prefix, pattern:"\+", replace:"\+");
  var installed = pgrep(string: dpkg_l, pattern: "^\wi +" + prefix_escaped + "(:\w+)? +");
  if(! installed)
    return 0;

  var installed_parts = _parse_debian_dpkg_name(dpkg:installed);
  if(isnull(installed_parts))
    return 0;

  var ver = installed_parts["version"];

  var ubuntu_flag = 0;
  if(get_one_kb_item("Host/Ubuntu"))
    ubuntu_flag = 1;

  var pkgver = _find_package_branch(version:ver, ubuntu:ubuntu_flag);

  var release_trimmed = release;
  if(!ubuntu_flag && preg(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?"))
  {
    release_trimmed = pregmatch(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?");
    if(isnull(release_trimmed))
      release_trimmed = "Release_trimmed regex broke, which is not possible.";
    else
      release_trimmed = release_trimmed[1];
  }

  # The package release to release check.
  if(pkgver && release != pkgver && ! match(string: pkgver, pattern: release_trimmed + ".*"))
    return 0;

  if(empty_or_null(min) || (deb_ver_cmp(ver1:ver, ver2:min) >= 0))
  {
    if(!deb_add_unpatched_pkgs(package:prefix + "_" + ver, release:release_trimmed))
      return 0;

    return 1;
  }

  return 0;
}


##
# Parses numerical and string portions of a version string into a list
#
# @param [ver_str:string] version string
#
# @return [list] parts of the version string broken into digit parts and non-digit parts
##

function deb_parse_ver_str(ver_str)
{
  var ret_val, is_num, tmp, i;

  ret_val = [];

  tmp = ver_str[0];
  is_num = FALSE;
  if(tmp =~ "[0-9.]") is_num = TRUE;
  tmp = '';

  for(i=0; i<strlen(ver_str); i++)
  {
    if(ver_str[i] == '~')
    {
      is_num = FALSE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      ret_val = make_list(ret_val, '~');
      tmp = '';
    }
    else if(ver_str[i] =~ "[0-9.]" && is_num == FALSE)
    {
      is_num = TRUE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    else if(ver_str[i] !~ "[0-9.]" && is_num == TRUE)
    {
      is_num = FALSE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    if(ver_str[i] != '~')
    {
      tmp = tmp + ver_str[i];
    }
  }
  if(tmp != '') append_element(var:ret_val, value:tmp);

  return ret_val;
}

##
# Build the structured report object
#
# @param [install_ver:string] The detected version of the package
# @param [ref_ver:string] The fixed version of the package
# @param [prefix:string] Descriptive package name
# @param [cves:list] optional list of CVEs that apply to package being checked
##
function deb_structured_report(install_ver, ref_ver, prefix, cves)
{
  var package_obj, package_name, package_version;
  var package_purl, fix_purl, qualifiers;
  var cve, distro;
  var fix_type = "deb";

  distro = get_kb_item("Host/distro");

  if(!empty_or_null(distro))
  {
    package_purl = generate_purl(type:fix_type, nspace:distro, name:prefix, version:install_ver);

    fix_purl = generate_purl(type:fix_type, nspace:distro, name:prefix, version:ref_ver);

    if(isnull(__deb_report_obj))
      __deb_report_obj = new structured_data_vuln_reporting();

    var vuln = {
      "fix_available": TRUE,
      "fixes":[{"fix_type":fix_type, "value":fix_purl}],
      "identifier": package_purl,
      "all_vulnerabilities": TRUE
    };

    if(!empty_or_null(cves))
    {
      vuln.all_vulnerabilites = FALSE;
      foreach cve (cves)
      {
        if(empty_or_null(vuln.vulnerabilities))
          vuln.vulnerabilities = [cve];
        else
          append_element(var:vuln.vulnerabilities, value:cve);
      }
    }

    __deb_report_obj.append("vulnerability", vuln);
  }
}

##
# Adds package/reference info to the internal deb_report value
#
# @param [install_ver:string] Installed version of package
# @param [ref_ver:string]  Non-affected version of package
# @param [prefix:string] Descriptive package name
#
# @remark If this is a package beginning with linux whose package name
#           matches #.#.#-#, it will replace that last -# with -<ANY>.
#
##
function deb_report_add(install_ver, ref_ver, prefix)
{
  var package = install_ver;
  var reference = ref_ver;
  if(!isnull(prefix))
  {
    package = prefix + "_" + install_ver;
    reference = prefix + "_" + ref_ver;
  }

  # Strip out Debian linux package name version ascension if applicable
  var dpkg_linux_pattern_check;
  var dpkg_linux_pattern = "^(linux-.*)(\d+\.\d+\.\d+)\-\d+(.*)_(.+)$";
  var dpkg_linux_bpo_pattern = "^(linux-.*)(\d+\.\d+\.0\-0\.bpo)\.\d+(.*)_(.+)$";
  if(empty_or_null(package) || empty_or_null(reference))
    return NULL;

  if(!isnull(_deb_dpkg_edits[package]) && strlen(_deb_dpkg_edits[package]))
    package = _deb_dpkg_edits[package];
  if(!isnull(_deb_dpkg_edits[reference]) && strlen(_deb_dpkg_edits[reference]))
    reference = _deb_dpkg_edits[reference];

  dpkg_linux_pattern_check = pgrep(string: reference, pattern:dpkg_linux_bpo_pattern);
  if(!isnull(dpkg_linux_pattern_check) && strlen(dpkg_linux_pattern_check))
  {
    reference = ereg_replace(string: reference, pattern:dpkg_linux_bpo_pattern, replace:"\1\2.<ANY>\3_\4");
    _linux_package_flag = 1;
  }
  else
  {
    dpkg_linux_pattern_check = pgrep(string: reference, pattern:dpkg_linux_pattern);
    if(!isnull(dpkg_linux_pattern_check) && strlen(dpkg_linux_pattern_check))
    {
      reference = ereg_replace(string: reference, pattern:dpkg_linux_pattern, replace:"\1\2-<ANY>\3_\4");
      _linux_package_flag = 1;
    }
  }

  # It's bad to have different reporting verbiage,
  # but changing all of the unit tests at this point is a separate issue.
  if(get_one_kb_item("Host/Ubuntu"))
  {
    deb_report += '  - Installed package : ' + package + '\n' +
                  '  - Fixed package     : ' + reference + '\n' +
                  '\n';
  }
  else
  {
    deb_report += 'Remote package installed : ' + package + '\n' +
                  'Should be : ' + reference + '\n';
  }
}

##
# Returns internal deb_report value
#
# @remark If the _linux_package_flag is set, this will also include a
#           caveat about potentially needing to update kernel version
#
# @return [string|NULL] newline + the global deb_report if it is not empty
##
function deb_report_get()
{
  var report, plural;
  var env, plugin_id, report_port, tag_protocol;

  if(!isnull(__deb_report_obj))
  {
    __deb_report_obj.report_internal();
    __deb_report_obj = NULL;
  }

  report = deb_report;
  if(_linux_package_flag && strlen(report))
  {
    report += '\nBecause Debian/Ubuntu linux packages increment their package name numbers as\n' +
              'well as their version numbers, an update may not be available for the\n' +
              'current kernel level, but the package will still be vulnerable. You may\n' +
              'need to update the kernel level in order to get the latest security\n'+
              'fixes available.';
  }
  if(requires_esm > 0)
  {
    if(requires_esm > 1)
    {
      plural = 's';
    }
    else
    {
      plural = '';
    }
    report += '\nNOTE: The fixed ESM package' + plural + ' referenced in this plugin requires a\n' +
              'subscription to Ubuntu Pro to enable the ESM repositories.';
  }
  if(strlen(report) )
    return '\n' + report;
  else
    return NULL;
}

##
# Alias for deb_report_get()
#
# @return [string|NULL] newline + the global deb_report if it is not empty
##
function ubuntu_report_get()
{
  return deb_report_get();
}

##
# Adds package to _deb_pkg_tests list
#
# @anonparam [First:string] A full package/version combination from target system
##
function deb_pkg_tests_add()
{
  var array, package;
  package = _FCT_ANON_ARGS[0];
  if(!package || !strlen(package)) return NULL;
  if(!isnull(_deb_dpkg_edits[package]) && strlen(_deb_dpkg_edits[package]))
    package = _deb_dpkg_edits[package];
  append_element(var:_deb_pkg_tests, value:package);
}

##
# Alias for deb_pkg_tests_add()
#
# @anonparam [First:string] A full package/version combination from target system
##
function ubuntu_pkg_tests_add()
{
  return deb_pkg_tests_add(_FCT_ANON_ARGS[0]);
}

##
# Sorts and uniques entries in _deb_pkg_tests list, returns as string
#
# @return [string|NULL] Sorted, unique list of dpkgs from _deb_pkg_tests in a string
#           separated by " / "
##
function deb_pkg_tests_get()
{
  var p, s, pkg_tests_unique, pkg_tests_array, package;

  if(max_index(_deb_pkg_tests) == 0) return NULL;
  pkg_tests_array = make_array();
  pkg_tests_unique = make_list();
  foreach package (_deb_pkg_tests)
    if(!pkg_tests_array[package]++) pkg_tests_unique = make_list(pkg_tests_unique, package);
  pkg_tests_unique = sort(pkg_tests_unique);

  s = "";
  foreach p (pkg_tests_unique)
    s += " / " + p;
  return substr(s, 3);
}

##
# Alias for deb_pkg_tests_get()
#
# @return [string|NULL] Sorted, unique list of dpkgs from _deb_pkg_tests in a string
#           separated by " / "
##
function ubuntu_pkg_tests_get()
{
  return deb_pkg_tests_get();
}

##
# Prepares lists of parsed version strings of debian packages, for parallel comparison
#
# @param [l1:list] First version list
# @param [l2:list] Second version list
#
# @return [list] List of the two now prepared original lists l1 and l2
#
# @remark returns the modified lists in the same order as they were given to the function
##
function deb_align_lists(l1, l2)
{
  var i;
  var original_order = TRUE;
  var ref = l1;
  var cmp = l2;
  # Select the longer list as reference if it's not already the case
  if(max_index(l1) < max_index(l2))
  {
    ref = l2;
    cmp = l1;
    original_order = FALSE;
  }

  # Compare each element, they should be of the same type
  # (i.e. string, number or ~)
  # if not, insert empty string at studied index, in the list that doesn't contain the ~ or string
  for ( i = 0; !isnull(ref[i]); i++)
  {
    if(isnull(cmp[i]))
      cmp[i] = "";
    # Look at ~ before anything else because its placement may matter
    else if((ref[i] == '~' && cmp[i] != '~'))
      insert_element(idx: i, value: "", var: cmp);
    else if((cmp[i] == '~' && ref[i] != '~'))
      insert_element(idx: i, value: "", var: ref);
    # Then look at strings vs. numbers
    else if(ref[i] =~ "[a-zA-Z+:\-]+" && cmp[i] !~ "[a-zA-Z+:\-]+")
      insert_element(idx: i, value: "", var: cmp);
    else if(cmp[i] =~ "[a-zA-Z+:\-]+" && ref[i] !~ "[a-zA-Z+:\-]+")
      insert_element(idx: i, value: "", var: ref);
  }
  # List order is important for the calling function
  if(!original_order)
    return [cmp, ref];
  return [ref, cmp];
}

##
# Compares two Debian version string pieces
#
# @param [s1:string] First version string piece
# @param [s2:string] Second version string piece
#
# @remark If one string has more parts than the other and they're identical
#           to the limit of the shorter, the longer one is decided greater.
#
# @return [int|NULLL] 1 if s1 > s2 in version parts from left to right
#         -1 if s1 < s2 in version parts from left to right
#         0 if s1 and s2 are equal through lowest max_len
#         NULL if either version is an invalid format
##
function deb_str_cmp(s1, s2)
{
  var v1, v2, v1_len, v2_len,
      t1, t2, t1_len, t2_len,
      i,  j, aligned_v;

  v1 = deb_parse_ver_str(ver_str:s1);
  v2 = deb_parse_ver_str(ver_str:s2);
  # Make sure the lists are ready for parallel comparison
  aligned_v = deb_align_lists(l1: v1, l2: v2);
  v1 = aligned_v[0];
  v2 = aligned_v[1];

  v1_len = max_index(v1);
  v2_len = max_index(v2);

  for(i=0; i < v1_len && i < v2_len; i ++)
  {
    # Numeric comparisons
    if(v1[i] =~ "^[0-9.]+")
    {
      t1 = split(v1[i], sep:'.', keep:FALSE);
      t2 = split(v2[i], sep:'.', keep:FALSE);
      t1_len = max_index(t1);
      t2_len = max_index(t2);

      for (j = 0; j < t1_len && j < t2_len; j++)
      {
        if(int(t1[j]) < int(t2[j]))
          return -1;
        if(int(t1[j]) > int(t2[j]))
          return 1;
      }
      # End of shared distance. If either has more at this point.
      # it is the greater.
      if(t1_len < t2_len)
        return -1;
      if(t1_len > t2_len)
        return 1;
    }
    else
    {
      # String comparisons
      # https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
      # ~ is special. Despite having an ASCII value of 126, it scores
      # as -1 value for Debian version string comparison purposes
      # deb_parse_ver_str() has been modified to keep tildes by themselves.
      #
      # Sorting note - all letters sort earlier than non-letters even though non-letters
      # have a lower ascii value
      # so we need to replace ':' and '-' with a high value and keep their order
      v1[i] = str_replace(string: v1[i], find: '-', replace: '\xfe');
      v1[i] = str_replace(string: v1[i], find: ':', replace: '\xff');
      v2[i] = str_replace(string: v2[i], find: '-', replace: '\xfe');
      v2[i] = str_replace(string: v2[i], find: ':', replace: '\xff');

      # Debian versioning
      for (j = 0; j < len(v1[i]) && j < len(v2[i]); j++)
      {
        if(v1[i][j] == '~' && v2[i][j] != '~')
          return -1;
        if(v1[i][j] != '~' && v2[i][j] == '~')
          return 1;
        if(vcf::is_alpha(v1[i][j]) && !vcf::is_alpha(v2[i][j]))
          return -1;
        if(!vcf::is_alpha(v1[i][j]) && vcf::is_alpha(v2[i][j]))
          return 1;
        if(v1[i][j] < v2[i][j])
          return -1;
        if(v1[i][j] > v2[i][j])
          return 1;
      }
      # The tilde ranks lower than the empty string, make sure to return accordingly
      if(len(v1[i]) == 0 || len(v2[i]) == 0)
      {
        if(v1[i] == '~')
          return -1;
        if(v2[i] == '~')
          return 1;
      }
      if(len(v1[i]) > len(v2[i]))
        return 1;
      if(len(v1[i]) < len(v2[i]))
        return -1;
    }
  }
  # End of shared distance. Return based on what has anything left,
  # or 0 if they're equal.
  if(v1_len < v2_len)
    return -1;
  if(v1_len > v2_len)
    return 1;
  return 0;
}

##
# Compares two complete Debian/Ubuntu versions
#
# @param [ver1:string] First version
# @param [ver2:string] Second version
#
# @remark This function will remove RC entries from versions and then consider
#           which is greater if the version (not release) part is equal.
#
# @return [int|NULL] 1 or more if ver1 > ver2 in version parts from left to right
#         -1 or less if ver1 < ver2 in version parts from left to right
#         0 if versions are equal
#         NULL if either version is an invalid format
##
function deb_ver_cmp(ver1, ver2)
{
  var v1, v2, e1, e2, uv1, uv2, dr1, dr2, rc1, rc2, x, rctype1, rctype2, package_pattern;

  # Parse RCs. Treat alphas and betas the same as RCs.
  rc1 = pregmatch(string: ver1, pattern: "^(.*)[.~\-+](rc|alpha|beta)([0-9]+)(.*)$", icase: 1);
  rc2 = pregmatch(string: ver2, pattern: "^(.*)[.~\-+](rc|alpha|beta)([0-9]+)(.*)$", icase: 1);
  if(! isnull(rc1))
  {
    ver1 = rc1[1] + rc1[4];
    rctype1 = rc1[2];
    rc1 = rc1[3];
  }
  if(! isnull(rc2))
  {
    ver2 = rc2[1] + rc2[4];
    rctype2 = rc2[2];
    rc2 = rc2[3];
  }

  package_pattern = "^([0-9]+:)?(.+?)(-([a-z0-9+.~]+))?$";
  v1 = pregmatch(string: ver1, pattern:package_pattern, icase: 1);
  v2 = pregmatch(string: ver2, pattern:package_pattern, icase: 1);

  if(isnull(v1) || isnull(v2)) return NULL;
  e1 = int(v1[1]); uv1 = v1[2]; dr1 = v1[4];
  e2 = int(v2[1]); uv2 = v2[2]; dr2 = v2[4];

  if(e1 != e2) return e1 - e2;
  x = deb_str_cmp(s1: uv1, s2: uv2);
  if(x) return x;
  if(! isnull(rc1) && isnull(rc2))
  {
    return -1;
  }
  if(isnull(rc1) && ! isnull(rc2))
  {
    return 1;
  }
  if(! isnull(rc1) && ! isnull(rc2) && (rc1 != rc2 || rctype1 != rctype2) )
  {
    # If different type, return based on which type is higher
    if(rctype1 != rctype2)
    {
      return _rc_type_array[rctype1] - _rc_type_array[rctype2];
    }
    else
    {
      # If same type, return based on high rc number
      return int(rc1) - int(rc2);
    }
  }
  x = deb_str_cmp(s1: dr1, s2: dr2);
  return x;
}

##
# Alias to deb_ver_cmp()
#
# @param [ver1:string] First version
# @param [ver2:string] Second version
#
# @remark This function will remove RC entries from versions and then consider
#           which is greater if the version (not release) part is equal.
#
# @return [int|NULL] 1 or more if ver1 > ver2 in version parts from left to right
#         -1 or less if ver1 < ver2 in version parts from left to right
#         0 if versions are equal
#         NULL if either version is an invalid format
##
function ubuntu_ver_cmp(ver1, ver2)
{
  return deb_ver_cmp(ver1:ver1, ver2:ver2);
}

##
# Normalizes Debian package names
#
# @param [name:string] Package names.
#
# @return [string] Returns a normalized Debian package name.
##
function _fixup_debian_pkg_name(name)
{
  var metapackage, name_version, prefix, suffix, name_version_major, name_pieces;

  if(preg(string:name, pattern:"\d+\.\d+\.0-0\.bpo\.\d+([^0-9]|$)") ) {
    name_pieces = pregmatch(string:name, pattern:"^(.*)-(\d+\.\d+\.0-0\.bpo\.\d+)-?(.*)$");
    if(isnull(name_pieces)) {
      metapackage = "Unable to parse metapackage";
    } else {
      prefix = name_pieces[1];
      name_version = name_pieces[2];
      suffix = name_pieces[3];
      name_version_major = pregmatch(string:name_version, pattern:"^(\d+\.\d+)\.");
      if(isnull(name_version_major)) {
        name_version_major = "Unable to parse name_version_major";
      } else {
        name_version_major = name_version_major[1];
      }
      metapackage = prefix + '-' + name_version_major + '.bpo';
      if(!isnull(suffix) && strlen(suffix)) {
        metapackage += '-' + suffix;
      }
    }
  } else if(preg(string:name, pattern:"\d+\.\d+\.\d+-\d+") ) {
    name_pieces = pregmatch(string:name, pattern:"^(.*)-(\d+\.\d+\.\d+-\d+)-?(.*)$");
    if(isnull(name_pieces)) {
      metapackage = "Unable to parse metapackage";
    } else {
      prefix = name_pieces[1];
      name_version = name_pieces[2];
      suffix = name_pieces[3];
      name_version_major = pregmatch(string:name_version, pattern:"^(\d+\.\d+)\.");
      if(isnull(name_version_major)) {
        name_version_major = "Unable to parse name_version_major";
      } else {
        name_version_major = name_version_major[1];
      }
      metapackage = prefix + '-' + name_version_major;
      if(!isnull(suffix) && strlen(suffix)) {
        metapackage += '-' + suffix;
      }
    }
  } else {
    metapackage = name;
  }

  return metapackage;
}

##
# Determines shortened name and metapackage name for the dpkg
#
# @param [dpkg:string] package name to parse
#
# @return [array] my_dpkg array containing key-values about dpkg
##
function _parse_debian_dpkg_name(dpkg, keep_full_name)
{
  var elems, i, name, version, prefix, name_version, name_version_major, suffix, name_pieces;
  var my_dpkg, metapackage;

  if(isnull(dpkg) || !strlen(dpkg)) return NULL;
  if(isnull(keep_full_name)) keep_full_name = FALSE;
  my_dpkg["line"]  = dpkg;
  # Trim off character status code and spacing.
  dpkg = ereg_replace(string:dpkg, pattern:"^\wi\s+", replace:"");
  dpkg = ereg_replace(string:dpkg, pattern:" {3,}", replace:"  ");
  elems = split(dpkg, sep:"  ", keep:0);
  name = elems[0];
  version = elems[1];

  if(dpkg =~ "^linux-")
  {
    metapackage = _fixup_debian_pkg_name(name:name);
    if("Unable to parse" >< metapackage)
      return NULL;
  }
  else
  {
    metapackage = name;
  }

  my_dpkg["name"]        = name;
  my_dpkg["version"]     = version;
  my_dpkg["metapackage"] = metapackage;

  if(!keep_full_name && name != metapackage)
    my_dpkg["line"] = str_replace(string:my_dpkg["line"], find:name, replace:metapackage);

  _deb_dpkg_edits[metapackage + "_" + version] = name + "_" + version;

  return my_dpkg;
}

##
# Changes dpkg-l so that only a single copy of each package that
# begins with "linux-", the latest, appears in the dpkg list
#
# @anonparam [First:string] List of dpkgs, joined with newlines as in most
#              dpkg-l KB entries
#
# @remark Only applies to linux packages.
#
# @return [string] Revised copy of dpkg-l with only the latest linux package
#
##
function _fixup_debian_dpkg_list(keep_full_name)
{
  var lines, line, arg, ret;
  var linux_dpkg, linux_dpkgs;
  var kernel_maj_min, maj_min, kernel_type, running_kernel;

  arg = _FCT_ANON_ARGS[0];
  if(isnull(arg) || !strlen(arg))
    return NULL;
  if(isnull(keep_full_name))
    keep_full_name = FALSE;

  kernel_maj_min = split(get_kb_item("Host/uname/major_minor"), sep:'.', keep:FALSE);
  kernel_type = get_kb_item("Host/Debian/kernel-type");

  running_kernel = get_kb_item("Host/Debian/kernel-version");
  if(running_kernel >!< arg)
    running_kernel = NULL;

  lines = split(arg, keep:FALSE);
  foreach line ( lines )
  {
    if(line =~ "^\wi +linux-" )
    {
      linux_dpkg = _parse_debian_dpkg_name(dpkg:line, keep_full_name:keep_full_name);
      if(isnull(linux_dpkg))
        return NULL;

      # Apply the major minor restriction to all linux packages except linux-firmware.
      if(linux_dpkg["name"] !~ "^linux-firmware" && !isnull(kernel_maj_min) && max_index(kernel_maj_min) > 0)
      {
        maj_min = split(linux_dpkg["version"], sep:'.', keep:FALSE);
        # Let's only reject non-matching kernel versions when there actually are kernel versions
        if((!isnull(maj_min[0]) && !isnull(kernel_maj_min[0]) && maj_min[0] != kernel_maj_min[0]) ||
           (!isnull(maj_min[1]) && !isnull(kernel_maj_min[1]) && maj_min[1] != kernel_maj_min[1]))
          continue;
      }
      # If it doesn't match the kernel-type, ignore it.
      if(linux_dpkg["name"] =~ "^linux-image" && !empty_or_null(kernel_type) && kernel_type >!< linux_dpkg["name"] )
        continue;

      if(isnull(linux_dpkgs[linux_dpkg["metapackage"]]) )
      {
        linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
      }
      else
      {
        if(!isnull(running_kernel))
        {
          if(running_kernel >< linux_dpkg["name"])
            linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
        }
        else
        {
          if(deb_ver_cmp(ver1:linux_dpkg["version"], ver2:linux_dpkgs[linux_dpkg["metapackage"]]["version"]) > 0)
            linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
        }
      }
    }
    else
    {
      ret += line + '\n';
    }
  }

  foreach linux_dpkg ( sort(keys(linux_dpkgs)) )
    ret += linux_dpkgs[linux_dpkg]["line"] + '\n';

  return ret;
}


##
# Converts Debian package versions based on the distro release name to
# their numerical equivalent to allow comparisons.
#
# @param [version:string] Version part of the package name
# @param [ubuntu:boolean] TRUE if the target is Ubuntu, FALSE otherwise
#
# @return [string] A number based version component.
##
function _find_package_branch(version, ubuntu)
{
  var debver, pkgver;

  if(ubuntu)
    debver = chomp(get_kb_item("Host/Ubuntu/release"));
  else
    debver = chomp(get_kb_item("Host/Debian/release"));

  if(isnull(debver))
    debver = chomp(get_kb_item("Host/UOS/release"));

  if(isnull(debver))
    debver = chomp(get_kb_item("Host/Kali/release"));

  if(!debver)
    return 0; # Not a Debian, Ubuntu or derivative

  # Here, we try to extract the "branch" from the installed package
  # I don't think that mixing sarge, woody and sid packages on a single
  # system is great, but it is possible.
  # However, the branch is not always included in the package name, and
  # Look at "DSA 865-1" for example. So we fall back to /etc/debian-release
  # and hope that such mix did not occur
  # 20220303: These release inclusions generally stopped around the
  # "wheezy" era. Still, just in case, keep this.
  if(preg(string:version, pattern: '[0-9]$'))
    pkgver = debver; # or '4.0'?
  else if(preg(string:version, pattern:'bullseye[0-9]$'))
    pkgver = '11.0';
  else if(preg(string:version, pattern:'buster[0-9]$'))
    pkgver = '10.0';
  else if(preg(string:version, pattern:'stretch[0-9]$'))
    pkgver = '9.0';
  else if(preg(string:version, pattern:'jessie[0-9]$'))
    pkgver = '8.0';
  else if(preg(string:version, pattern:'wheezy[0-9]$'))
    pkgver = '7.0';
  else if(preg(string:version, pattern:'squeeze[0-9]$'))
    pkgver = '6.0';
  else if(preg(string:version, pattern:'lenny[0-9]$'))
    pkgver = '5.0';
  else if(preg(string:version, pattern:'etch[0-9]$'))
    pkgver = '4.0';
  else if(preg(string:version, pattern:'sarge[0-9]$'))
    pkgver = '3.1';
  else if(preg(string:version, pattern:'woody[0-9]$'))
    pkgver = '3.0';
  else if(preg(string:version, pattern:'potato[0-9]$'))
    pkgver = '2.2';
  else if(preg(string:version, pattern:'hamm[0-9]$'))
    pkgver = '2.0';
  else
    pkgver = debver; # No Debian descriptor pattern, or Ubuntu.

  return pkgver;
}

##
# Checks if package below a reference version is installed.
#
# @param [prefix:string] package name (ie: python)
# @param [release:string] Debian release number (optional)
# @param [reference:string] version and release number (ie: 2.6.6-3+squeeze7)
# @param [min:string] minimum version and release number to check (optional)
# @param [cves:list] optional list of CVEs that apply to package being checked
#
# @remark This function has the side-effect of modifying deb_report
#
# @return [int] 1 if package installed and min <= package < reference
#              and Host OS release == release
#         0 otherwise
##
function deb_check(prefix, release, reference, min, cves)
{
  var debver, pkgver, release_trimmed, prefix_local;
  var installed, ver, v, prefix_escaped;
  var name_orig, name_pieces, name_version, name_version_major, suffix;
  var ubuntu_flag;

  # Uncommon situation, _ubuntu_report has been prepopulated for plugin reasons such as ksplice detection.
  # Copy it over. Should happen at most once per plugin.
  if(empty_or_null(deb_report) && !empty_or_null(_ubuntu_report))
    deb_report = _ubuntu_report;

  if(get_kb_item("Host/uptrack-uname-r") &&
     (preg(string:prefix, pattern:'^kernel-.*') || preg(string:prefix, pattern:'^linux-.*')))
    return 0;

  if(!dpkg_l)
    dpkg_l = get_kb_item("Host/Debian/dpkg-l");

  if(prefix =~ "^linux-" )
  {
    if(!dpkg_fixup_flag)
    {
      dpkg_l = _fixup_debian_dpkg_list(dpkg_l);
      if(isnull(dpkg_l))
        return 0;

      dpkg_fixup_flag = 1;
    }
    # Trim down supplied prefix to match the fixups
    # bpo format
    name_orig = prefix;
    prefix = _fixup_debian_pkg_name(name:prefix);
    if("Unable to parse" >< prefix)
      return 0;
    _deb_dpkg_edits[prefix + "_" + reference] = name_orig + "_" + reference;
  }

  # Try something smarter but slower below
  # if(debver && release != debver) return 0;

  # Only packages where the second letter of the status is 'i'
  # are actually installed (ii, hi, ui, ri, pi would all indicate installed)
  prefix_escaped = ereg_replace(string:prefix, pattern:"\+", replace:"\+");
  installed = pgrep(string: dpkg_l, pattern: "^\wi +" + prefix_escaped + "(:\w+)? +");
  if(! installed)
    return 0;

  ver = ereg_replace(string: installed, replace: "\1",
                     pattern: "^\wi +" + prefix_escaped + "\s+(([0-9]:)?[0-9][0-9A-Za-z.+~-]+?)\s+.*$");

  if(ver == installed)
    return 0; # Cannot extract version

  ver = fips_check(ver:ver);
  if(isnull(ver))
    return NULL; # fips_check failed unexpectedly

  if(get_one_kb_item("Host/Ubuntu"))
    ubuntu_flag = 1;

  pkgver = _find_package_branch(version:ver, ubuntu:ubuntu_flag);
  release_trimmed = release;
  if(!ubuntu_flag && preg(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?"))
  {
    release_trimmed = pregmatch(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?");
    if(isnull(release_trimmed))
      release_trimmed = "Release_trimmed regex broke, which is not possible.";
    else
      release_trimmed = release_trimmed[1];
  }

  # Here's the actual package release to release check. That's really far down.
  if(pkgver && release != pkgver && ! match(string: pkgver, pattern: release_trimmed+".*"))
    return 0;

  deb_pkg_tests_add( prefix + '_' + ver );
  if(deb_ver_cmp(ver1: ver, ver2: reference) < 0)
  {
    # Added a check for a minimum version.
    if(isnull(min) || (deb_ver_cmp(ver1:ver, ver2:min) >= 0))
    {
      deb_report_add(install_ver:ver, ref_ver:reference, prefix:prefix);
      deb_structured_report(install_ver:ver, ref_ver:reference, prefix:prefix, cves:cves);
      return 1;
    }
  }
  return 0;
}

##
# Alias to deb_check
#
# @param [prefix:string] package name (ie: python)
# @param [release:string] Debian release number (optional)
# @param [reference:string] version and release number (ie: 2.6.6-3+squeeze7)
# @param [min:string] minimum version and release number to check (optional)
#
# @remark This function has the side-effect of modifying deb_report
#
# @return [int] 1 if package installed and min <= package < reference
#              and Host OS release == release
#         0 otherwise
##
function ubuntu_check(osver, pkgname, pkgver,min)
{
  return deb_check(release:osver, prefix:pkgname, reference:pkgver, min:min);
}

##
# Checks if package is fips package. Strip out fips and return package name.
#
# @param [ver:string] package version extracted from dpkg_l
#
# @return [string|NULL] revised version string without "fips"
#         original version string if not a fips package
#         NULL if ereg_replace fails
##
function fips_check(ver)
{
  var ver_stripped, ver_match, fips_pattern;
  fips_pattern = "(\d+.*(?:ubuntu|debian))\d+\.fips\.(\d+.*)$";
  ver_match = pregmatch(string:ver, pattern:fips_pattern);
  if(!isnull(ver_match))
  {
    ver_stripped = ereg_replace(string:ver, pattern:fips_pattern, replace:ver_match[1] + ver_match[2]);
    if(!isnull(ver_stripped) && strlen(ver_stripped)) return ver_stripped;
    else return NULL;
  }
  else if(preg(string:ver, pattern:"\d+.*(\.fips\.).*$"))
  {
    # Older method of just removing .fips in case the supposed official pattern isn't met
    ver_stripped = ereg_replace(string:ver, pattern:"\.fips\.", replace:".");
    if(!isnull(ver_stripped) && strlen(ver_stripped)) return ver_stripped;
    else return NULL;
  }
  else return ver;
}
