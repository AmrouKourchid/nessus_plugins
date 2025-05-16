#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# oracle_http_server_patch_func.inc
#
# Revision: 1.2

include("compat_shared.inc");

##
# Function to check if the patch has been applied.
# @param install [List] of the product install like ['Oracle/OHS/c:\oracle\middleware\oracle_home/Version', '12.1.3.0.0']
# @param min_patches [NestedArray] of minimum patch and fix_ver for each product version
# @param severity - report severity (note, warning, hole)
##
function oracle_http_server_check_vuln(install, min_patches, severity)
{
  var product = 'Oracle HTTP Server';

  if (empty_or_null(install) || empty_or_null(min_patches))
    exit(1, 'oracle_http_server_check_vuln() missing argument: install or min_patches');

  var report = '';
  var path = install[0];

  # Pull path out of KB data
  path = path - 'Oracle/OHS/';
  path = path - '/EffectiveVersion';

  var installed_version = install[1];
  var base_version = ereg_replace(pattern:"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*", string:installed_version, replace:"\1");

  if (empty_or_null(min_patches[base_version]))
  {
    audit(AUDIT_INST_PATH_NOT_VULN, product, base_version, path);
  }

  if (empty_or_null(min_patches[base_version]['fix_ver']) || empty_or_null(min_patches[base_version]['patch']))
  {
    exit(1, 'oracle_http_server_check_vuln() missing argument: "fix_ver" and "patch" are both required in the min_patches array');
  }

  # Check version for supersession
  if (ver_compare(ver:installed_version, fix:min_patches[base_version]['fix_ver'], strict:FALSE) >= 0)
  {
    audit(AUDIT_INST_PATH_NOT_VULN, product, base_version, path);
  }

  # Check if specific patch is installed
  var patchesinstalled = query_scratchpad(
    'SELECT patchid FROM oracle_patches WHERE ohome=? AND patchid=?;',
    path,
    min_patches[base_version]['patch']
  );
  if (!empty_or_null(patchesinstalled))
  {
    audit(AUDIT_INST_PATH_NOT_VULN, product, base_version, path);
  }

  report =
    '\n  Path           : ' + path +
    '\n  Version        : ' + base_version + 
    '\n  Required patch : ' + min_patches[base_version]['patch'] + '\n';

  security_report_v4(port:0, extra:report, severity:severity);
}
