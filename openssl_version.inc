#TRUSTED 3572eb98b20df523873e9776107c9dd564a920c675db37365fa5261ddf4b2802c0a054c2ccc8b79f0ead80a7bf1ca7acb7c7844fad1e864fc9b54923ef585fa3074d2804b89db09b63704a1a583570d2cd2ce77f968c968310706fbfb863153decd571637b16782ef6b9272db605b61b1180244813e0e1a09b82aa923bab36462fd659c9ec1d9f9fe9780a4f396477defed7eeae6f3461761f32ae35d5b0e8f8943394fb1da8e4a538b649cffc67ba401e3e07fe6d9faddb95b92ae63f866f7f3a6e4ae7e1772586929ab7e9c9fc61681c550fbb517a5de690981019e3c0997cae1567abe459b7f1fb10a3b26427ec2103fd1cbf26e2b72f6c8e3067feef423311e76e07fa00355027639b07c575e1044a58c110f3c97683a17061abc47f64713f9314c9995bf0f2e0a9a3dbb6235da88fba3ca474d39fa399bcd22f1405c9a60cd9a91a3dd112ca6bb4e3f6fa2c2f1569160245b6ed004a7d390dd564c4ed1d28b3b75a35208b01a124c817d74045d1cbb27ffe9eeb7ae80fc1b53465d9da1cbafb482018ed3d2bf16e15fe641bd646da7b07ac9417e235f546a0fb1030cca7724edd30e62ec99fae46752b88c47d9bd0e3944fcfe003ea5fcda28cb6559f5fe2e837379f30d091d1611891a1d28b1c8a8b1a877b5cb1dc53e2eea65b4fd4c99ce81a5056e9f1271becd3e21c96408428b502ce915660a0c7c8040579e46456
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.1
#

include("compat_shared.inc");

global_var app_name = "OpenSSL";

# compares two OpenSSL versions. each version must be all numeric and
# can end with a letter, optionally with a beta version number
# e.g. 0.9.6e
# or   1.0.0-beta1
#
# Additional text like -fips, -pre, or -rhel5 is erased & ignored currently.
#
# args: ver, fix - versions to compare
#
# returns -1	if ver < fix
#          0	if ver == fix
#          1	if ver > fix
#	   NULL	error, invalid format
#
function openssl_ver_cmp(ver, fix, same_branch, is_min_check)
{
  local_var	pat, vv, ff, i, v, f;

  # Do not anchor on the right, version might be "0.9.8e-fips-rhel5"
  pat = '^([0-9]+)\\.([0-9]+)\\.([0-9]+)([a-z]+)?((-fips)?(-beta([0-9]+))?(-pre([0-9]+))?)?';

  vv = eregmatch(string: ver, pattern: pat, icase: FALSE);
  if (isnull(vv))
  {
    err_print('openssl_ver_cmp: invalid version ver=', ver);
    return NULL;
  }

  ff = eregmatch(string: fix, pattern: pat, icase: FALSE);
  if (isnull(ff))
  {
    err_print('openssl_ver_cmp: invalid version fix=', fix);
    return NULL;
  }

  for (i = 1; i <= 3; i ++)
  {
    v = int(vv[i]);
    f = int(ff[i]);
    if (same_branch)
    {
      if (v != f) return 0;
    }
    else
    {
      if (v < f) return -1;
      if (v > f) return 1;
    }
  }

  # a < z is safe
  # z < za is safe
  # za < zz is safe
  v = vv[4];
  f = ff[4];
  if (v < f) return -1;
  if (v > f) return 1;

  # handles match 8 for -beta, and match 10 for -pre
  if ((! isnull(vv[8]) || ! isnull(ff[8])) || (! isnull(vv[10]) || ! isnull(ff[10])))
  {
    if ((! isnull(vv[8]) || ! isnull(ff[8])))
    {
      v = int(vv[8]);
      f = int(ff[8]);
    }
    else
    {
      v = int(vv[10]);
      f = int(ff[10]);
    }

    if (v != f)
    {
      # No beta or pre is newer than betaXXX or preXXX

      # In a min_check, betas/pres are not vuln
      if (is_min_check)
      {
        if (v == 0) return -1;
        if (f == 0) return 1;
      }
      else
      {
        # In a normal check, betas/pres are vuln
        if (v == 0) return 1;
        if (f == 0) return -1;
      }

      if (v < f) return -1;
      if (v > f) return 1;
    }
  }
  return 0;
}

####

global_var	port, ver;

##
# Checks if server's OpenSSL version is vulnerable.
#
# @param  list   fixed list of fixed versions
# @param  int    severity reporting severity
# @param  string min minimum vulnerable version
#
# @remark This function does not return, it either reports or exits.
##
function openssl_check_version(fixed, severity, min)
{
  local_var port;
  local_var kb_base;
  local_var banner, version, backported;
  local_var fix, same_branch;
  local_var report;

  report = '';

  # Make sure OpenSSL is installed.
  port = get_kb_item("openssl/port");
  if (isnull(port)) audit(AUDIT_NOT_INST, app_name);

  # Get relevant data for installed version.
  kb_base = "openssl/" + port + "/";
  banner = get_kb_item(kb_base + "pristine_banner");
  version = get_kb_item(kb_base + "pristine_version");
  backported = get_kb_item(kb_base + "backported");

  # If the banner is backported, and we're not running a paranoid
  # scan, audit out.
  if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, app_name);

  # Make sure the version is above the min vuln version.
  if (!isnull(min) && openssl_ver_cmp(ver:version, fix:min, same_branch:FALSE, is_min_check:TRUE) < 0)
    audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

  # Check against list of fixes.
  fixed = make_list(fixed);
  if (len(fixed) > 1) same_branch = TRUE;
  else same_branch = FALSE;

  foreach fix (fixed)
  {
    if (openssl_ver_cmp(ver:version, fix:fix, same_branch:same_branch) < 0)
    {
      report =
        '\n  Banner           : ' + banner +
        '\n  Reported version : ' + version +
        '\n  Fixed version    : ' + fix;

      if (backported) report +=
        '\n\nBased on the banner, security patches may have been backported to' +
        '\nthis install of OpenSSL. A local check is needed to confirm the' +
        '\npresence of this vulnerability.';

      report += '\n';
      security_report_v4(port:port, severity:severity, extra:report);
      exit(0);
    }
  }

  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
}

# Local Variables:
# mode:Fundamental
# End:
