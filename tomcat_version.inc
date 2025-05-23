# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# tomcat_version.inc
# Revision: 1.13
#

include("compat_shared.inc");
include("http.inc");
include("install_func.inc");
include("http.inc");

##
# Performs a version check for Apache Tomcat
#
# @param fixed The fixed version to check against; version string or list of version strings
# @param fixed_display The version to display if no fix has been released.
# @param severity The reporting level (note, warn, hole) desired; constant
# @param min The minimum version that is vulnerable; not compatible with 'fixed' as a list ; version string
# @param paranoid The paranoid flag if a paranoid check is desired; integer
# @param xss A flag to set XSS KB
# @param xsrf A flag to set XSRF KB
# @param all_vuln_ceiling Catch-all - used when fixed is a list; version string
# @param granularity_regex Regular expression to fail versions which are not granular enough for a check; string
# @remark This function may fork; this function never returns
##
function tomcat_check_version(fixed, fixed_display, severity, min, paranoid, xss, xsrf, all_vuln_ceiling, granularity_regex)
{
  local_var report, br, f, port, ver, backported, fixed_string, install;

  get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
  install = get_single_install(app_name:"Apache Tomcat", exit_if_unknown_ver:TRUE, combined:TRUE);

  if (!empty_or_null(install['port']) )
    port = install['port'];

  # If install is managed by the package manager, we want to use the OS-specific local checks
  if (!paranoid && report_paranoia < 2 && install['Managed'])
    audit(AUDIT_HOST_NOT, 'relevant to this plugin as Tomcat was installed by a package manager');

  # Tomcat installs are known to contain backported fixes
  # quite often - we do not want to report on those if the
  # scan is not in paranoid mode
  if (!paranoid && report_paranoia < 2 && install["backported"])
    audit(AUDIT_BACKPORT_SERVICE, port, "Apache Tomcat");

  ver  = install["version"];

  # Protect against array/list being provided as 'min' param
  if (typeof(min) == 'array')
    audit(AUDIT_FN_FAIL, "Parameter 'min' cannot be a list or array. tomcat_check_version");

  # Check detected version granularity if regex is passed in
  if (!isnull(granularity_regex))
  {
    if (ver =~ granularity_regex)
    {
      if (empty_or_null(port))
        audit(AUDIT_VER_NOT_GRANULAR, "Apache Tomcat", install["version"]);
      else
        audit(AUDIT_VER_NOT_GRANULAR, "Apache Tomcat", port, install["version"]);
    }
  }

  # Check if detected version is below a minimum level
  # and thus is not vuln. This is not compatible when a list
  # of fixed versions is passed in since each in such a list
  # is constrained to the same major.minor branch.
  # Example:
  #  vuln range: 3.3.3 - 4.5.5
  # Thus, tomcat_check_version(fixed:"4.5.6", min:"3.3.3", ...)
  if (! isnull(min) && (typeof(fixed) != 'array'))
    if (tomcat_ver_cmp(ver: ver, fix: min, same_branch: 0) < 0)
      if (empty_or_null(port))
        audit(AUDIT_INST_PATH_NOT_VULN, "Tomcat", install['path'], ver);
      else
        audit(AUDIT_LISTEN_NOT_VULN, "Tomcat", port, ver);

  fixed = make_list(fixed);
  br = (max_index(fixed) > 1);

  # Check if version is in the all-vuln range. This is intended to be
  # used if a list of fixed versions is to be checked AND you'd like to
  # define a cut-off version below which everything else is vuln.
  # Example:
  #   vuln range one:   4.5.0 - 4.5.5
  #   vuln range two:   4.1.0 - 4.1.5
  #   vuln range three: everything < 4.0.0
  # Thus, tomcat_check_version(fixed:make_list("4.5.6", "4.1.6"), all_vuln_ceiling:"4.0.0", ...)
  # and this section simply checks if the detected version is below
  # the ceiling and thus, vuln.
  # Reported fix is a string comprised of the versions in the fixed list
  # that is passed
  if (
        !isnull(all_vuln_ceiling) &&
        isnull(min) &&
        tomcat_ver_cmp(ver: ver, fix: all_vuln_ceiling, same_branch: 0) < 0
  )
  {
    if(fixed_display)
      fixed_string = fixed_display;
    else
      fixed_string = join(fixed, sep:" / ");

    if (!empty_or_null(port))
      if (xss)
        set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
      if (xsrf)
        set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

    if (report_verbosity > 0)
    {
      report = "";
      if (!empty_or_null(install['path']))
        report += '\n  Path              : ' + install['path'];
      report += '\n  Installed version : ' + ver +
                '\n  Fixed version     : ' + fixed_string + '\n';
    }
    if (empty_or_null(port))
      security_report_v4(port: 0, extra: report, severity: severity);
    else
      security_report_v4(port: port, extra: report, severity: severity);

    exit(0);
  }

  # Do normal version checks now
  foreach f (fixed)
  {
    if (tomcat_ver_cmp(ver: ver, fix: f, same_branch: br) < 0)
    {
      if (!empty_or_null(port))
        if (xss)
          set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
        if (xsrf)
          set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

      report = NULL;
      if(fixed_display)
        f = fixed_display;
      if (report_verbosity > 0)
      {
        report = "";
        if (!empty_or_null(install['path']))
          report += '\n  Path              : ' + install['path'];
        report += '\n  Installed version : ' + ver +
                  '\n  Fixed version     : ' + f + '\n';
      }

      if (empty_or_null(port))
        security_report_v4(port: 0, extra: report, severity: severity);
      else
        security_report_v4(port: port, extra: report, severity: severity);
      exit(0);
    }
  }
  if (empty_or_null(port))
    audit(AUDIT_INST_PATH_NOT_VULN, "Tomcat", ver, install['path']);
  else
    audit(AUDIT_LISTEN_NOT_VULN, "Tomcat", port, ver);
}

##
# Compares two Tomcat versions
#
# @param ver The version to be checked for vulnerability; string
# @param fix The fixed version to check against; string
# @param same_branch Constrains check to same branch; boolean
# @return -1    if ver < fix
#          0    if ver == fix
#          1    if ver > fix
#          NULL error, invalid format
##ƒpr
function tomcat_ver_cmp(ver, fix, same_branch)
{
  local_var     pat, vv, ff, i, v, f, n, pad;
  pad = FALSE;

  if (ver =~ ".*(M|-RC)[0-9]+")
  {
    pad = TRUE;
    if ("M" >< ver)
     ver = ereg_replace(string:ver, pattern:"M", replace:"");
    if ("-RC" >< ver)
     ver = ereg_replace(string:ver, pattern:"-RC", replace:"");
  }
  if (fix  =~ ".*(M|-RC)[0-9]+")
  {
    pad = "TRUE";
    if ("M" >< fix)
     fix = ereg_replace(string:fix, pattern:"M", replace:"");
    if ("-RC" >< fix)
     fix = ereg_replace(string:fix, pattern:"-RC", replace:"");
  }
  # Ensure versions are the same length after we drop the
  # -RC or M from the version number
  if (pad)
  {
    if (strlen(fix) < strlen(ver)) fix = fix + ".0";
  }


  # Just ensure version is numeric
  pat = "^[0-9.]+";

  vv = pregmatch(string: ver, pattern: pat, icase: FALSE);
  if (isnull(vv))
  {
    err_print('tomcat_ver_cmp: invalid version ver=', ver);
    return NULL;
  }

  ff = pregmatch(string: fix, pattern: pat, icase: FALSE);
  if (isnull(ff))
  {
    err_print('tomcat_ver_cmp: invalid version fix=', fix);
    return NULL;
  }

  vv = split(ver, sep: '.', keep: 0);
  ff = split(fix, sep: '.', keep: 0);
  n = max_index(vv); if (max_index(ff) > n) n = max_index(ff);

  # If a list was passed to tomcat_check_version(), the checks
  # are constrained to the same major.minor branch.
  if (same_branch)
  {
    v = int(vv[0]);
    f = int(ff[0]);
    if (v != f) return 0;
    if (n >= 2)
    {
      v = int(vv[1]);
      f = int(ff[1]);
      if (v != f) return 0;
    }
  }

  for (i = 0; i < n; i ++)
  {
    v = int(vv[i]); f = int(ff[i]);
    if (v < f) return -1;
    if (v > f) return 1;
  }

  return 0;
}
