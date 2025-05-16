#TRUSTED 6bbe2a91a3cc36d6bcce2c808921a76e97ca12d28ff7527eef61d90c8b7d464eea006d8c72dc5fae9a7baf33b8b24d0a118f1522b678f76a67bebc48f477496274a288fcf2839bf7a98fadb0ee3a85ee20046ac7817b3378d75e0610ad0cba50a242012cb3f7f5f7b92514d1fa2f2fe269f7842b2c96a06cd61abd87a215d53933fe390e874adb23e5be3624e6cff1ac2f36e3f836b29499f0429feb613b938ff9c520841b367e80d9a0b99e2d99f6fb5684aec5efac2dee6e89be0b3d999873b9cd80aa854200290eddac7d474765bdeed86df819a5aef6e09e7afe36b8d84f42ac6ca39cb4e3c7d04f187b12755e531dab0dc05fe6236c8311576e8e158688fb2b61f0c0cc64215bcac51b76815ba47eddbd2fd783c807742e91776d19c41e563ea0f1a2580bfb53c8b13315491c1a628757dc3ed53d805c758f36b834c5fcbb000ad4320d8c4c121654a3f48672c9871da9219bd0ffbc2b5a4b2c9cfebcedb5815ff19c97c735194b25ea959ce8ed06bf00933d0e1e4a347eb1fc6621903e0def920340f7c68d607eed2e3627fc21a9ccd857d6c95d4992941b2d2f067108379aae3133961134b90474c892204c55f9900f2241e9f7192ee1b30342f8a68d7c6f1ccdabe5b218d975a859e0a03656e64720da0d172796164b02b011c23e638629fecf3f9ade9dba8787fddfc4c0a19ec7fdf2e6bcc4d270ae2bfb7bf89a46
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
# mozilla_version.inc
# Revision: 1.7
#

include("compat_shared.inc");
include_if("patch_log.inc", 80502);
include_if("patch_globals.inc", 80502);

global_var MOZ_PRODUCTS = make_array('firefox', 'Firefox', 'thunderbird', 'Thunderbird', 'seamonkey', 'Seamonkey');

##
# Determine to check if a Mozilla product is vulnerable
#
# @param installs An array of install keys
# @param product The product we are checking for.  Should be 'firefox', 'thunderbird', or 'seamonkey'
# @param esr A boolean value to determine if we are checking the ESR branch
# @param fix The fixed version
# @param min The minimum version, used to specify a branch
# @param skippat The pattern of branches to skip
# @param severity The severity rating for reporting
# @param xss A boolean value to determine if the XSS kb item has to be set
# @param xsrf A boolean value to determine if the XSRF kb item has to be set
#
# @return NULL if there is an error
#
##
function mozilla_check_version(installs, version, path, product, esr, fix, min, skippat, severity, xss, xsrf)
{
  local_var key, match, report, port;
  local_var info, ver_esr, esr_ui, be;

  if (esr) esr_ui = ' ESR';
  else esr_ui = '';

  report = '';
  info = '';

  # Validate parameters
  if (fix !~ '^[0-9\\.]+$') 
  {
    err_print('mozilla_check_version: invalid version fix=', fix);
    return NULL;
  }
  if (min && min !~ '^[0-9\\.]+$')
  {
    err_print('mozilla_check_version: invalid version min=', min);
    return NULL;
  }
  if (isnull(product))
  {
    err_print('mozilla_check_version: invalid product product=', product);
    return NULL;
  }
  product = tolower(product);
  if (product != 'firefox' && product != 'thunderbird' && product != 'seamonkey') 
  {
    err_print('mozilla_check_version: invalid product product=', product);
    return NULL;
  }

  if (isnull(installs))
  {
    key = 'MacOSX/' + MOZ_PRODUCTS[product];
    if (get_kb_item(key + '/is_esr'))
      ver_esr = ' ESR';
    else
      ver_esr = '';
    if (isnull(version) || isnull(path))
    {
      err_print('mozilla_check_version: missing version or path');
      return NULL;
    }
    # Check the version, making sure we are in the correct branch if needed
    if (!min || (min && ver_compare(ver:version, fix:min, strict:FALSE) >= 0))
    {
      if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
      {
        report +=
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version + ver_esr +
          '\n  Fixed version     : ' + fix + esr_ui +
          '\n';
        if (xss)
          set_kb_item(name:'www/0/XSS', value:TRUE);
        if (xsrf)
          set_kb_item(name:'www/0/XSRF', value:TRUE);
        security_report_v4(port:0, extra:report, severity:severity);
        exit(0);
      }
      audit(AUDIT_INST_PATH_NOT_VULN, 'Mozilla ' + MOZ_PRODUCTS[product], version + ver_esr, path);
    }
    else
      audit(AUDIT_INST_PATH_NOT_VULN, 'Mozilla ' + MOZ_PRODUCTS[product], version + ver_esr, path);
  }
  else
  {
    port = get_kb_item('SMB/transport');
    if (!port) port = 445;

    foreach key (keys(installs))
    {
      if (get_kb_item(key + '/is_esr'))
        ver_esr = ' ESR';
      else
        ver_esr = '';

      match = pregmatch(string:key, pattern:'/([a-zA-Z]+)/([0-9.]+)$');
      if (isnull(match)) continue;
      # Check that we are looking at the expected product
      if (tolower(match[1]) !~ product) continue;
  
      # Grab the version and the path
      version = match[2];
      path = installs[key];

      if (esr)
      {
        # Skip the is_esr key, and make sure the product is the ESR branch
        if ('is_esr' >< key) continue;
        if (!ver_esr)
        {
          info += ' and ' + version + ver_esr;
          continue;
        }
      }
      else
      {
        if (ver_esr)
        {
          info += ' and ' + version + ver_esr;
          continue;
        }
      }

      # Check the version, making sure we are in the correct branch if needed
      if (skippat && version =~ skippat) continue;
      if (!min || (min && ver_compare(ver:version, fix:min, strict:FALSE) >= 0))
      {
        if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
        {
          report += 
            '\n  Path              : ' + path +
            '\n  Installed version : ' + version + ver_esr +
            '\n  Fixed version     : ' + fix + esr_ui +
            '\n';
          if (nasl_level() >= 80502)
          {
            if (product == 'firefox')
              patch::log_finding(
                prod_name      : "Mozilla Firefox" + ver_esr,
                prod_family_id : patch::FAM_MOZILLA,
                location       : path,
                version        : version + ver_esr,
                missing        : fix
              );
          }
        }
        else
          info += ' and ' + version + ver_esr;
      }
      else
        info += ' and ' + version + ver_esr;
    }
  }
  if (report)
  {
    if (xss)
      set_kb_item(name:'www/' + port + '/XSS', value:TRUE);
    if (xsrf)
      set_kb_item(name:'www/' + port + '/XSRF', value:TRUE);
    security_report_v4(port:port, extra:report, severity:severity);
    exit(0);
  }

  else
  {
    if (info)
    {
      info -= ' and ';
      if (' and ' >< info) be = 'are';
      else be = 'is';

      exit(0, 'The host is not affected since Mozilla ' + MOZ_PRODUCTS[product] + ' ' + info + ' ' + be + ' installed.');
    }
  }
  exit(0);
}
