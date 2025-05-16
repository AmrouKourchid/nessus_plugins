#TRUSTED 2839bb937ca1732839c72f6dee262d19073b7c2ddd461a2f8b3fd94184cf9b114511fade9254cd47bc0f29c391d9a1ef50f4cd948afb1d3d707ecf1ae36a9e43e8df710f83bb587db16e5e00a8d96b2cdf06822f026ab2f173ed88871bfc2ee4dd9e1eb810348fc0eb8a08536f0cc1b4f5e8211089cd7dbb6e4de3ff78b573faa69156ad1bd753c9c4baaadb1194fbd981b6e0f51b71b08b242e4be1eddf62b95cf4cf18c063b98f574fd04a403339ab1473e3ee471bf0ee3681dcbfe8293a80ffe201742be915df4a25e47644146e7461b5d3966d778e08a46197b6eb81338184dafbbeb65cf442221ce5cef52dd26a6e62d2c434afa0ab5503720c4c163f2ad954cd7776c5c864be6e3a4803aa520d1b029eb7d2f48178083838cf9c0ec4abefb9f14748aea340bf9886dac857f2a167b44312e2e2095c23364b3c43e7238947db5235e749eed93a1b743891212251399b7a7d011e660ad19d228a0ca7b71636f80b0dcb4768930b3504a348deb4faaa0b126ebd1abfc1f69b23860bd38eb979ef7057df3be4912b8c3fc09f6677f20cb1eb94acd2ff10fc72375487e02660015209099125ef8b2d4d7f22b80ff7ff4a9b2deab847c93e340c79571afd2b9351bb9b924912f4c01f448695258b8b2818ffcfadf20ddb420d56e3761ace36a0d87d48c327dfd159ce3eeeb35b9d753cc6995e24bc538c158049abad2a08df80
#TRUST-RSA-SHA256 310951f336e86191a9f4047633781a48b911c89e17642effd05984b73111028ae788047cf102f10ee2fc483f50f66822f80edc527b40d3da2dc5921f1c9273a89ed0d7f104fdef13f5b380c7e7e0bf6e0773acce542523e9bcef90360fc082768c006f34bf8c213a802ad9f1473bd2167e9708cd08a29e54f98c90549947c84336559b4286ad8da06b1af9e134101bb57753bfc59e00c3d000c8d38033a49eb67da8bd9d996efed42e0d7cda89cddd67328df0d05fc89ab9ba355398b8ef3bcaff868da5a4f59b9d41120f4cc3726e489ad0d59b1c4b06e5243837f5d191f517e90cc82ccf8ad70ee1299c5c4a2ad3ca001ba9f637a68182e86ee30c98ae97e69b7aa6381963209bdd33d12160a4a0debdc20e3c41307ada5e983fd6cab2b5ec9f7e6225e559f2d0b8ad4761e7b9c68e0343ecda9edc9e95cb4961cceef48faedd976f17bb47c399e39e88489bf3313fc0af5f0e59fd9281709bb6d1f0b38d2b78c35c69955ec06cd90566573f6430515fd0be366411e35bceffb19d6f28b77c9660da7c7bd202465971a942372833fdd8858dcfffae2cebd95bf227a25fe8fa94a6bad8205a230b8d579af8b4012fdabea365e8cb22533460b69fe567bf3a32c5ebd063825270ab371422bc9be6b3295a75791c72cec2df52c2e418ad4d738d03922bb5be3ecb914f58fdf4013416e0f7d801dc5b53beef2af881d74bc47ae6
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# This include file provides functions used for Junos patch auditing
#
# junos.inc
#
# Revision: 1.35
###

include("compat_shared.inc");

# Some constants used with the 'flags' parameter of check_model()
global_var E_SERIES   = 1 << 0;
global_var EX_SERIES  = 1 << 1;
global_var G_SERIES   = 1 << 2;
global_var IC_SERIES  = 1 << 3;
global_var J_SERIES   = 1 << 4;
global_var M_SERIES   = 1 << 5;
global_var MX_SERIES  = 1 << 6;
global_var SRX_SERIES = 1 << 7;
global_var T_SERIES   = 1 << 8;
global_var LN_SERIES  = 1 << 9;
global_var JCS_SERIES = 1 << 10;
global_var PTX_SERIES = 1 << 11;
global_var QFX_SERIES = 1 << 12;
global_var F_SERIES   = 1 << 13;
global_var ACX_SERIES = 1 << 14;
# It appears the only series that aren't routers are :
# EX / QFX (switches)
# IC (access control)
# JCS (control system)
global_var ALL_ROUTERS = ACX_SERIES | E_SERIES | F_SERIES | G_SERIES | J_SERIES | M_SERIES | MX_SERIES | PTX_SERIES | SRX_SERIES | T_SERIES | LN_SERIES;
# BX series appears to be a solution comprised of M series, MX series, and JUNOScope software

##
# Compares two dates in the format YYYY-MM-dd
#
# @anonparam a date to compare
# @anonparam b date to compare
# @return -1 if a < b
#          0 if a == b
#          1 if a > b
##
function compare_build_dates()
{
  local_var a, b, i;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (isnull(a))
  {
    err_print('compare_build_dates(): missing first argument');
    return NULL;
  }
  if (isnull(b))
  {
    err_print('compare_build_dates(): missing second argument');
    return NULL;
  }

  a = split(a, sep:'-', keep:FALSE);
  b = split(b, sep:'-', keep:FALSE);

  for (i = 0; i < 3; i++)
  {
    if (int(a[i]) < int(b[i]))
      return -1;
    else if (int(a[i]) > int(b[i]))
      return 1;
  }

  return 0;
}

##
# Checks if the given model is a member of one of the series denoted by 'flags'
#
# @param model        model number to check
# @param flags        a bitmask of *_SERIES flags
# @param exit_on_fail exits if 'model' is not a member of the 'flags' series (instead of returning)
#
# @return TRUE if 'model' is a member of any of the series denoted by 'flags',
#         FALSE otherwise
##
function check_model(model, flags, exit_on_fail)
{
  if (isnull(model))
  {
    err_print('check_model(): missing argument "model"');
    return NULL;
  }
  if (isnull(flags))
  {
    err_print('check_model(): missing argument "flags"');
    return NULL;
  }

  if (flags & E_SERIES && model =~ '^E(RX)?[0-9]+')  # E-series begin with either E, or ERX. but not EX.
    return TRUE;
  else if (flags & EX_SERIES && model =~ '^EX[0-9]+')
    return TRUE;
  else if (flags & G_SERIES && model =~ '^G[0-9]+')
    return TRUE;
  else if (flags & IC_SERIES && model =~ '^IC[0-9]+')
    return TRUE;
  else if (flags & J_SERIES && model =~ '^J[0-9]+')
    return TRUE;
  else if (flags & JCS_SERIES && model =~ '^JCS[0-9]+')
    return TRUE;
  else if (flags & LN_SERIES && model =~ '^LN[0-9]+')
    return TRUE;
  else if (flags & M_SERIES && model =~ '^M[0-9]+')
    return TRUE;
  else if (flags & MX_SERIES && model =~ '^v?MX[0-9]+')
    return TRUE;
  else if (flags & PTX_SERIES && model =~ '^PTX[0-9]+')
    return TRUE;
  else if (flags & QFX_SERIES && model =~ '^QFX[0-9]+')
    return TRUE;
  else if (flags & SRX_SERIES && (model =~ '^v?SRX[0-9]+' || model =~ '^firefly-perimeter'))
    return TRUE;
  else if (flags & T_SERIES && model =~ '^T[0-9]+')
    return TRUE;
  else if (flags & ACX_SERIES && model =~ '^ACX[0-9]+')
    return TRUE;

  if (exit_on_fail)
    exit(0, 'Model ' + model + ' is not affected.');
  else
    return FALSE;
}

##
# Compares two Junos version numbers.  This function assumes that the only
# valid release types are A, B, I, F, R, and S
#
# This function will return 0 if either 'a' or 'b' are interim releases,
# either 'a' or 'b' are not in the expected format (x.yRr.b, .b is optional),
# or the major release numbers of 'a' and 'b' are different
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_base_ver_compare()
{
  local_var a, b, match, a_major, b_major, a_type, b_type, a_rev, b_rev, a_build, b_build;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # http://kb.juniper.net/InfoCenter/index?page=content&id=KB1868
  # e.g. 11.1R3.4
  # 11.1 - major version number
  # R - release type
  # 3 - revision
  # 4 - build (optional)
  match = pregmatch(string:a, pattern:'^([0-9]+\\.[0-9]+)([A-Z])([0-9]+)(\\.([0-9]+))?$');
  if (isnull(match))
  {
    err_print('_junos_base_ver_compare(): Error parsing version: ' + a);
    return 0;
  }
  a_major = match[1];
  a_type = ord(match[2]);
  a_rev = int(match[3]);
  a_build = int(match[5]);

  match = pregmatch(string:b, pattern:'^([0-9]+\\.[0-9]+)([A-Z])([0-9]+)(\\.([0-9]+))?$');
  if (isnull(match))
  {
    err_print('_junos_base_ver_compare(): Error parsing version : ' + b);
    return 0;
  }
  b_major = match[1];
  b_type = ord(match[2]);
  b_rev = int(match[3]);
  b_build = int(match[5]);

  # different major versions get supported differently, only like releases can be compared
  if (a_major != b_major)
    return 0;

  # Juniper says if an interim release is being used, there's no reliable way to
  # tell if it's missing security updates
  if (a_type == ord('I') || b_type == ord('I')) return 0;

  # If the types don't match and release types 'R' and 'S' are not being compared
  if (a_type != b_type && !(a_type >= ord('R') && b_type >= ord('R')))
  {
    # explicitly check if alpha vs beta is being compared
    if (a_type == ord('A') && b_type == ord('B')) return -1;
    if (a_type == ord('B') && b_type == ord('A')) return 1;

    # A (alpha) and B (beta) are always < F, R and S (feature velocity, release, security)
    if (a_type <= ord('B') && b_type >= ord('F')) return -1;
    if (a_type >= ord('F') && b_type <= ord('B')) return 1;

    # If we've gotten this far, one of a_type and b_type is F and the other is R or S
    # They can't be directly compared
    return 0;
  }

  # we should only get this far if the release types are the same,
  # or release types R and S are being compared.  For the latter
  # scenario, Juniper says the 'R' and 'S' can be ignored with
  # one exception (see below)
  if (a_rev < b_rev) return -1;
  if (a_rev > b_rev) return 1;
  if (a_build < b_build) return -1;
  if (a_build > b_build) return 1;

  # Juniper says if 'R' and 'S' versions are being compared and the major version,
  # revision, and build are identical, the 'S' version is more current
  if (a_type < b_type) return -1;
  if (a_type > b_type) return 1;

  return 0;
}

##
# Compares two Junos Space version numbers.  This function assumes that the only
# valid release types are R and P
#
# This function will return 0 if the versions are the same, and expects the
# versions to be in the format x.x[RP]x.x with [RP]x.x as optional.
#
# @param ver (first) version to compare
# @param fix (second) fixed version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_space_ver_compare(ver, fix)
{
  local_var match, v_major, f_major, v_minor, f_minor, v_type, f_type;
  local_var v_rev, f_rev, v_build, f_build;

  # http://kb.juniper.net/InfoCenter/index?page=content&id=KB1868
  # e.g. 11.1R3.4
  # 11.1 - major version number
  # R - release type
  # 3 - revision
  # 4 - build (optional)
  match = pregmatch(string:ver, pattern:'^([0-9]+)\\.([0-9]+)(([A-Z])([0-9]+)(\\.([0-9]+))?)?$');
  if (isnull(match))
  {
    err_print('_junos_space_ver_compare(): Error parsing version : ' + ver);
    return 0;
  }
  v_major = match[1];
  v_minor = match[2];
  if (!isnull(match[4]))
    v_type = ord(match[4]);
  v_rev = int(match[5]);
  v_build = int(match[7]);

  if (v_type && (v_type != ord('R') && v_type != ord('P')))
  {
    err_print('check_junos_space(): Error invalid release type: ' + v_type);
    return 0;
  }

  match = pregmatch(string:fix, pattern:'^([0-9]+)\\.([0-9]+)(([A-Z])([0-9]+)(\\.([0-9]+))?)?$');
  if (isnull(match))
  {
    err_print('_junos_space_ver_compare(): Error parsing version : ' + fix);
    return 0;
  }
  f_major = match[1];
  f_minor = match[2];
  if (!isnull(match[4]))
    f_type = ord(match[4]);
  f_rev = int(match[5]);
  f_build = int(match[7]);

  if (f_type && (f_type != ord('R') && f_type != ord('P')))
  {
    err_print('check_junos_space(): Error invalid release type: ' + f_type);
    return 0;
  }

  # With Junos Space major versions can be compared
  if (v_major < f_major) return -1;
  if (v_major > f_major) return 1;
  if (v_minor < f_minor) return -1;
  if (v_minor > f_minor) return 1;

  # Junos Space only has 'R' and 'P' types.
  # In most cases we will rather want to compare the rev and build
  if (v_rev < f_rev) return -1;
  if (v_rev > f_rev) return 1;
  if (v_build < f_build) return -1;
  if (v_build > f_build) return 1;

  # If we do have a equal Rev and Build then
  # 'P' > 'R'
  if (v_type == ord('R') && f_type == ord('P')) return -1;
  if (v_type == ord('P') && f_type == ord('R')) return 1;

  return 0;
}

##
# Compares two Junos special release version numbers
#
# This function assumes all versions will be in the format:
#
# 10.4X24
#
# Everything up to and including the X and the following numbers
# should match, and everything after should be compared.  The
# numbers are compared left to right. So the following two numbers
# would not be compared:
#
# 10.4X24
# 10.4X25.8
#
# The following two would be compared:
#
# 11.4X27.20
# 11.4X27.37
#
# This will be treated as comparing .20 to .37.  In other words, it
# makes the (perhaps incorrect) assumption that a given release train
# (for example, a 11.4X27 release) does not have multiple branches
# containing multiple fixes.
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_special_ver_compare()
{
  local_var a, b, a_match, b_match, a_release, b_release, a_train, b_train;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  a_match = pregmatch(string:a, pattern:"^([\d.]+X\d+)\.(\d+)");
  if (isnull(a_match))
    exit(1, 'Error parsing Junos version : ' + a);

  b_match = pregmatch(string:b, pattern:"^([\d.]+X\d+)\.(\d+)");
  if (isnull(b_match))
    exit(1, 'Error parsing Junos version : ' + b);

  a_train = a_match[1];
  a_release = a_match[2];
  b_train = b_match[1];
  b_release = b_match[2];

  # sanity checking - the parts of each version that are stripped away should match
  if (a_train != b_train)
    return NULL;

  if (int(a_release) < int(b_release))
    return -1;
  else if (int(a_release) > int(b_release))
    return 1;

  return 0;
}

##
# Compares two Junos X version numbers.
#
# Regarding 12.1X44-D10, this document says:
#   Junos 12.1 is the latest Junos release that includes security features and is
#   considered a stable release with core functionality; hence was selected as the baseline
#   for X44.
#   D10 denotes the specific release number for the X44 release train, and will be
#   incremented by 5 for maintenance releases, for example D15, D20, and so on.
#
# This function assumes all Junos X versions will be in the format:
#
# 12.2X50-D41.1
#
# In other words, everything up to and including the D should match, and
# everything after should be compared
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_x_ver_compare()
{
  local_var a, b, idx, a_train, b_train, a_release, b_release, i;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # get the release number for each version.
  # for 12.2X50-D41.1, this means extracting 41.1
  idx = stridx(a, '-D');
  if (idx == -1)
    exit(1, 'Error parsing Junos version : ' + a);

  a_train = substr(a, 0, idx);
  a_release = substr(a, idx + 2);

  idx = stridx(b, '-D');
  if (idx == -1)
    exit(1, 'Error parsing Junos version : ' + b);

  b_train = substr(b, 0, idx);
  b_release = substr(b, idx + 2);

  # sanity checking - the parts of each version that are stripped away should match
  if (a_train != b_train)
    exit(1, 'Error comparing Junos versions ' + a + ' and ' + b);

  a_release = split(a_release, sep:'.', keep:FALSE);
  b_release = split(b_release, sep:'.', keep:FALSE);

  for (i = 0; i < max_index(a_release) || i < max_index(b_release); i++)
  {
    if (int(a_release[i]) < int(b_release[i]))
      return -1;
    else if (int(a_release[i]) > int(b_release[i]))
      return 1;
  }

  return 0;
}

##
# Compares two Junos version numbers including number which ends in -S.
#
# This function assumes all Junos -S versions will be in the format:
#
# 12.2R50-S41.1
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_ver_compare()
{
  local_var a, b, idx, a_train, b_train, a_release, b_release, i, respin, rmatch, ver_comp;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];
  respin = 0;

  # quick exit
  if (a == b) return 0;

  # get the release number for each version.
  # for 12.2S50-S41.1, this means extracting 41.1
  idx = stridx(a, '-S');

  if (idx == -1)
  {
    rmatch = pregmatch(string:a, pattern:"^([0-9.]+)([A-Z])+[0-9]\.");
    if (rmatch == 1)
    {
      # Juniper minor version bug fix (respin) found.
      respin = 1;
    }
    a_train = a;
    a_release = NULL;
  }
  else
  {
    a_train = substr(a, 0, idx-1);
    a_release = substr(a, idx + 2);
  }

  idx = stridx(b, '-S');
  if (idx == -1)
  {
    b_train = b;
    b_release = NULL;
  }
  else
  {
    b_train = substr(b, 0, idx-1);
    b_release = substr(b, idx + 2);
  }

  # check if respin version, The .10 of 17.3R3.10 means it is the 10th release of 17.3R3
  # These build number e.g. .10 are only minor bugfixes, Juniper call them respins. 
  # If a JSA states that all versions prior a S release are affected (here 17.3R3-S7) that means that a 
  # 17.3R3.10 is affected as well because it is not an S release.
  # respin is flag above, idx from the chceking for -S in fix version
  ver_comp = stridx(a_train, b_train);

  if (respin == 1 && ver_comp != -1 && !(empty_or_null(b_release))) return -1;

  # if a_train != b_train then just compare them and return the result
   # or if the releases of both are null, then just compare the beginnings
  if ((a_train != b_train) || (isnull(a_release) && isnull(b_release))) return _junos_base_ver_compare(a_train, b_train);

  # check to see if either version has a null -S portion
  if (isnull(a_release)) return -1;
  if (isnull(b_release)) return 1;

  # a_train must == b_train at this point and neither version has a NULL -S portion
  # thus we compare releases
  a_release = split(a_release, sep:'.', keep:FALSE);
  b_release = split(b_release, sep:'.', keep:FALSE);

  for (i = 0; i < max_index(a_release) || i < max_index(b_release); i++)
  {
    if (int(a_release[i]) < int(b_release[i]))
      return -1;
    else if (int(a_release[i]) > int(b_release[i]))
      return 1;
  }

  return 0;
}

##
# Checks if a Junos version is out of date.
# Compares the given version to the relevant fixed version.
# If 'ver' doesn't have a corresponding fix in 'fixes', this function assumes it is not out-of-date.
#
# @param ver          version to check
# @param fixes        a hash of fixes. key = release, value = fix. e.g. 11.1 => 11.1S1
# @param exit_on_fail exits instead of returning NULL
#
# @return the appropriate fix if 'ver' is out-of-date,
#         NULL otherwise
##
function check_junos(ver, fixes, exit_on_fail)
{
  local_var match, feature, fix, junoss, junosx, release, report, series, special;
  if (isnull(ver))
  {
    err_print('check_junos(): missing argument "ver".');
    return NULL;
  }
  if (isnull(fixes))
  {
    err_print('check_junos(): missing argument "fixes".');
    return NULL;
  }

  junosx = FALSE;
  special = FALSE;
  feature = FALSE;

  # Try to extract the release (x.y) from the version.
  #
  # X releases look different than other versions
  # (e.g., 12.2X50-D41.1 versus 10.4R13)
  #
  # there is a third kind of version that looks different. i think they're
  # called "special releases" but there may be a different, official term
  # (e.g., 11.4X27 or 12.1X44)
  match = pregmatch(string:ver, pattern:"^([0-9.]+X[0-9.]+)-");
  if(!empty_or_null(match))
    junosx = TRUE;
  else
  {
    match = pregmatch(string:ver, pattern:"^([0-9.]+X)[0-9.]+$");
    if(!empty_or_null(match))
      special = TRUE;
    else
    {
      match = pregmatch(string:ver, pattern:"^([0-9.]+F)[0-9.]+$");
      if(!empty_or_null(match))
        feature = TRUE;
      else
        match = pregmatch(string:ver, pattern:"^([0-9.]+)([A-Z])+");
    }
  }
  
  if (isnull(match))
  {
    if (exit_on_fail)
      exit(1, 'check_junos(): error parsing version : ' + ver);

    err_print('check_junos(): error parsing version : ' + ver);
    return NULL;
  }
  else
  {
    release = match[1];
    series = match[2];
  }

  # If the caller says there's no fix for a given release, we're going to assume it's not vulnerable
  if (!isnull(fixes[release + series]))
  {
    fix = fixes[release + series];
  }
  else
  {
    fix = fixes[release];
  }
  if (isnull(fix))
  {
    if (exit_on_fail)
      exit(0, 'Junos ' + ver + ' is not affected.');
    else
      return NULL;
  }

  if (
    (junosx && _junos_x_ver_compare(ver, fix) < 0) ||
    (special && _junos_special_ver_compare(ver, fix) < 0) ||
    (!junosx && !special && !junoss && _junos_ver_compare(ver, fix) < 0)
  )
  {
    return fix;
  }
  else if (exit_on_fail)
    exit(0, 'Junos ' + ver + ' is not affected.');
  else
    return NULL;
}

##
# Checks if a Junos Space version is out of date.
# Compares the given version to the relevant fixed version.
# Will either exit or print report.
# Specifically this will flag previous versions.
#
# @param ver        The version to check
# @param fix        The fixed version
# @param severity   The severity rating for reporting
# @param min        The minimum vulnerable version
# @param xss        A boolean value to determine if the XSS kb item has to be set
# @param xsrf       A boolean value to determine if the XSRF kb item has to be set
# @param sqli       A boolean value to determine if the SQLI kb item has to be set
#
# @return NULL if there was an error.
##
function check_junos_space(ver, fix, severity, min, xss, xsrf, sqli)
{
  if (isnull(ver))
  {
    err_print('check_junos_space(): missing argument "ver"');
    return NULL;
  }
  if (isnull(fix))
  {
    err_print('check_junos_space(): missing argument "fix"');
    return NULL;
  }
  if (isnull(severity))
  {
    err_print('check_junos_space(): missing argument "severity"');
    return NULL;
  }

  if (min && _junos_space_ver_compare(ver:ver, fix:min) < 0)
    exit(0, 'Junos Space ' + ver + ' is not affected.');

  if (_junos_space_ver_compare(ver:ver, fix:fix) < 0)
  {
    if (xss)
      set_kb_item(name:'www/0/XSS', value:TRUE);
    if (xsrf)
      set_kb_item(name:'www/0/XSRF', value:TRUE);
    if (sqli)
      set_kb_item(name:'www/0/SQLInjection', value:TRUE);
    security_report_v4(port:0, extra:get_report(ver:ver, fix:fix), severity:severity);
    exit(0);
  }
  else
    exit(0, 'Junos Space ' + ver + ' is not affected.');
}

##
# Generates plugin output for on out-of-date Junos install
#
# @param model    model number of the Junos device (optional)
# @param ver      currently installed Junos version
# @param fix      version to upgrade to
#
# @return plugin output
##
function get_report(model, ver, fix)
{
  local_var report;
  report = '';

  if (!isnull(model))
    report += '\n  Model             : ' + model;

  report +=
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';

  return report;
}

##
# Parses the branch of ver
#
# @param string ver  Junos version
#
# @return branch of specified version (e.g. 14.2R6 returns 14.2R, 12.1X46-D45 returns 12.1X46, etc.)
#         NULL if invalid version
##
function junos_ver_branch(ver)
{
  local_var keep, separator, branch;

  if (isnull(ver) || typeof(ver) !~ '^(string|data)$')
  {
    err_print("junos_ver_branch: 'ver' must be specified and a string");
    exit(1);
  }

  keep = TRUE;
  foreach separator (make_list("R", "F", "-", "S")) # '-' should be second to last and 'S' last
  {
    if (separator >< ver)
    {
      if (separator == "-") keep = FALSE;
      branch = split(ver, sep:separator, keep:keep);
      return branch[0];
    }
  }
}

##
# Compare detected version with fixed versions when a advisory has multiple fixed versions.
#
# @param string ver    Junos version
# @param array  fixes  nested array of advisories using 'CVEs' and 'Fixed Versions' as keys
#
# @remark This is mainly to be used for Juniper advisories covering multiple OpenSSL versions
#
# @return report including CVE IDs associated with the fixed version if affected
#         NULL if not affected
##
function junos_multi_check_and_report(ver, fixes)
{
  local_var sep, cve_ids, ver_branch, required_keys, key, month;
  local_var fix_list, fix, fix_branch, cve_report, fix_report, report_cve_ids, report;

  if (isnull(ver) || typeof(ver) !~ '^(string|data)$')
  {
    err_print("junos_multi_check_and_report: 'ver' must be specified and a string");
    exit(1);
  }

  if (empty_or_null(fixes) || typeof(fixes) != 'array')
  {
    err_print("junos_multi_check_and_report: 'fixes' must be specified and a nested array");
    exit(1);
  }

  sep = ", ";
  cve_ids = make_nested_array();

  ver_branch = junos_ver_branch(ver:ver);
  if (isnull(ver_branch)) audit(AUDIT_FN_FAIL, "junos_ver_branch", "NULL");

  foreach month (keys(fixes))
  {
    required_keys = make_list("CVEs", "Fixed Versions");
    foreach key (required_keys)
    {
      if (isnull(fixes[month][key]) || typeof(fixes[month][key]) !~ '^(string|data)$')
      {
        err_print("junos_multi_check_and_report: '"+ month +"' is missing the '"+ key +"' key or not assigned a string");
        exit(1);
      }
    }
    fix_list = split(fixes[month]["Fixed Versions"], sep:sep, keep:FALSE);
    foreach fix (fix_list)
    {
      fix_branch = junos_ver_branch(ver:fix);
      if (isnull(fix_branch) || fix_branch != ver_branch) continue;
      if (!isnull(check_junos(ver:ver, fixes:make_array(fix_branch, fix))))
      {
        if (isnull(cve_ids[fix])) cve_ids[fix] = make_list();
        cve_ids[fix] = make_list(cve_ids[fix], split(fixes[month]["CVEs"], sep:sep, keep:FALSE));
      }
    }
  }
  if (empty(cve_ids)) return NULL;

  # Sort, dedup, and report CVE IDs 
  fix_report = make_list();
  foreach fix (keys(cve_ids))
  {
    fix_report = make_list(fix_report, fix);
    cve_report += '\n    ' + join(list_uniq(sort(cve_ids[fix])), sep:sep);
    if (len(cve_ids) == 1) break; # We don't append the fixed version if there is only one fix
    cve_report += ' (fixed in ' + fix + ')';
  }

  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed versions    : ' + join(sort(fix_report), sep:' / ') +
    '\n  CVEs fixed        : ' + cve_report +
    '\n';

  return report;
}

##
# Formats a command based on whether shell handler is enabled
# @param <cmd> string Junos command in shell mode format
# @param <flag> boolean True/False signifying if we are using shell mode or cli mode
#
# @return a string of the appropriately formatted command to send using session_send_cmd
##
function junos_format_cmd(cmd, flag)
{ 
  if(flag)
  {
    if ("|" >< cmd) cmd = str_replace(string:cmd, find:"|", replace:"\|");
    cmd = "cli " + cmd;
  }
  return cmd;
}

##
# Parse Junos version into a dictionary with 4 keys.
# 1. year
# 2. quarter_release
# 3. major_release
# 4. minor_release
#
# @param version        The version to parse.
##
function parse_version(version) {
  # Below regex will ignore respin numbers as they are static build numbers used pre release
  # and so should not be relevant to us.
  var match = pregmatch(string:version, pattern:"^([0-9]+)\.([0-9]+)([FfRrXx]([0-9]+)(-[SsDd]([0-9]+)(?:\.([0-9]+))?)?)?");
  if (!isnull(match))
  {
    var parsed = {'year':match[1],
                  'quarter_release':match[2],
                  'major_release':match[4],
                  'minor_release':match[6],
                  'subminor_release':match[7]};

    # the below checks included incase the major_release, minor_release, and/or subminor_release is not present
    if (empty_or_null(parsed['major_release'])) parsed['major_release'] = 0;
    if (empty_or_null(parsed['minor_release'])) parsed['minor_release'] = 0;
    if (empty_or_null(parsed['subminor_release'])) parsed['subminor_release'] = 0;
    return parsed;
  }
}

##
# Checks if a Junos version is between X min vuln version and Y fixed version.
# Sets the fixed version if target version is found to be between X and Y range.
#
# @param target_version        The version to check.
# @param vuln_ranges           a list of dictionaries containing the min_ver and fixed_ver and fixed_display.
#
##
function junos_compare_range(target_version, vuln_ranges)
{
  var range;
  var model_match_success;
  var model;
  var model_match;
  var target_ver_track;
  var fixed_ver_track;
  var fixed_version;
  var target_ver;
  var fixed_ver;
  var min_ver;
  var fixed_display;
  var yearIsFlagged;
  var quarterIsFlagged;
  var majorIsFlagged;
  var minorIsFlagged;
  var subMinorIsFlagged;
  var yearMatchesMinVer;
  var yearMatchesFixedVer;
  var quarterMatchesMinVer;
  var quarterMatchesFixedVer;
  var majorMatchesMinVer;
  var majorMatchesFixedVer;
  var minorMatchesMinVer;
  var minorMatchesFixedVer;
  var continueChecking;
  var compareMinAndFixed;

  ##
  # @param min_ver               min version to check.
  # @param fixed_ver             max version to check.
  # @param model                 Regex that attempts to matche the junos model.
  ##
  foreach range (vuln_ranges)
  {
    # ensure range is not null
    if (isnull(target_version) || isnull(range['min_ver']) || isnull(range['fixed_ver']))
    {
      exit(1, "junos_compare_range(): vuln_ranges is not properly formatted, it must be a list containing 'min_ver' and 'fixed_ver'");
    }

    # check if model param has been passed
    if (!isnull(range['model']))
    {
      model_match_success = FALSE;
      model = get_kb_item("Host/Juniper/model");
      if (isnull(model)) exit(0, 'No model was identified on the target junos.');
      model_match = pregmatch(string:model, pattern:range['model']);
      if (model_match) model_match_success = TRUE;
      else continue;
    }

    # if there is a track specified we need to ensure that the target_version and fixed version are on the same track.
    target_ver_track = pregmatch(string:target_version, pattern:"^[0-9]+\.[0-9]+([FfRrXx])");
    fixed_ver_track = pregmatch(string:range['fixed_ver'], pattern:"^[0-9]+\.[0-9]+([FfRrXx])");

    if (!isnull(target_ver_track) && !isnull(fixed_ver_track)
        && target_ver_track[1] != fixed_ver_track[1]) continue;

    # evo could exist in fix or target, if so they both need evo
    if (( 'EVO' >< target_version ) ^ ('EVO' >< range['min_ver']))
      continue;

    fixed_version = range['fixed_ver'];
    target_ver = parse_version(version:target_version);
    fixed_ver = parse_version(version:fixed_version);
    min_ver = parse_version(version:range['min_ver']);
    fixed_display = range['fixed_display'];

    yearMatchesMinVer = min_ver['year'] == target_ver['year'];
    yearMatchesFixedVer = target_ver['year'] == fixed_ver['year'];
    quarterMatchesMinVer = min_ver['quarter_release'] == target_ver['quarter_release'];
    quarterMatchesFixedVer = target_ver['quarter_release'] == fixed_ver['quarter_release'];
    majorMatchesMinVer = min_ver['major_release'] == target_ver['major_release'];
    majorMatchesFixedVer = target_ver['major_release'] == fixed_ver['major_release'];
    minorMatchesMinVer = min_ver['minor_release'] == target_ver['minor_release'];
    minorMatchesFixedVer = target_ver['minor_release'] == fixed_ver['minor_release'];
    compareMinAndFixed = yearMatchesMinVer && yearMatchesFixedVer;

    continueChecking = TRUE;

    yearIsFlagged = min_ver['year'] < target_ver['year'] &&
        target_ver['year'] < fixed_ver['year'];

    # Quarter Release Comparison
    if (compareMinAndFixed)
    {
      quarterIsFlagged = min_ver['quarter_release'] < target_ver['quarter_release'] &&
          target_ver['quarter_release'] < fixed_ver['quarter_release'];
      compareMinAndFixed = yearMatchesMinVer && yearMatchesFixedVer && quarterMatchesMinVer && quarterMatchesFixedVer;
    }
    else if (yearMatchesMinVer)
    {
      quarterIsFlagged = min_ver['quarter_release'] < target_ver['quarter_release'];
    }
    else if (yearMatchesFixedVer)
    {
      quarterIsFlagged = target_ver['quarter_release'] < fixed_ver['quarter_release'];
    }
    else
    {
      # Cannot compare anything else
      continueChecking = FALSE;
    }

    # Major Release Comparison
    if (continueChecking && compareMinAndFixed)
    {
      majorIsFlagged = min_ver['major_release'] < target_ver['major_release'] &&
          target_ver['major_release'] < fixed_ver['major_release'];
      compareMinAndFixed = yearMatchesMinVer && yearMatchesFixedVer && quarterMatchesMinVer && quarterMatchesFixedVer && majorMatchesMinVer && majorMatchesFixedVer;
    }
    else if (continueChecking && yearMatchesMinVer && quarterMatchesMinVer)
    {
      majorIsFlagged = min_ver['major_release'] < target_ver['major_release'];
    }
    else if (continueChecking && yearMatchesFixedVer && quarterMatchesFixedVer)
    {
      majorIsFlagged = target_ver['major_release'] < fixed_ver['major_release'];
    }
    else
    {
      continueChecking = FALSE;
    }

    # Minor Release Comparison
    if (continueChecking && compareMinAndFixed)
    {
      minorIsFlagged = min_ver['minor_release'] <= target_ver['minor_release'] &&
        target_ver['minor_release'] < fixed_ver['minor_release'];
      compareMinAndFixed = yearMatchesMinVer && yearMatchesFixedVer && quarterMatchesMinVer && quarterMatchesFixedVer && majorMatchesMinVer && majorMatchesFixedVer && minorMatchesMinVer && minorMatchesFixedVer;
    }
    else if (continueChecking && yearMatchesMinVer && quarterMatchesMinVer && majorMatchesMinVer)
    {
      minorIsFlagged = min_ver['minor_release'] <= target_ver['minor_release'];
    }
    else if (continueChecking && yearMatchesFixedVer && quarterMatchesFixedVer && majorMatchesFixedVer)
    {
      minorIsFlagged = target_ver['minor_release'] < fixed_ver['minor_release'];
    }
    else
    {
      continueChecking = FALSE;
    }

    # SubMinor Release Comparison
    if (continueChecking && compareMinAndFixed)
    {
      subMinorIsFlagged = min_ver['subminor_release'] <= target_ver['subminor_release'] &&
        target_ver['subminor_release'] < fixed_ver['subminor_release'];
    }
    else if (continueChecking && yearMatchesMinVer && quarterMatchesMinVer && majorMatchesMinVer && minorMatchesMinVer)
    {
      subMinorIsFlagged = min_ver['subminor_release'] <= target_ver['subminor_release'];
    }
    else if (continueChecking && yearMatchesFixedVer && quarterMatchesFixedVer && majorMatchesFixedVer && minorMatchesFixedVer)
    {
      subMinorIsFlagged = target_ver['subminor_release'] < fixed_ver['subminor_release'];
    }

    if (yearIsFlagged || quarterIsFlagged || majorIsFlagged || minorIsFlagged || subMinorIsFlagged)
    {
      if (!isnull(fixed_display))
        return fixed_display;
      return fixed_version;
    }
  }
  if (!isnull(range['model']) && !model_match_success)
    exit(0, 'Model ' + model + ' is not affected "' + range['model'] + '".');
  else
    exit(0, 'Junos ' + target_version + ' is not affected.');
}
