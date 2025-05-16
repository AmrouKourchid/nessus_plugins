#TRUSTED 46f9f9541bf98cfbe4e7041d8a6c4bc091e277e584a91d1dc4a44bee68ed6913ab5b420010e69a80e793b9895d1ee1c0d8b39ad210fdbf672e3c1565302f71188ff9b0bf54ad06ac343d93722b537dc27afac5485324631a7b48c420f6619cd3c20119a5b2c99ede6dfe230c78f310b30faa4467d6fb4d9999b27780bec86065457676ecb544b9035c720b1a4994342860989de2642ff3e42ad1ec57e87a8e8aa25e09674b62d6db7b8743fa0e8f4cea43148240b4cf646d471ff096839f86c9626642e9cdd10ad20500d174d15120d602ccdd4a41e6f757996f9d2b53af9cc1285bfe353b99765dfc46f7a6d034b62a63c63e69999eaaabdf84037d58037847af604b0f1915b1a16d55d51e3e8726b3a3846647051c1be75d7612bd57d2cb237f1fe2d5c38f594b8e3b3fdc5c94683a9bddd98c6a725a7dc9503e26bf67ad2e861a40bc9b5197ca4aa3c0b4fa0e745ce2f42824c62cb8834451b8a400a67f3d845190da89b997d6f240ed8289d3aee2da9eb18ea3b422eef059e084bc2dcb1170fcf14d959bcfc3f2e4a0e3b20714b9126f4954cb0d1f30607c1d8d2cd2c58768f2d84a2712fef86d8acc088ce72ecc4a665730d551ce77d19289acc2c3f948a58e891932431374b0561d10b1b1041f0c5e9cee066a8f6a317762fec67ced6b4bd92763c16e7cd0fe6e12932d08b980f01eaa473c0e40317686204d9b642920
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ksplice.inc
#
# Revision: 1.1
#

include("lists.inc");

##
# Storage value for release kb so we only need to fetch once.
##
global_var _ksplice_kernel_cves = make_array();

##
# Storage value for missing KSplice CVEs.
##
global_var _ksplice_missing_cves = make_list();

##
# Populates and returns _ksplice_kernel_cves
#
# @return _ksplice_kernel_cves if Host/ksplice/kernel-cves has a value
#         NULL if the KB is missing
##
function ksplice_load_cve_list()
{
  local_var kb_value, kb_split, cve;
  kb_value = get_kb_item("Host/ksplice/kernel-cves");
  if (isnull(kb_value)) return NULL;
  kb_split = split(kb_value, sep:",", keep:FALSE);
  foreach cve (kb_split)
  {
    _ksplice_kernel_cves[cve] = 1;
  }
  return _ksplice_kernel_cves;
}

##
# Determines if all CVEs are present in the _ksplice_kernel_cves list
#
# @anonparam list of CVEs to check
#
# @remark Empties and populates _ksplice_missing_cves
#
# @return 1 if all the CVEs exist in the Host/ksplice/kernel-cves list
#         else NULL
##
function ksplice_cves_check ()
{
  local_var cves, cve;
  cves = _FCT_ANON_ARGS[0];
  if (isnull(cves) || max_index(cves) < 1) return NULL;
  if (isnull(max_index(keys(_ksplice_kernel_cves)))) ksplice_load_cve_list();
  _ksplice_missing_cves = make_list();
  foreach cve (cves)
  {
    if (!_ksplice_kernel_cves[cve])
    {
      _ksplice_missing_cves = make_list(_ksplice_missing_cves, cve);

    }
  }
  if (max_index(_ksplice_missing_cves) < 1)
  {
    return 1;
  }
  else
  {
    return NULL;
  }
}

##
# Determines if all CVEs are present in the _ksplice_kernel_cves list
#
# @remark Checks _ksplice_missing_cves for any missing CVEs.
#
# @return string text indicating missing CVEs in ksplice
#         else empty string
##
function ksplice_reporting_text ()
{
  local_var cves, report, i, terminator;
  cves = _ksplice_missing_cves;
  if (isnull(cves) || max_index(cves) < 1) return '';
  cves = collib::cve_sort(cves);
  report = 'KSplice is running, but the following required CVEs remain unpatched:\n  ';
  for (i = 0; i < max_index(cves); i++)
  {
    terminator = '  ';
    if (i == (max_index(cves) - 1))
    {
      terminator = '\n\n';
    }
    else if ((i + 1) % 4 == 0)
    {
      terminator = ',\n  ';
    }
    else
    {
      terminator = ', ';
    }
    report += cves[i] + terminator;
  }
  return report;
}
