#TRUSTED 9d7dfea1454e1b095562eb9d1eaa868d78c85f2b227c534ac9ba0cd2fec19c330fc68a85f8f511677cd2853be2bb36a8edb24cc1adae8336141f5462c3505b275e0340b4295185b839a42d6c2b1ea5d662533e7e2d69fe24fdc781bff0169df03c4e289745d40c107970af6dfd351997d64be8f5ac03b6d7c4e52a903a41abf3368bf20033e65f42793e38e195d15f13f7c0602c6ba82289c1b496d540c67937619153fa7cfa50f58168d2d35ea589b80f7c5b25bab395997375234722b85d43c690381dd4ab86bde1ea16eb72a75d245377c5f2ed4234cfcc823de3243f4cbf5ccbb159113cc40f47571a7405fdd7dea3cd13f08e87975d2ed24d7871e39379e80199026bd1888af88924315d6ec570d7cdf883f16bf5494e37e8fc59bc4e0ec81eef3a102c8af3bbd0f0e42ea82858e9543d070473f95eda3178e0ab77e4b0336d582f9392a13892a38ffb776b3565c6476cd6a2cbec0ffa1c87efd16122c13fd17b74fd8ff35e9c2c5365c4b61454b52c4b25edf3809d9f7956ca7bc21d7c320cdfc375205812a9953713f5c2e06479ba3e77284a8a8e5faca7498899768da3c7b29b7ba3f45fc4c505bdca30fc8c99868a1662d714e53276b001ee48445a62dd0b4d0e52f488e22f9da9be90ec1ceecfb66348ad2cc73fd690e26ab9db6c67413c1409c271da0f46adcd20ff453e3374e27d8a287323a4edcc0fe2970a30
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# kpatch.inc
#
# Revision: 1.2
#

include("lists.inc");

##
# Populates and returns a list of Kpatch CVEs that are applied.
#
# @return List of applied Kpatch CVEs if Host/kpatch/kernel-cves has a value
#         NULL if the KB is missing
##
function kpatch_load_cve_list()
{
  var kb_value, kb_split, cve, kpatch_kernel_cves;
  kb_value = get_kb_item("Host/kpatch/kernel-cves");
  if (isnull(kb_value)) return NULL;
  kb_split = split(kb_value, sep:",", keep:FALSE);
  foreach cve (kb_split)
  {
    kpatch_kernel_cves[cve] = 1;
  }
  return kpatch_kernel_cves;
}

##
# Storage value for installed Kpatch patches.
##
global_var _kpatch_installed_patches = {};

##
# Storage value for missing Kpatch patches.
##
global_var _kpatch_missing_patches = [];

##
# Populates and returns _kpatch_installed_patches
#
# @return _kpatch_installed_patches if Host/kpatch/patch-list has a value
#         NULL if the KB is missing
##
function kpatch_load_patch_list()
{
  local_var kb_value, kb_split, patch;
  kb_value = get_kb_item("Host/kpatch/patch-list");
  if (isnull(kb_value)) return NULL;
  kb_split = split(kb_value, sep:",", keep:FALSE);
  foreach patch (kb_split)
  {
    _kpatch_installed_patches[patch] = 1;
  }
  return _kpatch_installed_patches;
}

##
# Determines if all patches are present in the _kpatch_installed_patches list
#
# @anonparam list of patches to check
#
# @remark Empties and populates _kpatch_missing_patches
#
# @return 1 if all the patches exist in the Host/kpatch/patch-list list
#         else NULL
##
function kpatch_patch_check ()
{
  local_var patches, patch;
  patches = _FCT_ANON_ARGS[0];
  if (isnull(patches) || max_index(patches) < 1) return NULL;
  if (isnull(max_index(keys(_kpatch_installed_patches)))) kpatch_load_patch_list();
  _kpatch_missing_patches = [];
  foreach patch (patches)
  {
    if (!_kpatch_installed_patches[patch])
    {
      append_element(var:_kpatch_missing_patches, value:patch);
    }
  }
  if (max_index(_kpatch_missing_patches) < 1)
  {
    return 1;
  }
  else
  {
    return NULL;
  }
}

##
# Aggregates together missing KPatches into meaningful reporting text
#
# @remark Checks _kpatch_missing_patches for any missing patches.
#
# @return string text indicating missing patches in kpatch
#         else empty string
##
function kpatch_reporting_text ()
{
  local_var patches, report, i, terminator;
  patches = _kpatch_missing_patches;
  if (isnull(patches) || max_index(patches) < 1) return '';
  patches = sort(patches);
  report = 'KPatch is running, but the following specific patches for this advisory are not installed and running:\n  ';
  for (i = 0; i < max_index(patches); i++)
  {
    terminator = ',\n  ';
    if (i == (max_index(patches) - 1))
    {
      terminator = '\n\n';
    }
    report += patches[i] + terminator;
  }
  return report;
}
