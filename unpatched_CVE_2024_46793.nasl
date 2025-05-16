#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228646);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46793");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46793");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ASoC: Intel: Boards: Fix NULL pointer
    deref in BYT/CHT boards harder Since commit 13f58267cda3 (ASoC: soc.h: don't create dummy Component via
    COMP_DUMMY()) dummy codecs declared like this: SND_SOC_DAILINK_DEF(dummy,
    DAILINK_COMP_ARRAY(COMP_DUMMY())); expand to: static struct snd_soc_dai_link_component dummy[] = { };
    Which means that dummy is a zero sized array and thus dais[i].codecs should not be dereferenced *at all*
    since it points to the address of the next variable stored in the data section as the dummy variable has
    an address but no size, so even dereferencing dais[0] is already an out of bounds array reference. Which
    means that the if (dais[i].codecs->name) check added in commit 7d99a70b6595 (ASoC: Intel: Boards: Fix
    NULL pointer deref in BYT/CHT boards) relies on that the part of the next variable which the name member
    maps to just happens to be NULL. Which apparently so far it usually is, except when it isn't and then it
    results in crashes like this one: [ 28.795659] BUG: unable to handle page fault for address:
    0000000000030011 ... [ 28.795780] Call Trace: [ 28.795787] <TASK> ... [ 28.795862] ? strcmp+0x18/0x40 [
    28.795872] 0xffffffffc150c605 [ 28.795887] platform_probe+0x40/0xa0 ... [ 28.795979] ?
    __pfx_init_module+0x10/0x10 [snd_soc_sst_bytcr_wm5102] Really fix things this time around by checking
    dais.num_codecs != 0. (CVE-2024-46793)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "kernel",
     "kernel-rt"
    ],
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
