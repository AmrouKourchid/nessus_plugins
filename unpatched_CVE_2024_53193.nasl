#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230412);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53193");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53193");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: clk: clk-loongson2: Fix memory
    corruption bug in struct loongson2_clk_provider Some heap space is allocated for the flexible structure
    `struct clk_hw_onecell_data` and its flexible-array member `hws` through the composite structure `struct
    loongson2_clk_provider` in function `loongson2_clk_probe()`, as shown below: 289 struct
    loongson2_clk_provider *clp; ... 296 for (p = data; p->name; p++) 297 clks_num++; 298 299 clp =
    devm_kzalloc(dev, struct_size(clp, clk_data.hws, clks_num), 300 GFP_KERNEL); Then some data is written
    into the flexible array: 350 clp->clk_data.hws[p->id] = hw; This corrupts `clk_lock`, which is the
    spinlock variable immediately following the `clk_data` member in `struct loongson2_clk_provider`: struct
    loongson2_clk_provider { void __iomem *base; struct device *dev; struct clk_hw_onecell_data clk_data;
    spinlock_t clk_lock; /* protect access to DIV registers */ }; The problem is that the flexible structure
    is currently placed in the middle of `struct loongson2_clk_provider` instead of at the end. Fix this by
    moving `struct clk_hw_onecell_data clk_data;` to the end of `struct loongson2_clk_provider`. Also, add a
    code comment to help prevent this from happening again in case new members are added to the structure in
    the future. This change also fixes the following -Wflex-array-member-not-at-end warning: drivers/clk/clk-
    loongson2.c:32:36: warning: structure containing a flexible array member is not at the end of another
    structure [-Wflex-array-member-not-at-end] (CVE-2024-53193)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53193");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-lowlatency-hwe-6.11",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
