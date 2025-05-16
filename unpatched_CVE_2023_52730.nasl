#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225895);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52730");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52730");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mmc: sdio: fix possible resource leaks
    in some error paths If sdio_add_func() or sdio_init_func() fails, sdio_remove_func() can not release the
    resources, because the sdio function is not presented in these two cases, it won't call of_node_put() or
    put_device(). To fix these leaks, make sdio_func_present() only control whether device_del() needs to be
    called or not, then always call of_node_put() and put_device(). In error case in sdio_init_func(), the
    reference of 'card->dev' is not get, to avoid redundant put in sdio_free_func_cis(), move the get_device()
    to sdio_alloc_func() and put_device() to sdio_release_func(), it can keep the get/put function be
    balanced. Without this patch, while doing fault inject test, it can get the following leak reports, after
    this fix, the leak is gone. unreferenced object 0xffff888112514000 (size 2048): comm kworker/3:2, pid
    65, jiffies 4294741614 (age 124.774s) hex dump (first 32 bytes): 00 e0 6f 12 81 88 ff ff 60 58 8d 06 81 88
    ff ff ..o.....`X...... 10 40 51 12 81 88 ff ff 10 40 51 12 81 88 ff ff .@Q......@Q..... backtrace:
    [<000000009e5931da>] kmalloc_trace+0x21/0x110 [<000000002f839ccb>] mmc_alloc_card+0x38/0xb0 [mmc_core]
    [<0000000004adcbf6>] mmc_sdio_init_card+0xde/0x170 [mmc_core] [<000000007538fea0>]
    mmc_attach_sdio+0xcb/0x1b0 [mmc_core] [<00000000d4fdeba7>] mmc_rescan+0x54a/0x640 [mmc_core] unreferenced
    object 0xffff888112511000 (size 2048): comm kworker/3:2, pid 65, jiffies 4294741623 (age 124.766s) hex
    dump (first 32 bytes): 00 40 51 12 81 88 ff ff e0 58 8d 06 81 88 ff ff .@Q......X...... 10 10 51 12 81 88
    ff ff 10 10 51 12 81 88 ff ff ..Q.......Q..... backtrace: [<000000009e5931da>] kmalloc_trace+0x21/0x110
    [<00000000fcbe706c>] sdio_alloc_func+0x35/0x100 [mmc_core] [<00000000c68f4b50>]
    mmc_attach_sdio.cold.18+0xb1/0x395 [mmc_core] [<00000000d4fdeba7>] mmc_rescan+0x54a/0x640 [mmc_core]
    (CVE-2023-52730)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": "kernel-rt",
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
