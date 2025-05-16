#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229183);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2024-42136");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42136");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - cdrom: rearrange last_media_change check to avoid unintentional overflow When running syzkaller with the
    newly reintroduced signed integer wrap sanitizer we encounter this splat: [ 366.015950] UBSAN: signed-
    integer-overflow in ../drivers/cdrom/cdrom.c:2361:33 [ 366.021089] -9223372036854775808 - 346321 cannot be
    represented in type '__s64' (aka 'long long') [ 366.025894] program syz-executor.4 is using a deprecated
    SCSI ioctl, please convert it to SG_IO [ 366.027502] CPU: 5 PID: 28472 Comm: syz-executor.7 Not tainted
    6.8.0-rc2-00035-gb3ef86b5a957 #1 [ 366.027512] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    1.16.3-debian-1.16.3-2 04/01/2014 [ 366.027518] Call Trace: [ 366.027523] <TASK> [ 366.027533]
    dump_stack_lvl+0x93/0xd0 [ 366.027899] handle_overflow+0x171/0x1b0 [ 366.038787] ata1.00: invalid
    multi_count 32 ignored [ 366.043924] cdrom_ioctl+0x2c3f/0x2d10 [ 366.063932] ?
    __pm_runtime_resume+0xe6/0x130 [ 366.071923] sr_block_ioctl+0x15d/0x1d0 [ 366.074624] ?
    __pfx_sr_block_ioctl+0x10/0x10 [ 366.077642] blkdev_ioctl+0x419/0x500 [ 366.080231] ?
    __pfx_blkdev_ioctl+0x10/0x10 ... Historically, the signed integer overflow sanitizer did not work in the
    kernel due to its interaction with `-fwrapv` but this has since been changed [1] in the newest version of
    Clang. It was re-enabled in the kernel with Commit 557f8c582a9ba8ab (ubsan: Reintroduce signed overflow
    sanitizer). Let's rearrange the check to not perform any arithmetic, thus not tripping the sanitizer.
    (CVE-2024-42136)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42136");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
