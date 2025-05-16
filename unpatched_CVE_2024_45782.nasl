#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232036);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-45782");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45782");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - A flaw was found in the HFS filesystem. When reading an HFS volume's name at grub_fs_mount(), the HFS
    filesystem driver performs a strcpy() using the user-provided volume name as input without properly
    validating the volume name's length. This issue may read to a heap-based out-of-bounds writer, impacting
    grub's sensitive data integrity and eventually leading to a secure boot protection bypass.
    (CVE-2024-45782)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "grub-common",
     "grub-coreboot",
     "grub-coreboot-bin",
     "grub-coreboot-dbg",
     "grub-efi",
     "grub-efi-amd64",
     "grub-efi-amd64-bin",
     "grub-efi-amd64-dbg",
     "grub-efi-amd64-signed-template",
     "grub-efi-arm",
     "grub-efi-arm-bin",
     "grub-efi-arm-dbg",
     "grub-efi-arm64",
     "grub-efi-arm64-bin",
     "grub-efi-arm64-dbg",
     "grub-efi-arm64-signed-template",
     "grub-efi-ia32",
     "grub-efi-ia32-bin",
     "grub-efi-ia32-dbg",
     "grub-efi-ia32-signed-template",
     "grub-efi-ia64",
     "grub-efi-ia64-bin",
     "grub-efi-ia64-dbg",
     "grub-emu",
     "grub-emu-dbg",
     "grub-firmware-qemu",
     "grub-ieee1275",
     "grub-ieee1275-bin",
     "grub-ieee1275-dbg",
     "grub-linuxbios",
     "grub-mount-udeb",
     "grub-pc",
     "grub-pc-bin",
     "grub-pc-dbg",
     "grub-rescue-pc",
     "grub-theme-starfield",
     "grub-uboot",
     "grub-uboot-bin",
     "grub-uboot-dbg",
     "grub-xen",
     "grub-xen-bin",
     "grub-xen-dbg",
     "grub-xen-host",
     "grub-yeeloong",
     "grub-yeeloong-bin",
     "grub-yeeloong-dbg",
     "grub2",
     "grub2-common"
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
       "match_one": {
        "os_version": [
         "11",
         "12"
        ]
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "grub-common",
     "grub-coreboot",
     "grub-coreboot-bin",
     "grub-coreboot-dbg",
     "grub-efi",
     "grub-efi-amd64",
     "grub-efi-amd64-bin",
     "grub-efi-amd64-dbg",
     "grub-efi-amd64-signed-template",
     "grub-efi-amd64-unsigned",
     "grub-efi-arm",
     "grub-efi-arm-bin",
     "grub-efi-arm-dbg",
     "grub-efi-arm-unsigned",
     "grub-efi-arm64",
     "grub-efi-arm64-bin",
     "grub-efi-arm64-dbg",
     "grub-efi-arm64-signed-template",
     "grub-efi-arm64-unsigned",
     "grub-efi-ia32",
     "grub-efi-ia32-bin",
     "grub-efi-ia32-dbg",
     "grub-efi-ia32-signed-template",
     "grub-efi-ia32-unsigned",
     "grub-efi-ia64",
     "grub-efi-ia64-bin",
     "grub-efi-ia64-dbg",
     "grub-efi-ia64-unsigned",
     "grub-efi-loong64",
     "grub-efi-loong64-bin",
     "grub-efi-loong64-dbg",
     "grub-efi-loong64-unsigned",
     "grub-efi-riscv64",
     "grub-efi-riscv64-bin",
     "grub-efi-riscv64-dbg",
     "grub-efi-riscv64-unsigned",
     "grub-emu",
     "grub-emu-dbg",
     "grub-firmware-qemu",
     "grub-ieee1275",
     "grub-ieee1275-bin",
     "grub-ieee1275-dbg",
     "grub-linuxbios",
     "grub-pc",
     "grub-pc-bin",
     "grub-pc-dbg",
     "grub-rescue-pc",
     "grub-uboot",
     "grub-uboot-bin",
     "grub-uboot-dbg",
     "grub-xen-bin",
     "grub2",
     "grub2-common"
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
        "os_version": "13"
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
