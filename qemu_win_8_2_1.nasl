#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190777);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2024-26328");
  script_xref(name:"IAVB", value:"2024-B-0022-S");

  script_name(english:"QEMU < 8.2.1 Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by buffer overflow");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host is prior to 8.2.1 and therefore vulnerable to the following:

  - An issue was discovered in QEMU 7.0.0 through 8.2.1. register_vfs in hw/pci/pcie_sriov.c does not set NumVFs to 
    PCI_SRIOV_TOTAL_VF, and thus interaction with hw/nvme/ctrl.c is mishandled.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qemu.org/download/#source");
  # https://github.com/qemu/qemu/commit/7c0fa8dff811b5648964630a1334c3bb97e1e1c6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9119036");
  # https://github.com/qemu/qemu/commit/714a1415d7a69174e1640fcdd6eaae180fe438aa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f44fe98");
  # https://lore.kernel.org/all/20240213055345-mutt-send-email-mst%40kernel.org/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41d44ac1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 8.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26328");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '7.0.0', 'fixed_version': '8.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);