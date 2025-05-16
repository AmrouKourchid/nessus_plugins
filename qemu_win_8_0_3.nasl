#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179667);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2023-1544", "CVE-2023-3019");
  script_xref(name:"IAVB", value:"2023-B-0058-S");

  script_name(english:"QEMU < 7.2.4 / < 8.0.3 Multiple Vulnerabilites");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host is affected by multiple vulnerabilities, as follows:
   
  - A DMA reentrancy issue leading to a use-after-free error was found in the e1000e NIC emulation code in QEMU. 
    This issue could allow a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. (CVE-2023-3019)

  - A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device. This flaw allows a crafted guest 
    driver to allocate and initialize a huge number of page tables to be used as a ring of descriptors for CQ and 
    async events, potentially leading to an out-of-bounds read and crash of QEMU. (CVE-2023-1544)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qemu.org/download/#source");
  # https://lists.nongnu.org/archive/html/qemu-devel/2023-03/msg00206.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b525f632");
  # https://lists.nongnu.org/archive/html/qemu-devel/2023-05/msg08310.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93f5c304");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 7.2.4, 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1544");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-3019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version':'0.0', 'fixed_version':'7.2.4'},
  {'min_version':'8.0', 'fixed_version' : '8.0.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);