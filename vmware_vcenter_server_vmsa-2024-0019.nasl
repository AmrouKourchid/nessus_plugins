#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207464);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-38812", "CVE-2024-38813");
  script_xref(name:"IAVA", value:"2024-A-0588-S");
  script_xref(name:"IAVA", value:"2024-A-0683");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/12/11");

  script_name(english:"VMware vCenter Server 7.x < 7.0 U3t / 8.x < 8.0.3 U3d Multiple Vulnerabilities (VMSA-2024-0019)");

  script_set_attribute(attribute:"synopsis", value:
"The VMware vCenter Server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 7.x prior to 7.0 U3t or 8.x prior to 8.0 U3d. 
It is, therefore, affected by multiple vulnerabilities as referenced in the VMSA-2024-0019 advisory:

  - The vCenter Server contains a heap-overflow vulnerability in the implementation of the DCERPC protocol. A
    malicious actor with network access to vCenter Server may trigger this vulnerability by sending a
    specially crafted network packet potentially leading to remote code execution. (CVE-2024-38812)

  - The vCenter Server contains a privilege escalation vulnerability. A malicious actor with network access to
    vCenter Server may trigger this vulnerability to escalate privileges to root by sending a specially
    crafted network packet. (CVE-2024-38813)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24968
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2748da59");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 7.0 U3t, 8.0 U3d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

var constraints = [
{ 'min_version' : '7.0', 'fixed_version' : '7.0.24322018', 'fixed_display' : '7.0 Build 24322018 (U3t)' },
{ 'min_version' : '8.0', 'fixed_version' : '8.0.24321653', 'fixed_display' : '8.0 Build 24322831 (U3d) or 8.0 Build 24321653 (U2e)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
