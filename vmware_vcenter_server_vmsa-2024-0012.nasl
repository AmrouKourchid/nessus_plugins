#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200746);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2024-37079", "CVE-2024-37080", "CVE-2024-37081");
  script_xref(name:"VMSA", value:"2024-0012");
  script_xref(name:"IAVA", value:"2024-A-0362-S");

  script_name(english:"VMware vCenter Server 7.0 < 7.0U3r / 8.0 < 8.0U2d Multiple Vulnerabilities (VMSA-2024-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The VMware vCenter Server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 7.0 prior to 7.0U3r, or 8.0 prior to 8.0U2d. It
is, therefore, affected by a partial information disclosure vulnerability as referenced in the VMSA-2024-0012 advisory:

  - The vCenter Server contains multiple heap-overflow vulnerabilities in the implementation of the DCERPC protocol. 
    (CVE-2024-37079, CVE-2024-37080)

  - The vCenter Server contains multiple local privilege escalation vulnerabilities due to misconfiguration of sudo. 
    (CVE-2024-37081)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24453
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?448f7cb3");
  script_set_attribute(attribute:"see_also", value:"https://core.vmware.com/resource/vmsa-2024-0012-questions-answers");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 7.0U3r, or 8.0U2d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37080");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vCenter Sudo Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/19");

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

include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.24026615', 'fixed_display' : '7.0 Build 24026615 (U3r)' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.23929136', 'fixed_display' : '8.0 Build 23929136 (U2d)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
