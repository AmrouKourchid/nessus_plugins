#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(111220);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_cve_id("CVE-2018-6969");
  script_bugtraq_id(104737);
  script_xref(name:"VMSA", value:"2018-0017");

  script_name(english:"VMware Tools 10.x < 10.3.0 Multiple Vulnerabilities (VMSA-2018-0017)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite is installed on the remote Windows host is
affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host
is 10.x prior to 10.3.0. It is, therefore, affected by
an information disclosure vulnerability.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0017.html");
  # https://my.vmware.com/web/vmware/details?downloadGroup=VMTOOLS1030&productId=491
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fbb6d9b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 10.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6969");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin", "vmware_vsphere_detect.nbin", "vmware_esxi_detection.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools", "Host/ESXi/checked");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

esx = get_kb_item("Host/ESXi");
if (esx)
  audit(AUDIT_HOST_NOT, "affected");


app_info = vcf::get_app_info(app:"VMware Tools", win_local:TRUE);

constraints = [{ "min_version" : "0", "fixed_version" : "10.3.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
