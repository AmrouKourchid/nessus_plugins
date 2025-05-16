#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183917);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2023-34044", "CVE-2023-34045", "CVE-2023-34046");
  script_xref(name:"VMSA", value:"2023-0022");
  script_xref(name:"IAVA", value:"2023-A-0576-S");

  script_name(english:"VMware Fusion 13.0.x < 13.5 Multiple Vulnerabilities (VMSA-2023-0022)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or Mac OS X host is 13.0.x prior to 13.5. It is, therefore,
affected by multiple vulnerabilities.

  - VMware Fusion(13.x prior to 13.5) contain an out-of-bounds read vulnerability that exists in the
    functionality for sharing host Bluetooth devices with the virtual machine. A malicious actor with
    local administrative privileges on a virtual machine may be able to read privileged information
    contained in hypervisor memory from a virtual machine.(CVE-2023-34044)

  - VMware Fusion(13.x prior to 13.5) contains a local privilege escalation vulnerability that occurs
    during installation for the first time (the user needs to drag or copy the application to a folder
    from the '.dmg' volume) or when installing an upgrade. A malicious actor with local non-administrative
    user privileges may exploit this vulnerability to escalate privileges to root on the system where
    Fusion is installed or being installed for the first time. (CVE-2023-34045)

  - VMware Fusion(13.x prior to 13.5) contains a TOCTOU (Time-of-check Time-of-use) vulnerability that
    occurs during installation for the first time (the user needs to drag or copy the application to a
    folder from the '.dmg' volume) or when installing an upgrade. A malicious actor with local
    non-administrative user privileges may exploit this vulnerability to escalate privileges to root on
    the system where Fusion is installed or being installed for the first time. (CVE-2023-34046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0022.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Fusion version 13.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'VMware Fusion');

var constraints = [
  { 'min_version' : '13.0', 'fixed_version' : '13.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
