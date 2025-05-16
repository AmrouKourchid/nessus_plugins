#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200538);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id("CVE-2024-20361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd66820");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-object-bypass-fTH8tDjq");

  script_name(english:"Cisco Firepower Management Center Software Object Group Access Control List Bypass (cisco-sa-fmc-object-bypass-fTH8tDjq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Object Groups for Access Control Lists (ACLs) feature of Cisco Firepower Management Center (FMC)
Software could allow an unauthenticated, remote attacker to bypass configured access controls on managed devices that 
are running Cisco Firepower Threat Defense (FTD) Software. This vulnerability is due to the incorrect deployment of the 
Object Groups for ACLs feature from Cisco FMC Software to managed FTD devices in high-availability setups. After an 
affected device is rebooted following Object Groups for ACLs deployment, an attacker can exploit this vulnerability by 
sending traffic through the affected device. A successful exploit could allow the attacker to bypass configured access 
controls and successfully send traffic to devices that are expected to be protected by the affected device.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-object-bypass-fTH8tDjq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31f151e8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd66820");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd66820");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20361");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (get_kb_item('Host/local_checks_enabled'))
{
  var buf = cisco_command_kb_item('Host/Cisco/Config/show_running-config_failover', 'show running-config failover');
  if (check_cisco_result(buf))
  {
    if ('no failover' >< buf)
      audit(AUDIT_HOST_NOT, 'affected since high availability is not configured');
  }
}

var app_info = vcf::get_app_info(
  app:'Cisco Firepower Management Center',
  kb_ver:'Host/Cisco/firepower_mc/version'
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'7.1', 'fixed_version':'7.2.4'},
  {'min_version':'7.3', 'fixed_version':'7.3.1.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);


