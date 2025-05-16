#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187208);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2023-28053");
  script_xref(name:"IAVA", value:"2023-A-0704");

  script_name(english:"Dell NetWorker Virtual Edition Weak SSH Cryptography (DSA-2023-358)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Linux host has an application that is affected by an SSH cryptography vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell NetWorker Virtual Edition installed on the remote Linux host is prior to 19.7, 19.7.0.x prior to
19.7.0.6, 19.7.1, 19.8.x prior to 19.8.0.4 or 19.9.x prior to 19.9.0.3. It is, therefore, affected by vulnerability
in the SSH component. Due to use of deprecated cryptographic algorithms, an unauthenticated, remote attacker could
access confidential information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000220547/dsa-2023-358-security-update-for-dell-networker-virtual-edition-ssh-cryptographic-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40d46e46");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell NetWorker Virtual Edition 19.8.0.4, 19.9.0.3, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28053");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_networker_virtual_edition_installed.nbin");
  script_require_keys("installed_sw/Dell NetWorker Virtual Edition");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell NetWorker Virtual Edition');

var constraints = [
  { 'max_version' : '19.7.0.5', 'fixed_version' : '19.9.0.3' },
  { 'equal' : '19.7.1', 'fixed_display' : '19.9.0.3' },
  { 'min_version' : '19.8', 'fixed_version' : '19.8.0.4' },
  { 'min_version' : '19.9', 'fixed_version' : '19.9.0.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

