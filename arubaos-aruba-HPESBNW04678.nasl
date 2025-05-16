#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205308);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2023-48795",
    "CVE-2023-51385",
    "CVE-2024-42398",
    "CVE-2024-42399",
    "CVE-2024-42400"
  );
  script_xref(name:"IAVA", value:"2024-A-0468-S");

  script_name(english:"ArubaOS 10.4.x < 10.4.1.4, 10.6.x < 10.6.0.1 Multiple Vulnerabilities (HPESBNW04678)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is affected by multiple vulnerabilities:

  - In OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and 
    this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can 
    have a submodule with shell metacharacters in a user name or host name. The impact of this vulnerability on 
    InstantOS 8.x and ArubaOS 10.x running on HPE Aruba Networking Access Points has not been confirmed, but the 
    version of OpenSSH has been upgraded for mitigation. (CVE-2023-51385)

  - The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 allows remote attackers to 
    bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client 
    and server may consequently end up with a connection for which some security features have been downgraded or 
    disabled, aka a Terrapin attack. The impact of this vulnerability on HPE Aruba Networking Access Points has not 
    been confirmed, but the version of OpenSSH in InstantOS and ArubaOS 10.x software has been upgraded for mitigation.
    (CVE-2023-48795)

  - Multiple unauthenticated Denial-of-Service (DoS) vulnerabilities exist in the Soft AP daemon accessed
    via the PAPI protocol. Successful exploitation of these vulnerabilities results in the ability to interrupt the 
    normal operation of the affected Access Point. (CVE-2024-42398, CVE-2024-42399, CVE-2024-42400)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04678en_us&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab07c9c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS');
if (!empty_or_null(app_info.ver_model))
    audit(AUDIT_INST_VER_NOT_VULN, 'ArubaOS', app_info.version);

var constraints = [
  { 'min_version' : '10.4', 'fixed_version' : '10.4.1.4' },
  { 'min_version' : '10.6', 'fixed_version' : '10.6.0.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
