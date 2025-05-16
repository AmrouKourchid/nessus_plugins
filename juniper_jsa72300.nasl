#TRUSTED 0b01820ff6d325e8e89958e8bb0fc81b36e866d8c9c58f3c5b3e98838cb071af861a9993a386ecbfafb287eed2166152dc3fe5b6cbed771b8123f86ee2acd55300692e72ec62148af432035424fc898616b6c20441a95ba241bcd02c269b5795e77fd6263172280f3f5973683740e7daabe9d99de6f2c504369b784ed514112df64cfcd7b5b7b121dc55409ddcfcd4eeca6f6e1e6d2ddb5f74bdac48fb984534633bab76beb396d0d0b31b07b57389eb25c4a232111e5ee15cbf0f1df7e9945348ae2d860c95fbb94ad4af9cad1456817d299a6724038d1e3c0c5694f7722403ed28adf63dcd4a83b9615cf7636d8f008bd5a970455bb47693c49ab4a57a4c3aac60cabbe37a42f8cdc414bda29e70c18f778232d439c7e506bf17693a14b1bb73ea56b0a14c056387183563be4b86e7d91565685f3b0963ae496fe47af4cdfe38337264988cc82cfdbe6e69fe8f2f98ef0381c6dcd239969a89334982c1199a82b233e235ebf49c677a38752df9ccd2d2652f86132323fc398022108de1df83859056c726704c897d1af0496aa39558eb75666923b76decb3cabb08c8312bbf12919c8565df10871872fc841239dfb929087633d7cc33b5ac0bec1518a4e7a8a5d31595d43223ef16732c90a45e6595d4d74b5d9c25c8844f94d1ffb3ceddf57ad1d5ad0cfa78610acd6fbe85dcea5b20864d51fe791edf172eca7fe2835ae8
#TRUST-RSA-SHA256 2a0db293c115366f07439b644c2ebd05dd07a6692af5c2ae6ca808cf71551fd6970ac1c491bab7e87512bcadcc58c22a37f63530a8509be7202dfa43c5528850d89adbdd1f7d06533a6d537ca7c4d0826b8e31d8921175a8e662926f31e7dc1ab577c14066c8606e28b2619d1456ddce94610d0eeec4670e8d80a667e3db31f8101f53d46acffdb5243c952e11e016d4fbe2e0a89497bb91a636300576fa689c394b3b9b1c93a28ea35e26a9220be8807a109ab92ed7422663b90075d19370164b410882177a4b80d81ba5502f1bee2c3addbbe4e3e90c951ab282e247947127974cef381b1332926e2d1dbe4258f9929cc2cbbfb63de46cc792143444e224a05e664af17dc4db15f6d158f7f437f0e251ff25dd09799ab197a2293f694fe76f89d016cc7e3547807ebd500005943d34a65a9affb20f51fe949cc22840f97de00f4106ed1bdf1c413eed9fb7d3123606fc79a345e5491ec6b34f6dd4f9566ec588293aa34d15d25c375118233fc500e8e66b64b2c162406fb7a9ac25f79ca965abe40e65e8103456d81924024cf66fa7d6999268b510604d9483d37f5ea365f1f76e1cc10382676b8f871815725c5f7ed680df4fa0e87adaf968b2454a585e84122a5636810783f5408db9db542c455aef76b5479cd64439b4c8edb92a1d50e3034f7b8eca0a62dcea25b6e09f03087420672d09a29784f7893a21b8666ed841
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180190);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2023-36844",
    "CVE-2023-36845",
    "CVE-2023-36846",
    "CVE-2023-36847",
    "CVE-2023-36851"
  );
  script_xref(name:"JSA", value:"JSA72300");
  script_xref(name:"CEA-ID", value:"CEA-2023-0042");
  script_xref(name:"IAVA", value:"2023-A-0465");
  script_xref(name:"IAVA", value:"2023-A-0433-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/11/17");

  script_name(english:"Juniper Junos OS Pre-Auth RCE (JSA72300)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA72300 advisory.

  - A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX and SRX Series
    allows an unauthenticated, network-based attacker to control certain, important environments variables.
    Utilizing a crafted request an attacker is able to modify certain PHP environments variables leading to
    partial loss of integrity, which may allow chaining to other vulnerabilities. (CVE-2023-36844, CVE-2023-36845)

  - A Missing Authentication for Critical Function vulnerability in Juniper Networks Junos OS on EX and SRX Series
    allows an unauthenticated, network-based attacker to cause limited impact to the file system integrity.
    With a specific request that doesn't require authentication an attacker is able to upload arbitrary files
    via J-Web, leading to a loss of integrity for a certain part of the file system, which may allow chaining
    to other vulnerabilities. (CVE-2023-36846, CVE-2023-36847)

Note: Nessus found J-Web enabled [set system services web-management http(s)] on this device.");
  # https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?752ef07a");
  # https://juniper.lightning.force.com/articles/Knowledge/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00a9cacd");
  # https://juniper.lightning.force.com/articles/Knowledge/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?812ee185");
  # https://juniper.lightning.force.com/articles/Knowledge/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0ab70e2");
  script_set_attribute(attribute:"solution", value:
"Disable J-Web, or limit access to only trusted hosts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36845");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Junos OS PHPRC Environment Variable Manipulation RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8'},
  {'min_ver':'21.1', 'fixed_ver':'21.2R3-S6'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4', 'model':'^EX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5', 'model':'^SRX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1', 'model':'^EX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2', 'model':'^SRX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:"show configuration | display set");
if (!empty_or_null(buf))
{
  override = FALSE;
  if(!junos_check_config(buf:buf, pattern:"^set system services web-management http(s)?")) 
  {
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

