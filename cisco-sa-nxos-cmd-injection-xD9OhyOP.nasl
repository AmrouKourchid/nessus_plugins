#TRUSTED 2372032d243e5add8e553894cb28b3b5973bde620c57adcc0cbe7d4bf8e157192cac47b91d09721b16a147fab014a498be686b9110449e07152e371f691926883ff9998fb3da108f36f0a565de5714fd66b4eeffd30ffdcf5701b38b9c29289229caf7ba445c0c6297c64c2baec30886a09f6b1b4c4ee025dd7697f1cb85ebfd04d249a1d13cab37f8fa1a3b46a6c170ee3cafdc8a96c016a675b78bd42f64cb9e130b4d1b2830d8e5cab944cf002e81eb125e4e101b9d70fc6ec9411bd688b2bac1f74f405d1d2379b8683a07980f00bab6ec8a7c01d91599d745ff606f616becde77e3b72562468c6f02e3beff601b45332474fcf7b8eccd3a1fafd33e2d952cb8ba687bb6c83d7fb6f4a1e809ada7cc62c5b018db78e36de009d97561c267d3074b067fd2ddd19beac929e88f3e9fc1a6e78e36b3cc822c18bb77d85c510d7b4babe4672c46f88ce0cdfd8dcd3a4c6678705f3bff656909726ee8ec453356705a7ce39e478a7f5f73ea368c713d03d6b1c697ff1253f81dc8a52fbce141f37af6415a8877a1fe4d0f05873d2b0c0c902cc2b1dae014a45ef5de2ea1537357ab122c3cd29a9ae0aa73a7cb4b47acd07a104247c49471da907136288fa1bbb7470f58b496a93c6f8b4bdb12df46c8a68311bf3b54bf6f0055c3d8e7648be2883e46a9ef76d87e4497bc15cb2b4e068d8778b081006dde5cd5b0a1b7f851d9f2
#TRUST-RSA-SHA256 3fc5ec939d5b8b31b49f5f9acadcb8018603fa7a6c62cc93266daeecd651db307c3c5aa6c03169a2ff51c47faeca96805d14ff85c29d30d0168753954de39107b873b61e80ed0bd731ae67c9aea24d48cf32859fe566c6576beba64358af4b096b7c7f7ca17ef0aa5756e400686c0eecac9bd45fbb4a69f828acd3c5f1502b972f48ee3d1558c2f319bc88129367a1be601727a338023a08513acb5be8f3d1109c375a619e607866bd5802e19fb74e264d2c19169c3d398d4a9c6194cc1e324afd33aed0b69e9f17f4dc8170d74eb92d061444ddabfe0c06f6ac70c70ad0f9349d89e0dd12d553d6d1da27b46b94d89c03b78d1e9ce63e4e662f283a524db4247252c7e65de0b553c1795b4e2a2f7344b04e749bafb09596bfae5e0fb073806d21ec7a3e850c7ab9749af25d78985e4a70e508d5d04b2285d1242d91080c22ad139e2d2cff5459f097ba4f4ca8e905fccee4357c2c809fed6e8b4044285d08ac633b95bb2717f40981ee80c3459acd0840b31bcba93689bdace463abcf6ca7bb0d0b655009659ad2546ab215c527b5bc16ba71eea911f9fa4cf2bb1e4573fe33cbfb6244c8b639d695d437628de3ff4a3394517682c1c86e3743fa720c578db72814cdc8b6a77220e9a5c00db7af63083f417c79c03d2bac19063ece4c1c8c21cb9e8fb1a4fd8659587d1429ed5f7743880bb20e1d0ef89c8b408fb5dd87f541
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201218);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-20399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj94682");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj97007");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj97009");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj97011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-cmd-injection-xD9OhyOP");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/23");
  script_xref(name:"IAVA", value:"2024-A-0377-S");

  script_name(english:"Cisco NX-OS Software CLI Comm Injection (cisco-sa-nxos-cmd-injection-xD9OhyOP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco NX-OS Software could allow an authenticated, local attacker to execute
    arbitrary commands as root on the underlying operating system of an affected device. This vulnerability is
    due to insufficient validation of arguments that are passed to specific configuration CLI commands. An
    attacker could exploit this vulnerability by including crafted input as the argument of an affected
    configuration CLI command. A successful exploit could allow the attacker to execute arbitrary commands on
    the underlying operating system with the privileges of root. Note: To successfully exploit this
    vulnerability on a Cisco NX-OS device, an attacker must have Administrator credentials. (CVE-2024-20399)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cmd-injection-xD9OhyOP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a106946b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj94682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj97007");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj97009");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj97011");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj94682, CSCwj97007, CSCwj97009, CSCwj97011");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20399");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])7[0-9]{2,3}") &&
    ('MDS' >!< product_info.device || product_info.model !~ "^9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])5[5-6][0-9]{1,2}"))
audit(AUDIT_HOST_NOT, 'affected');

var version_list;
var version_list_2;
var vuln_model = FALSE;

# From advisory:
# Cisco NX-OS Software releases 9.3(5) and later are not affected by this vulnerability, with the exception of the following Cisco platforms:
var model_list = make_list(
  "N3K-C3264C-E(\s|$)",
  "N3K-C3172PQ-10GE(\s|$)",
  "N3K-C3172PQ-10GE-XL(\s|$)",
  "N3K-C3172TQ-10GT(\s|$)",
  "N3K-C3548P-10GX(\s|$)",
  "N9K-C92348GC-X(\s|$)"
);

var m_model = cisco_command_kb_item('Host/Cisco/Config/show_module', 'show module');

foreach var model (model_list)
{
  if(m_model =~ model)
    vuln_model = TRUE;
}

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
    '6.0(2)A6(1)',
    '6.0(2)A6(1a)',
    '6.0(2)A6(2)',
    '6.0(2)A6(2a)',
    '6.0(2)A6(3)',
    '6.0(2)A6(3a)',
    '6.0(2)A6(4)',
    '6.0(2)A6(4a)',
    '6.0(2)A6(5a)',
    '6.0(2)A6(5b)',
    '6.0(2)A6(6)',
    '6.0(2)A6(7)',
    '6.0(2)A6(8)',
    '6.0(2)A8(1)',
    '6.0(2)A8(2)',
    '6.0(2)A8(3)',
    '6.0(2)A8(4)',
    '6.0(2)A8(4a)',
    '6.0(2)A8(5)',
    '6.0(2)A8(6)',
    '6.0(2)A8(7)',
    '6.0(2)A8(7a)',
    '6.0(2)A8(7b)',
    '6.0(2)A8(8)',
    '6.0(2)A8(9)',
    '6.0(2)A8(10a)',
    '6.0(2)A8(10)',
    '6.0(2)A8(11)',
    '6.0(2)A8(11a)',
    '6.0(2)A8(11b)',
    '6.0(2)U6(1)',
    '6.0(2)U6(2)',
    '6.0(2)U6(3)',
    '6.0(2)U6(4)',
    '6.0(2)U6(5)',
    '6.0(2)U6(6)',
    '6.0(2)U6(7)',
    '6.0(2)U6(8)',
    '6.0(2)U6(1a)',
    '6.0(2)U6(2a)',
    '6.0(2)U6(3a)',
    '6.0(2)U6(4a)',
    '6.0(2)U6(5a)',
    '6.0(2)U6(5b)',
    '6.0(2)U6(5c)',
    '6.0(2)U6(9)',
    '6.0(2)U6(10)',
    '6.0(2)U6(10a)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '7.0(3)I4(1)',
    '7.0(3)I4(2)',
    '7.0(3)I4(3)',
    '7.0(3)I4(4)',
    '7.0(3)I4(5)',
    '7.0(3)I4(6)',
    '7.0(3)I4(7)',
    '7.0(3)I4(8)',
    '7.0(3)I4(8a)',
    '7.0(3)I4(8b)',
    '7.0(3)I4(8z)',
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(6z)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '7.0(3)IC4(4)',
    '7.0(3)IM7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)'
  );

  # Only specific models of Nexus 3000 are affected by 9.3(5) or later
  version_list_2 = make_list(
    '9.3(5)',
    '9.3(6)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '9.3(12)',
    '9.3(13)'
  );

  # Combine the version lists
  if (vuln_model)
    version_list = make_list(version_list, version_list_2);
}

if ('Nexus' >< product_info.device && product_info.model =~ "^7[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(2)',
    '6.2(2a)',
    '6.2(6)',
    '6.2(6b)',
    '6.2(8)',
    '6.2(8a)',
    '6.2(8b)',
    '6.2(10)',
    '6.2(12)',
    '6.2(18)',
    '6.2(16)',
    '6.2(14b)',
    '6.2(14)',
    '6.2(14a)',
    '6.2(6a)',
    '6.2(20)',
    '6.2(20a)',
    '6.2(22)',
    '6.2(24)',
    '6.2(24a)',
    '6.2(26)',
    '7.2(0)D1(1)',
    '7.2(1)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(1)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)D1(1)',
    '7.3(0)DX(1)',
    '7.3(1)D1(1)',
    '7.3(2)D1(1)',
    '7.3(2)D1(2)',
    '7.3(2)D1(3)',
    '7.3(2)D1(3a)',
    '7.3(2)D1(1d)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)',
    '8.2(3)',
    '8.2(4)',
    '8.2(5)',
    '8.2(6)',
    '8.2(7)',
    '8.2(7a)',
    '8.2(8)',
    '8.2(9)',
    '8.2(10)',
    '8.2(11)',
    '8.3(1)',
    '8.3(2)',
    '7.3(3)D1(1)',
    '7.3(4)D1(1)',
    '8.4(1)',
    '8.4(2)',
    '8.4(3)',
    '8.4(4)',
    '8.4(4a)',
    '8.4(5)',
    '8.4(6)',
    '8.4(6a)',
    '8.4(7)',
    '8.4(8)',
    '8.4(9)',
    '7.3(5)D1(1)',
    '7.3(6)D1(1)',
    '7.3(7)D1(1)',
    '7.3(8)D1(1)',
    '7.3(9)D1(1)'
  );
}

if ('MDS' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(1)',
    '6.2(5b)',
    '6.2(9)',
    '6.2(9a)',
    '6.2(9b)',
    '6.2(11)',
    '6.2(13a)',
    '6.2(13b)',
    '6.2(17)',
    '6.2(17a)',
    '6.2(27)',
    '6.2(29)',
    '6.2(33)',
    '7.3(0)D1(1)',
    '7.3(1)D1(1)',
    '8.1(1)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)',
    '8.3(1)',
    '8.3(2)',
    '9.2(1)',
    '9.2(2)',
    '8.4(1)',
    '8.4(2)',
    '8.4(2b)',
    '8.4(2c)',
    '8.4(2f)',
    '9.3(1)',
    '9.3(2)',
    '9.3(2a)',
    '8.5(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '7.0(3)I4(1)',
    '7.0(3)I4(2)',
    '7.0(3)I4(3)',
    '7.0(3)I4(4)',
    '7.0(3)I4(5)',
    '7.0(3)I4(6)',
    '7.0(3)I4(7)',
    '7.0(3)I4(8)',
    '7.0(3)I4(8a)',
    '7.0(3)I4(8b)',
    '7.0(3)I4(8z)',
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '7.0(3)IC4(4)',
    '7.0(3)IM3(2)',
    '7.0(3)IM3(2a)',
    '7.0(3)IM3(2b)',
    '7.0(3)IM3(3)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)'
  );

  # Only specific models of Nexus 9000 are affected by 9.3(5) or later
  version_list_2 = make_list(
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '9.3(12)',
    '9.3(13)',
    '10.2(1q)',
    '10.2(2a)',
    '10.3(99w)',
    '10.3(3w)',
    '10.3(99x)',
    '10.3(3o)',
    '10.3(3p)',
    '10.3(3q)',
    '10.3(3x)'
  );

  # Combine the version lists
  if (vuln_model)
    version_list = make_list(version_list, version_list_2);
}

if ('Nexus' >< product_info.device && product_info.model =~ "^5[5-6][0-9]{1,2}")
{
  version_list = make_list(
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(1)',
    '7.1(1)N1(1)',
    '7.1(1)N1(1a)',
    '7.1(2)N1(1)',
    '7.1(2)N1(1a)',
    '7.1(3)N1(1)',
    '7.1(3)N1(2)',
    '7.1(3)N1(5)',
    '7.1(3)N1(4)',
    '7.1(3)N1(3)',
    '7.1(3)N1(2a)',
    '7.1(4)N1(1)',
    '7.1(4)N1(1d)',
    '7.1(4)N1(1c)',
    '7.1(4)N1(1a)',
    '7.1(5)N1(1)',
    '7.1(5)N1(1b)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)',
    '7.3(1)N1(1)',
    '7.3(2)N1(1)',
    '7.3(2)N1(1b)',
    '7.3(2)N1(1c)',
    '7.3(3)N1(1)',
    '7.3(4)N1(1)',
    '7.3(4)N1(1a)',
    '7.3(5)N1(1)',
    '7.3(6)N1(1)',
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)',
    '7.3(13)N1(1)',
    '7.3(14)N1(1)'
  );
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj94682, CSCwj97007, CSCwj97009, CSCwj97011',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
