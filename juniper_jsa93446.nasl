#TRUSTED 2086fea6561fd070ba5744ee4dfffe1a41fc65f9dea8c4d2c2299adde338de14198e45abb7e19ed6dccda3bca99b91649f145b26976a0af8d6a2997f8fc1b6eb61922a945c20a5e5b542dfe6409e30220247d9dd86da2b1638cb0c7c66bc4b15a59e61142314619fcb3cbf6c610c9d0e033dc47148260999fcd909e024beafedfe99cc282239f86cfd2e4652f78db4e586fdb02d9c2faad8deecce7bf198fdcd66d890d54f6f771ad00d1a5d6326496cc7b4eb132065dabfe8fd5305b95db0823dd8de4754cd4447fa9efc26dfde1fbc7408f910cd1b5ff7cbc3276cad1af2edfe3820911d19cb1726867040859f085baae278099fe33fe7b861b943aeb470cd471629283db1edc52b0677bd325cb9bb92c69f5e37f98a889730c01ba45b26713a0d6ad055763775737ad6bd3779ef48aac0091badfb046444800e2641b890acf310b906df5d60eaeb2981f3aa0644948d3354de4c6f85afb3a83f2a310b169cee76d825042572a15d14d2889c5e81a47dfa21d9c901a7fb1c6706d716197f58de26b7f579abd72e6e8d03f613c17258ec01d8255cfd89b957df0d652bbf8170242dad3f8d5f279aa26070f4085141caab02793e7ba9c455d6246622dddb5ac1001cdb4758fc8115a42ced13cc202bbdbe6397287eb80ad00440a7dc7d7a5fea16d2279bf44d96b6b9e88d76a258d4ca032cfc22c4a2a1fbd3a5d8b8ed3e23f2
#TRUST-RSA-SHA256 3931e3131d8d526cb3d33c49f60528d26d6758bfa7e96380bf47a79d3aeb8879ac538103dc7365ceeafe403d93b70c0b49b694d74b9adcb9444455c805e0fca59f29c48047113939d756cc3a7aef3bdd1b7c31e4d667ebc6fd1dba07211da995c0e64d73cfc912b9abf3a8717ee9cb3e6e9b04e2cc563263139605ce5c45a127ca58a8df391f8f34ca40c6007a2e4d909e5f781cfa870d75d474cbfe34ced1f61ee9ea6226b593a532dcff05a4af4d2bff3413700b718946890ed1cf922ce0e82b65a5eb4374523df58626c85720a58d7ed5939faadec2bf76efb98ccfbdb4827eca47720b0da25e1ebba72b136df91ff25eae117c1494c5b1e7a24725a5a0a78c708b2fc8a52475d4703b42e27aa4ee0752ead82a0aebd3e10edca6d8eb0c40e977bf28ddc43c5b7a661c49e7142457613404dabdfc6710f67bcd4fceeb64d05d5833e47284d74c9fefe02cf35bbe8dfd2102c10228864190c99922b8980558ec49ecd56dd0526af1ec79f0425c40a1635be471caf590b8c12c055615e5990b28fbbec3b806709b9a39b27251ef44e3a2baff0c11a031a6d50e1b0537d1952e3c3d53ad96b9b8c596306a682b6c65cb13dbe1a131057cf10bc6fa001c6d5b64ae6481310ea0ea88ec730571cc6a10d6578e7cc0471e9918a116a28ac8c6cd6f389cd0bd581b00ee2d83b47f47038fa6dd2c85f8064cb97a8ff80f2b0f9efa41
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232834);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2025-21590");
  script_xref(name:"JSA", value:"JSA93446");
  script_xref(name:"IAVA", value:"2025-A-0170");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/03");

  script_name(english:"Juniper Junos OS Local Arbitrary Code Execution (JSA93446)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA93446
advisory:

  - An Improper Isolation or Compartmentalization vulnerability in the kernel of Juniper Networks Junos OS
    allows a local attacker with high privileges to compromise the integrity of the device. A local attacker
    with access to the shell is able to inject arbitrary code which can compromise an affected device. This
    issue is not exploitable from the Junos CLI. This issue affects Junos OS: * All versions before 21.2R3-S9,
    * 21.4 versions before 21.4R3-S10, * 22.2 versions before 22.2R3-S6, * 22.4 versions before 22.4R3-S6, *
    23.2 versions before 23.2R2-S3, * 23.4 versions before 23.4R2-S4, * 24.2 versions before 24.2R1-S2,
    24.2R2. (CVE-2025-21590)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b3f284f");
  # https://supportportal.juniper.net/s/article/2025-03-Reference-Advisory-The-RedPenguin-Malware-Incident
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4460528");
  # https://supportportal.juniper.net/s/article/2025-03-Out-of-Cycle-Security-Bulletin-Junos-OS-A-local-attacker-with-shell-access-can-execute-arbitrary-code-CVE-2025-21590
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b995393");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA93446");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21590");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S9'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S10'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S6'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S6'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S3'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2-S4'},
  {'min_ver':'24.2', 'fixed_ver':'24.2R1-S2', 'fixed_display':'24.2R1-S2, 24.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:FALSE, severity:SECURITY_WARNING);
