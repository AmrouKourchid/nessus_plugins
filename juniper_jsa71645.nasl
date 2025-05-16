#TRUSTED 26ff1591e46e92b5d7258d73725c86f9b7ecbb76b88fd14631da5c5d14f7514d64859e527064fefeb5e4428a2d4760a188aed60f152d63b2bc41ed0861b68841a81e7d18c98b056e14eed35c55e5a9904c8fd99ca3a31f24ad38c66a1bf0591b7bd1ad3dacda9e3acc17c7f69493de3afe046ec9073fa9bc0ef7aafce2a5a4ca03470d9fe8279526854d227619b81ff552602143313d5a791a3637b91841a44217566dc130479d7833c84dff466d6aebf31cb40f74e9f91e502957bca1cf43ce205a47a74b3c2b107755ed16bc497fa930020a7d78c42f75fbc08cb1914c5921f72b939cd9437300c7eead06ac99932a0d4ed540a8edb6f44292a68f33cc4b3e665c923d73cd56a5ea95e5ec095cffda7a9542b87bf13e95cf8f595b9cf71145ffba418b23a52a8d727d1e3e1a8a64d49516d94f50722f4f4a5374eb848fb071e8568da8c66f2b94c2f92915507c4ff6f05a921657089154e3e8b93f166f056d74f529fb5e35054e40eaec8d5c710e58ae61d2eaf5ff8d89a1b54984456cd12326d01a9ee74491305f3c06f4c6cb46db857d7d57add7e54cea63252464186fc2fcd627903ab37f262b9ff4cd30570dbbff55b703b9d6f8cdcf366232fedee3cf8fb2ea737b6b9fce7bd75b4c88e037fb0db71140cecbbd854a8b6a9a8e0cc491e85c032dba6f9f531a8c8881cf030f3999b3ce73f4b70a6342c81dd66f7d09b9
#TRUST-RSA-SHA256 0c45d77b8d4a19cc7e2f1f6493278a03220571c371d3919e7333e335bef44a6971713490b37342b1e3978592e8eed82ab3af4662f8fd887706970487799a54a1560fe8c7c0608eafb9bfb4ce686e16e4149225246fc3e7b225e840a789c0de404cd1f129cedcbd9b211a9bff313727adcd699db829c3fc3804bc18f91b07b8f9815dab081d0785259b571a8d605becad956985c0a6472388e8ad596a3fbfe73094214e6c70b7325e9c2a450da4a2f6a89d374a4b2ec3c377249658158e48c48624a64786072063ae3bbf67a9da93999205acc4dbf8b5bcaaaf53fd88ef9f2b1557b576b6177f636c2726c7baefa230caf5b0297baa83096d4947f066dba27f6544d7a16f2a0ffd7833bc9596343142fd9ad289891772887b24fb3e51320db43dd956a2fc1007e5ad9367a4735e5eef07b60956925dc7b78d4532f615c8026e875d97fba63293fa01464aab4b00dc8b96a5aaeffd8d38a1c4a528ec45d099e332dd929d988a145887ca4b10c5cb61c310406c4ca5dad6e42b832a5cf818a0e368923069493cef23c0a9474f284efd4673611f87edec38c83ecd1361f3096bb66a92c50eb30d704c27674b5d4ba3881e3b00e4a5a86f52eac4f88fbe80dabf22aa845bffe76f01641bbf81832d4bbce28a5ef5edc4c5ffd39276f7a5812609a38b24f68831b0f5739d54409746c2058ae9e753be14ef114bb5bcff86da112fa664
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178960);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/24");

  script_cve_id("CVE-2023-36838");
  script_xref(name:"JSA", value:"JSA71645");
  script_xref(name:"IAVA", value:"2023-A-0357-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA71645)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA71645
advisory.

  - An Out-of-bounds Read vulnerability in the flow processing daemon (flowd) of Juniper Networks Junos OS on
    SRX Series allows a local, authenticated attacker with low privileges, to cause a Denial of Service (DoS).
    (CVE-2023-36838)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-07-Security-Bulletin-Junos-OS-SRX-Series-A-flowd-core-occurs-when-running-a-low-privileged-CLI-command-CVE-2023-36838
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3442024");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71645");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.2R3-S7', 'model':'^SRX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1', 'model':'^SRX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S6', 'model':'^SRX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5', 'model':'^SRX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4', 'model':'^SRX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4', 'model':'^SRX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3', 'model':'^SRX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S1', 'model':'^SRX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3', 'model':'^SRX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2', 'model':'^SRX'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R1-S1', 'model':'^SRX', 'fixed_display':'22.4R1-S1, 22.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
