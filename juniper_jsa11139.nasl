#TRUSTED a540cced20a498398e02f977eed3f630ed614391d810934241c7f325e1099438994cd433309fed8abe243f7655b663f03b989ce3bbfc568f2210d6d9197ce0528fd32addb4fff2dc1be508459d346faa9d10a645e1905a9de096ba580021eea9e1ab0e597a86be48a2d0912b26ef583ea020039ca62735f08fb0e7e9b12a26b7e29af2ccb8a6182fbd4d0dc3053756a8dcb2842fa598b3d7ed04e3e034f8e2d1edea3adebc5b7b9fb399d94d78d00ee3f8ac47ef8d0ceae603063cbd85c11b615e1e47cc207bdcc81edb58468d72bb8415781335cb2794273da8fc8e795c7247971e39e0386ca27a53251df7a3005d83c1ea7ab3c266979488fc7df7300c4e0d114f596fa31f23ee36eeac16d5723d34fc8335161b022b247742b2008b4c404180cad6d8f53181a318a471fd6a875fcf8df72323591e153e841d2bbbd9173fd0dd8b565db21f28189fe65c64b226f2f9a22abc798f47948c80a7b4f38b7d64fcaa63a1fd932fbd0f9dc2fe2429d66262175d1fa4b43e005ad43c81d62e920d23863d89ac5061e517707a1e83883d4866d3dfcdd2d10a6c88afc098649e8b25b7ed754968649164111ce85b5b33a5ce84cff6cf6471eaa67fbfd4dc60143997d0b29962019e0aee193b0bcf33b327f5addbb2faaea10f82a0ef95e0f54676bd2ee4d774edb712f7d6dcab4b78d5c43a4798b754550f5f62a0aa322aeb1452179f
#TRUST-RSA-SHA256 9f67f202b3ba2d826f617036e22a208e08d7e0664934a470ce373de8d445c56e77d9cc295c13263269e9f259461329e254a399472a1f07be193428c854ffc324c43eb67625038825db6d8759011fa9a8ec888faefd8ac8d9b28a6cda06bffa67f60899bee33863b87b31a834402af380124de365135462ca559bad93dfb322af7361d3f59e773ec6d0c07ad1bc6a1c95cd1257424f733c91e80d4ddf581a1bf7fa4c03e38655bbd7d48b3ce8ce8f6140b749c4f357c52889082fb146e08ecf5de34680ad5371da4f8c7433aed456c9d9a547a7c73351f286fd6e384cbc967b36d08f135d46591d833607d2d0425c5ffc88fffcf1800f6022cd60c1450d4dac7970e21a39ee57844cb9109deddcfde6ffcf51c10c4abebf7ef2da80337af3e713f3e9310e15416698082e3885f5dca22d5830a921b220ba606a17e49e903b4cde9f63151f3f373d22b72f8ef20267d4096750c0d98689970eb3878cd50a07e7e508feeab36dbf828455adfd6aa3c44ace174e77a618d587061c77f1ffdd923cb6ed9d86b0123d80a3bcf78e748994f55e450b484572951c7b23c40e082f3c3b3b595c23f509b4a30719e3f9dd44d6394e749f02dfde736a61354b801cf80d601870b5c278071b046db4533d7b70b0d2803cc34fe81bb08a1c16038853e1f59dba6c6ac42b997b10bc3c9b10372760051fecd160178d9c03104b67e210e0466e9a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148677);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0246");
  script_xref(name:"JSA", value:"JSA11139");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11139)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11139
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://supportportal.juniper.net/s/article/2021-04-Security-Bulletin-Junos-OS-SRX1500-4100-4200-4600-5000-Series-with-SPC2-SPC3-In-a-multi-tenant-env-a-tenant-host-admin-may-jailbreak-out-of-their-network-impacting-other-tenant-networks-or-gather-info-from-other-networks-CVE-2021-0246
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1eafafda");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11139");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.3', 'fixed_ver':'18.3R1', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)', 'fixed_display':'18.3R1, 18.3R3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
