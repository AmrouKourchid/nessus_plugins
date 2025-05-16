#TRUSTED ac5e979eee9fe9ac8ee29b7dc822a742960bf3966bc87d358a222dba3fdc5f029bf698e06298b9c05b8e21c2ed3ee3bff0adfe91276e981ace9130671cc491db92799c980be5dcde656643baafbf95fbc6197461b24232fb5bfec6b8ba6f580131128da49365cc6d9c95ed5af1b70aa83763d094f835f71794d0701470276f7393eea4a3120ce98c456aa2fef8065261a50819d8e3ba1a7a0916efb78b891ba2b5081ab6d1c76a288f8f379e21604d6c9cd9bc8ccf9257a6736427be44ec9332468faa4a2e68e86b62172b0383a47a9ecf68b0c57b48fd12fefa3a6d2f582fbd12312c6c8994b49fc7f788f9c7a38c7b20a28cd332e42280abfec0ff4edfe858ecb8f98d8392ee572459271cf9b680fc9e554be091b3a68389e5fe6f224af44de1c8de635d040044ca005c751f0d035e8ad74c95be5ab479e63ebc3640a8f98156681160bbc12d351025144aef64e12defead65f3ba3f1bf416f1fde8fc017baddf42967408dbfb6cb0068c729144dd248119f809f6d9a5a11336a77b1f447c182ccf86e9918df6e3211e00eaafb22c5943023908a77233fe20c68168190f543c07d015bd731bad7dcd932e00c0f34a3419b426ff95bf7434d51f4f523ac843cd617af0c324fc87584cd1468056b53d5bbf31a1cf3b5020274dfd17d1cfd5f908ba043290296e81391ed0532b71317df2d11416d2c376aa530dc444ba8259681
#TRUST-RSA-SHA256 41af7e113405455e435042db7a809a8e52d6e8da5ad944e768080565c1a5fc82729b41743f62d3883993d2a512b71d87768597e93bc9c1af493b24fe3da603e094216c860d85d79cefa9771fe45d74f3e8e948565fe5a54aa262d04d56493de3331935fd25508bce51f84e4523e2799e933b31315585857eb84d2b030e8621ac074fb2c1f9b81d41c79715e1146318cd179db9854299678ff09ceca74400fbc5e6b7d8be5f95586632c2f4f80aa420fe822b8a48001e93223a891ed7477efe3077414478a9e004c7eb762b8d36243752cc9c03eea4ae547f78f2662bc2fb7dcc7ee19072e652f3669f123144f5ada3516afe63277d371a6a51e906bf6f183b6c4a81975a035e53e56e6b030f2e1af25d60a2a096b7e890290c84788c26e4bcebbac2f746467ef584f17f8072da9e54f389b1a3bf87595b66cabf33c3764fae58144646219c539072dc695a4004dfbb72e9020c7d83549db507874aadb9a9928461aa09b070bc9cd499a511c878ccc8548eb99216484fa401c9c93183449b4f0c47f7317e96700b9e4bbcfcedcd36f42b29a06f3b8f85111c7ad8026f65c51d93fffec1119393cc7a7e0df209bf870c7115604116177c21b97b41663a36a751d30e1d32401b7202886d181e4963887b1d29b26cfcef65f2a4cb8854d9c846b4b3384d93a7913326c8e0e3921e530e0c8dc75ec3f3d4e07cf88f3b5a480d96bf4f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166324);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_cve_id("CVE-2022-22239");
  script_xref(name:"JSA", value:"JSA69895");
  script_xref(name:"IAVA", value:"2022-A-0421-S");

  script_name(english:"Juniper Junos OS Privilege Escalation (JSA69895)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a privilege escalation vulnerability as
referenced in the JSA69895 advisory. An Execution with Unnecessary Privileges vulnerability in Management Daemon
(mgd) of Juniper Networks Junos OS Evolved allows a locally authenticated attacker with low privileges to escalate
their privileges on the device and potentially remote systems.

A workaround for this issue is to modify the applicable login class(es) so that the ssh command can not be accessed
anymore. This can be done by removing the 'network' permission or modifying the resp. allow-/deny-commands
configuration.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-The-ssh-CLI-command-always-runs-as-root-which-can-lead-to-privilege-escalation-CVE-2022-22239
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f66b8bb");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69895");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0-EVO', 'fixed_ver':'20.4R3-S5-EVO'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R3-EVO'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R2-S1-EVO', 'fixed_display':'21.2R2-S1-EVO, 21.2R3-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);