#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-34.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(189844);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id(
    "CVE-2023-2312",
    "CVE-2023-2929",
    "CVE-2023-2930",
    "CVE-2023-2931",
    "CVE-2023-2932",
    "CVE-2023-2933",
    "CVE-2023-2934",
    "CVE-2023-2935",
    "CVE-2023-2936",
    "CVE-2023-2937",
    "CVE-2023-2938",
    "CVE-2023-2939",
    "CVE-2023-2940",
    "CVE-2023-2941",
    "CVE-2023-3079",
    "CVE-2023-3214",
    "CVE-2023-3215",
    "CVE-2023-3216",
    "CVE-2023-3217",
    "CVE-2023-3420",
    "CVE-2023-3421",
    "CVE-2023-3422",
    "CVE-2023-3727",
    "CVE-2023-3728",
    "CVE-2023-3730",
    "CVE-2023-3732",
    "CVE-2023-3733",
    "CVE-2023-3734",
    "CVE-2023-3735",
    "CVE-2023-3736",
    "CVE-2023-3737",
    "CVE-2023-3738",
    "CVE-2023-3740",
    "CVE-2023-4068",
    "CVE-2023-4069",
    "CVE-2023-4070",
    "CVE-2023-4071",
    "CVE-2023-4072",
    "CVE-2023-4073",
    "CVE-2023-4074",
    "CVE-2023-4075",
    "CVE-2023-4076",
    "CVE-2023-4077",
    "CVE-2023-4078",
    "CVE-2023-4349",
    "CVE-2023-4350",
    "CVE-2023-4351",
    "CVE-2023-4352",
    "CVE-2023-4353",
    "CVE-2023-4354",
    "CVE-2023-4355",
    "CVE-2023-4356",
    "CVE-2023-4357",
    "CVE-2023-4358",
    "CVE-2023-4359",
    "CVE-2023-4360",
    "CVE-2023-4361",
    "CVE-2023-4362",
    "CVE-2023-4363",
    "CVE-2023-4364",
    "CVE-2023-4365",
    "CVE-2023-4366",
    "CVE-2023-4367",
    "CVE-2023-4368",
    "CVE-2023-4427",
    "CVE-2023-4428",
    "CVE-2023-4429",
    "CVE-2023-4430",
    "CVE-2023-4431",
    "CVE-2023-4572",
    "CVE-2023-4761",
    "CVE-2023-4762",
    "CVE-2023-4763",
    "CVE-2023-4764",
    "CVE-2023-4900",
    "CVE-2023-4901",
    "CVE-2023-4902",
    "CVE-2023-4903",
    "CVE-2023-4904",
    "CVE-2023-4905",
    "CVE-2023-4906",
    "CVE-2023-4907",
    "CVE-2023-4908",
    "CVE-2023-4909",
    "CVE-2023-5186",
    "CVE-2023-5187",
    "CVE-2023-5217",
    "CVE-2023-5218",
    "CVE-2023-5346",
    "CVE-2023-5472",
    "CVE-2023-5473",
    "CVE-2023-5474",
    "CVE-2023-5475",
    "CVE-2023-5476",
    "CVE-2023-5477",
    "CVE-2023-5478",
    "CVE-2023-5479",
    "CVE-2023-5480",
    "CVE-2023-5481",
    "CVE-2023-5482",
    "CVE-2023-5483",
    "CVE-2023-5484",
    "CVE-2023-5485",
    "CVE-2023-5486",
    "CVE-2023-5487",
    "CVE-2023-5849",
    "CVE-2023-5850",
    "CVE-2023-5851",
    "CVE-2023-5852",
    "CVE-2023-5853",
    "CVE-2023-5854",
    "CVE-2023-5855",
    "CVE-2023-5856",
    "CVE-2023-5857",
    "CVE-2023-5858",
    "CVE-2023-5859",
    "CVE-2023-5996",
    "CVE-2023-5997",
    "CVE-2023-6112",
    "CVE-2023-6345",
    "CVE-2023-6346",
    "CVE-2023-6347",
    "CVE-2023-6348",
    "CVE-2023-6350",
    "CVE-2023-6351",
    "CVE-2023-6508",
    "CVE-2023-6509",
    "CVE-2023-6510",
    "CVE-2023-6511",
    "CVE-2023-6512",
    "CVE-2023-6702",
    "CVE-2023-6703",
    "CVE-2023-6704",
    "CVE-2023-6705",
    "CVE-2023-6706",
    "CVE-2023-6707",
    "CVE-2023-7024",
    "CVE-2024-0222",
    "CVE-2024-0223",
    "CVE-2024-0224",
    "CVE-2024-0225"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/27");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/23");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/21");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/28");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/23");

  script_name(english:"GLSA-202401-34 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-34 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and its derivatives. Please review the CVE
    identifiers referenced below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-34");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=907999");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908471");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=909283");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=910522");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=911675");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=912364");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=913016");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=913710");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=914350");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=914871");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915137");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915560");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915961");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=916252");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=916620");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=917021");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=917357");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918882");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=919321");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=919802");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=920442");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=921337");
  script_set_attribute(attribute:"solution", value:
"All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-120.0.6099.109
        
All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-120.0.6099.109
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-120.0.2210.133");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0225");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/chromium',
    'unaffected' : make_list("ge 120.0.6099.109"),
    'vulnerable' : make_list("lt 120.0.6099.109")
  },
  {
    'name' : 'www-client/google-chrome',
    'unaffected' : make_list("ge 120.0.6099.109"),
    'vulnerable' : make_list("lt 120.0.6099.109")
  },
  {
    'name' : 'www-client/microsoft-edge',
    'unaffected' : make_list("ge 120.0.2210.133"),
    'vulnerable' : make_list("lt 120.0.2210.133")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Chromium / Google Chrome / Microsoft Edge');
}
