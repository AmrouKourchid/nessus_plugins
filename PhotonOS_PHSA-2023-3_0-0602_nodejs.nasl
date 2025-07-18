#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2023-3.0-0602. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204114);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/25");

  script_cve_id(
    "CVE-2018-16065",
    "CVE-2018-17458",
    "CVE-2018-17465",
    "CVE-2019-13670",
    "CVE-2019-13696",
    "CVE-2019-13698",
    "CVE-2019-13728",
    "CVE-2019-13730",
    "CVE-2019-13735",
    "CVE-2019-13764",
    "CVE-2019-5784",
    "CVE-2019-5807",
    "CVE-2019-5813",
    "CVE-2019-5825",
    "CVE-2019-5831",
    "CVE-2019-5841",
    "CVE-2019-5843",
    "CVE-2019-5847",
    "CVE-2019-5866",
    "CVE-2020-15979",
    "CVE-2020-16040",
    "CVE-2020-16042",
    "CVE-2020-6379",
    "CVE-2020-6381",
    "CVE-2020-6382",
    "CVE-2020-6383",
    "CVE-2020-6395",
    "CVE-2020-6415",
    "CVE-2020-6418",
    "CVE-2020-6419",
    "CVE-2020-6430",
    "CVE-2020-6434",
    "CVE-2020-6447",
    "CVE-2020-6448",
    "CVE-2020-6453",
    "CVE-2020-6468",
    "CVE-2020-6507",
    "CVE-2020-6512",
    "CVE-2020-6518",
    "CVE-2020-6533",
    "CVE-2020-6537",
    "CVE-2021-21169",
    "CVE-2021-21220",
    "CVE-2021-21227",
    "CVE-2021-21230",
    "CVE-2021-21231",
    "CVE-2021-30513",
    "CVE-2021-30517",
    "CVE-2021-30541",
    "CVE-2021-30551",
    "CVE-2021-30598",
    "CVE-2021-30599",
    "CVE-2021-37975",
    "CVE-2021-38007",
    "CVE-2021-4061",
    "CVE-2023-0466"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");
  script_xref(name:"CEA-ID", value:"CEA-2020-0023");

  script_name(english:"Photon OS 3.0: Nodejs PHSA-2023-3.0-0602");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the nodejs package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-3.0-602.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5866");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 89.0.4389.128 V8 XOR Typer Out-Of-Bounds Access RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:nodejs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item('Host/PhotonOS/release');
if (isnull(_release) || _release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (_release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'nodejs-16.20.0-1.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'nodejs-devel-16.20.0-1.ph3')) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs');
}
