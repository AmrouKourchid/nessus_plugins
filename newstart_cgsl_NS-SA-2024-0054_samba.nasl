#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0054. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206855);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/17");

  script_cve_id(
    "CVE-2007-2446",
    "CVE-2007-2447",
    "CVE-2008-1105",
    "CVE-2009-2813",
    "CVE-2009-2906",
    "CVE-2009-2948",
    "CVE-2012-0817",
    "CVE-2012-1182",
    "CVE-2012-2111",
    "CVE-2012-6150",
    "CVE-2013-0172",
    "CVE-2013-0213",
    "CVE-2013-0214",
    "CVE-2013-4408",
    "CVE-2013-4475",
    "CVE-2013-4496",
    "CVE-2013-6442",
    "CVE-2014-0178",
    "CVE-2014-0244",
    "CVE-2014-3493",
    "CVE-2014-3560",
    "CVE-2015-3223",
    "CVE-2015-5252",
    "CVE-2015-5296",
    "CVE-2015-5299",
    "CVE-2015-5370",
    "CVE-2015-7540",
    "CVE-2015-7560",
    "CVE-2016-2110",
    "CVE-2016-2111",
    "CVE-2016-2112",
    "CVE-2016-2113",
    "CVE-2016-2114",
    "CVE-2016-2115",
    "CVE-2016-2118",
    "CVE-2016-2119",
    "CVE-2016-2123",
    "CVE-2016-2125",
    "CVE-2016-2126",
    "CVE-2017-2619",
    "CVE-2017-7494",
    "CVE-2017-12150",
    "CVE-2017-12151",
    "CVE-2017-12163",
    "CVE-2017-14746",
    "CVE-2017-15275",
    "CVE-2018-1050",
    "CVE-2018-1057",
    "CVE-2018-1139",
    "CVE-2018-10858",
    "CVE-2018-10918",
    "CVE-2018-10919",
    "CVE-2020-14383",
    "CVE-2021-44142",
    "CVE-2023-34966",
    "CVE-2023-34967"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");
  script_xref(name:"IAVA", value:"2016-A-0002-S");
  script_xref(name:"IAVA", value:"2016-A-0095-S");
  script_xref(name:"IAVA", value:"2016-A-0195-S");
  script_xref(name:"IAVA", value:"2016-A-0353-S");
  script_xref(name:"IAVA", value:"2017-A-0085-S");
  script_xref(name:"IAVA", value:"2017-A-0163-S");
  script_xref(name:"IAVA", value:"2017-A-0281-S");
  script_xref(name:"IAVA", value:"2017-A-0344-S");
  script_xref(name:"IAVA", value:"2018-A-0074-S");
  script_xref(name:"IAVA", value:"2018-A-0257-S");
  script_xref(name:"IAVA", value:"2020-A-0508-S");
  script_xref(name:"IAVA", value:"2023-A-0376-S");
  script_xref(name:"IAVB", value:"2009-B-0050-S");
  script_xref(name:"IAVB", value:"2012-B-0045-S");
  script_xref(name:"IAVB", value:"2012-B-0047-S");
  script_xref(name:"IAVB", value:"2013-B-0006-S");
  script_xref(name:"IAVB", value:"2013-B-0010-S");
  script_xref(name:"IAVB", value:"2013-B-0131-S");
  script_xref(name:"IAVB", value:"2014-B-0067-S");
  script_xref(name:"IAVB", value:"2014-B-0105-S");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : samba Multiple Vulnerabilities (NS-SA-2024-0054)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has samba packages installed that are affected by multiple
vulnerabilities:

  - Multiple heap-based buffer overflows in the NDR parsing in smbd in Samba 3.0.0 through 3.0.25rc3 allow
    remote attackers to execute arbitrary code via crafted MS-RPC requests involving (1) DFSEnum
    (netdfs_io_dfs_EnumInfo_d), (2) RFNPCNEX (smb_io_notify_option_type_data), (3) LsarAddPrivilegesToAccount
    (lsa_io_privilege_set), (4) NetSetFileSecurity (sec_io_acl), or (5) LsarLookupSids/LsarLookupSids2
    (lsa_io_trans_names). (CVE-2007-2446)

  - The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute
    arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the
    username map script smb.conf option is enabled, and allows remote authenticated users to execute
    commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file
    share management. (CVE-2007-2447)

  - Heap-based buffer overflow in the receive_smb_raw function in util/sock.c in Samba 3.0.0 through 3.0.29
    allows remote attackers to execute arbitrary code via a crafted SMB response. (CVE-2008-1105)

  - Samba 3.4 before 3.4.2, 3.3 before 3.3.8, 3.2 before 3.2.15, and 3.0.12 through 3.0.36, as used in the SMB
    subsystem in Apple Mac OS X 10.5.8 when Windows File Sharing is enabled, Fedora 11, and other operating
    systems, does not properly handle errors in resolving pathnames, which allows remote authenticated users
    to bypass intended sharing restrictions, and read, create, or modify files, in certain circumstances
    involving user accounts that lack home directories. (CVE-2009-2813)

  - smbd in Samba 3.0 before 3.0.37, 3.2 before 3.2.15, 3.3 before 3.3.8, and 3.4 before 3.4.2 allows remote
    authenticated users to cause a denial of service (infinite loop) via an unanticipated oplock break
    notification reply packet. (CVE-2009-2906)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0054");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2007-2446");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2007-2447");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2008-1105");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2813");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2906");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2948");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-0817");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-1182");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-2111");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-6150");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-0172");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-0213");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-0214");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4408");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4475");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4496");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-6442");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-0178");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-0244");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-3493");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-3560");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3223");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-5252");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-5296");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-5299");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-5370");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-7540");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-7560");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2110");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2111");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2112");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2113");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2114");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2115");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2118");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2119");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2123");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2125");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2126");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-12150");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-12151");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-12163");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-14746");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-15275");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-2619");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-7494");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1050");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1057");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-10858");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-10918");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-10919");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1139");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-14383");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-44142");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-34966");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-34967");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL samba packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba lsa_io_trans_names Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'libsmbclient-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'libwbclient-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-client-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-client-libs-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-common-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-common-libs-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-common-tools-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-libs-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-winbind-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-winbind-clients-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765',
    'samba-winbind-modules-4.14.5-9.el8_5.cgslv6_2.4.gc40dc765'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'samba');
}
