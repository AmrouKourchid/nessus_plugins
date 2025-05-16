#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:7000.
##

include('compat.inc');

if (description)
{
  script_id(207758);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/25");

  script_cve_id(
    "CVE-2021-46984",
    "CVE-2021-47097",
    "CVE-2021-47101",
    "CVE-2021-47287",
    "CVE-2021-47289",
    "CVE-2021-47321",
    "CVE-2021-47338",
    "CVE-2021-47352",
    "CVE-2021-47383",
    "CVE-2021-47384",
    "CVE-2021-47385",
    "CVE-2021-47386",
    "CVE-2021-47393",
    "CVE-2021-47412",
    "CVE-2021-47432",
    "CVE-2021-47441",
    "CVE-2021-47455",
    "CVE-2021-47466",
    "CVE-2021-47497",
    "CVE-2021-47527",
    "CVE-2021-47560",
    "CVE-2021-47582",
    "CVE-2021-47609",
    "CVE-2022-48619",
    "CVE-2022-48754",
    "CVE-2022-48760",
    "CVE-2022-48804",
    "CVE-2022-48836",
    "CVE-2022-48866",
    "CVE-2023-6040",
    "CVE-2023-52470",
    "CVE-2023-52476",
    "CVE-2023-52478",
    "CVE-2023-52522",
    "CVE-2023-52605",
    "CVE-2023-52683",
    "CVE-2023-52798",
    "CVE-2023-52800",
    "CVE-2023-52809",
    "CVE-2023-52817",
    "CVE-2023-52840",
    "CVE-2024-23848",
    "CVE-2024-26595",
    "CVE-2024-26600",
    "CVE-2024-26638",
    "CVE-2024-26645",
    "CVE-2024-26649",
    "CVE-2024-26665",
    "CVE-2024-26717",
    "CVE-2024-26720",
    "CVE-2024-26769",
    "CVE-2024-26846",
    "CVE-2024-26855",
    "CVE-2024-26880",
    "CVE-2024-26894",
    "CVE-2024-26923",
    "CVE-2024-26939",
    "CVE-2024-27013",
    "CVE-2024-27042",
    "CVE-2024-35809",
    "CVE-2024-35877",
    "CVE-2024-35884",
    "CVE-2024-35944",
    "CVE-2024-35989",
    "CVE-2024-36883",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36919",
    "CVE-2024-36920",
    "CVE-2024-36922",
    "CVE-2024-36939",
    "CVE-2024-36953",
    "CVE-2024-37356",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38570",
    "CVE-2024-38579",
    "CVE-2024-38581",
    "CVE-2024-38619",
    "CVE-2024-39471",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39506",
    "CVE-2024-40901",
    "CVE-2024-40904",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40941",
    "CVE-2024-40954",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40972",
    "CVE-2024-40977",
    "CVE-2024-40978",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40995",
    "CVE-2024-40997",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41007",
    "CVE-2024-41008",
    "CVE-2024-41012",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41023",
    "CVE-2024-41035",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41055",
    "CVE-2024-41056",
    "CVE-2024-41060",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41071",
    "CVE-2024-41076",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41097",
    "CVE-2024-42084",
    "CVE-2024-42090",
    "CVE-2024-42094",
    "CVE-2024-42096",
    "CVE-2024-42114",
    "CVE-2024-42124",
    "CVE-2024-42131",
    "CVE-2024-42152",
    "CVE-2024-42154",
    "CVE-2024-42225",
    "CVE-2024-42226",
    "CVE-2024-42228",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42240",
    "CVE-2024-42246",
    "CVE-2024-42265",
    "CVE-2024-42322",
    "CVE-2024-43830",
    "CVE-2024-43871"
  );
  script_xref(name:"ALSA", value:"2024:7000");
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"AlmaLinux 8 : kernel (ALSA-2024:7000)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:7000 advisory.

    CVE-2023-6040  CVE-2024-26595  CVE-2024-26600  CVE-2021-46984  CVE-2023-52478  CVE-2023-52476
    CVE-2023-52522  CVE-2021-47101  CVE-2021-47097  CVE-2023-52605  CVE-2024-26638  CVE-2024-26645
    CVE-2024-26665  CVE-2024-26720  CVE-2024-26717  CVE-2024-26769  CVE-2024-26846  CVE-2024-26894
    CVE-2024-26880  CVE-2024-26855  CVE-2024-26923  CVE-2024-26939  CVE-2024-27013  CVE-2024-27042
    CVE-2024-35809  CVE-2023-52683  CVE-2024-35884  CVE-2024-35877  CVE-2024-35944  CVE-2024-35989
    CVE-2021-47412  CVE-2021-47393  CVE-2021-47386  CVE-2021-47385  CVE-2021-47384  CVE-2021-47383
    CVE-2021-47432  CVE-2021-47352  CVE-2021-47338  CVE-2021-47321  CVE-2021-47289  CVE-2021-47287
    CVE-2023-52798  CVE-2023-52809  CVE-2023-52817  CVE-2023-52840  CVE-2023-52800  CVE-2021-47441
    CVE-2021-47466  CVE-2021-47455  CVE-2021-47497  CVE-2021-47560  CVE-2021-47527  CVE-2024-36883
    CVE-2024-36922  CVE-2024-36920  CVE-2024-36902  CVE-2024-36953  CVE-2024-36939  CVE-2024-36919
    CVE-2024-36901  CVE-2021-47582  CVE-2021-47609  CVE-2024-38619  CVE-2022-48754  CVE-2022-48760
    CVE-2024-38581  CVE-2024-38579  CVE-2024-38570  CVE-2024-38559  CVE-2024-38558  CVE-2024-37356
    CVE-2024-39471  CVE-2024-39499  CVE-2024-39501  CVE-2024-39506  CVE-2024-40904  CVE-2024-40911
    CVE-2024-40912  CVE-2024-40929  CVE-2024-40931  CVE-2024-40941  CVE-2024-40954  CVE-2024-40958
    CVE-2024-40959  CVE-2024-40960  CVE-2024-40972  CVE-2024-40977  CVE-2024-40978  CVE-2024-40988
    CVE-2024-40989  CVE-2024-40995  CVE-2024-40997  CVE-2024-40998  CVE-2024-41005  CVE-2024-40901
    CVE-2024-41007  CVE-2024-41008  CVE-2022-48804  CVE-2022-48836  CVE-2022-48866  CVE-2024-41090
    CVE-2024-41091  CVE-2024-41012  CVE-2024-41013  CVE-2024-41014  CVE-2024-41023  CVE-2024-41035
    CVE-2024-41038  CVE-2024-41039  CVE-2024-41040  CVE-2024-41041  CVE-2024-41044  CVE-2024-41055
    CVE-2024-41056  CVE-2024-41060  CVE-2024-41064  CVE-2024-41065  CVE-2024-41071  CVE-2024-41076
    CVE-2024-41097  CVE-2024-42084  CVE-2024-42090  CVE-2024-42094  CVE-2024-42096  CVE-2024-42114
    CVE-2024-42124  CVE-2024-42131  CVE-2024-42152  CVE-2024-42154  CVE-2024-42225  CVE-2024-42226
    CVE-2024-42228  CVE-2024-42237  CVE-2024-42238  CVE-2024-42240  CVE-2024-42246  CVE-2024-42322
    CVE-2024-43830  CVE-2024-43871

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-7000.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 122, 125, 130, 158, 190, 20, 362, 369, 372, 388, 400, 401, 402, 404, 413, 416, 456, 457, 476, 665, 667, 690, 754, 787, 820, 822, 825, 833, 911, 96, 99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-46984', 'CVE-2021-47097', 'CVE-2021-47101', 'CVE-2021-47287', 'CVE-2021-47289', 'CVE-2021-47321', 'CVE-2021-47338', 'CVE-2021-47352', 'CVE-2021-47383', 'CVE-2021-47384', 'CVE-2021-47385', 'CVE-2021-47386', 'CVE-2021-47393', 'CVE-2021-47412', 'CVE-2021-47432', 'CVE-2021-47441', 'CVE-2021-47455', 'CVE-2021-47466', 'CVE-2021-47497', 'CVE-2021-47527', 'CVE-2021-47560', 'CVE-2021-47582', 'CVE-2021-47609', 'CVE-2022-48619', 'CVE-2022-48754', 'CVE-2022-48760', 'CVE-2022-48804', 'CVE-2022-48836', 'CVE-2022-48866', 'CVE-2023-6040', 'CVE-2023-52470', 'CVE-2023-52476', 'CVE-2023-52478', 'CVE-2023-52522', 'CVE-2023-52605', 'CVE-2023-52683', 'CVE-2023-52798', 'CVE-2023-52800', 'CVE-2023-52809', 'CVE-2023-52817', 'CVE-2023-52840', 'CVE-2024-23848', 'CVE-2024-26595', 'CVE-2024-26600', 'CVE-2024-26638', 'CVE-2024-26645', 'CVE-2024-26649', 'CVE-2024-26665', 'CVE-2024-26717', 'CVE-2024-26720', 'CVE-2024-26769', 'CVE-2024-26846', 'CVE-2024-26855', 'CVE-2024-26880', 'CVE-2024-26894', 'CVE-2024-26923', 'CVE-2024-26939', 'CVE-2024-27013', 'CVE-2024-27042', 'CVE-2024-35809', 'CVE-2024-35877', 'CVE-2024-35884', 'CVE-2024-35944', 'CVE-2024-35989', 'CVE-2024-36883', 'CVE-2024-36901', 'CVE-2024-36902', 'CVE-2024-36919', 'CVE-2024-36920', 'CVE-2024-36922', 'CVE-2024-36939', 'CVE-2024-36953', 'CVE-2024-37356', 'CVE-2024-38558', 'CVE-2024-38559', 'CVE-2024-38570', 'CVE-2024-38579', 'CVE-2024-38581', 'CVE-2024-38619', 'CVE-2024-39471', 'CVE-2024-39499', 'CVE-2024-39501', 'CVE-2024-39506', 'CVE-2024-40901', 'CVE-2024-40904', 'CVE-2024-40911', 'CVE-2024-40912', 'CVE-2024-40929', 'CVE-2024-40931', 'CVE-2024-40941', 'CVE-2024-40954', 'CVE-2024-40958', 'CVE-2024-40959', 'CVE-2024-40960', 'CVE-2024-40972', 'CVE-2024-40977', 'CVE-2024-40978', 'CVE-2024-40988', 'CVE-2024-40989', 'CVE-2024-40995', 'CVE-2024-40997', 'CVE-2024-40998', 'CVE-2024-41005', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41012', 'CVE-2024-41013', 'CVE-2024-41014', 'CVE-2024-41023', 'CVE-2024-41035', 'CVE-2024-41038', 'CVE-2024-41039', 'CVE-2024-41040', 'CVE-2024-41041', 'CVE-2024-41044', 'CVE-2024-41055', 'CVE-2024-41056', 'CVE-2024-41060', 'CVE-2024-41064', 'CVE-2024-41065', 'CVE-2024-41071', 'CVE-2024-41076', 'CVE-2024-41090', 'CVE-2024-41091', 'CVE-2024-41097', 'CVE-2024-42084', 'CVE-2024-42090', 'CVE-2024-42094', 'CVE-2024-42096', 'CVE-2024-42114', 'CVE-2024-42124', 'CVE-2024-42131', 'CVE-2024-42152', 'CVE-2024-42154', 'CVE-2024-42225', 'CVE-2024-42226', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42246', 'CVE-2024-42265', 'CVE-2024-42322', 'CVE-2024-43830', 'CVE-2024-43871');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2024:7000');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.22.1.el8_10', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.22.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.22.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
