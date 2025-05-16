#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/04 due to vendor advisory.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0142. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185413);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/04");

  script_cve_id(
    "CVE-2018-1118",
    "CVE-2018-7191",
    "CVE-2019-16089",
    "CVE-2020-36694",
    "CVE-2021-3759",
    "CVE-2021-29648",
    "CVE-2021-30178",
    "CVE-2021-32078",
    "CVE-2021-33061",
    "CVE-2022-1184",
    "CVE-2022-2196",
    "CVE-2022-2590",
    "CVE-2022-3108",
    "CVE-2022-3303",
    "CVE-2022-3344",
    "CVE-2022-3424",
    "CVE-2022-3523",
    "CVE-2022-3595",
    "CVE-2022-3606",
    "CVE-2022-3643",
    "CVE-2022-3707",
    "CVE-2022-3903",
    "CVE-2022-4095",
    "CVE-2022-4129",
    "CVE-2022-4379",
    "CVE-2022-4382",
    "CVE-2022-4662",
    "CVE-2022-4744",
    "CVE-2022-36280",
    "CVE-2022-41218",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-42432",
    "CVE-2022-42703",
    "CVE-2022-45884",
    "CVE-2022-45885",
    "CVE-2022-45886",
    "CVE-2022-45887",
    "CVE-2022-45934",
    "CVE-2022-47518",
    "CVE-2022-47519",
    "CVE-2022-47520",
    "CVE-2022-47521",
    "CVE-2022-47929",
    "CVE-2022-47946",
    "CVE-2023-0179",
    "CVE-2023-0266",
    "CVE-2023-0386",
    "CVE-2023-0394",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-0461",
    "CVE-2023-0590",
    "CVE-2023-0597",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1077",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1382",
    "CVE-2023-1829",
    "CVE-2023-1855",
    "CVE-2023-1859",
    "CVE-2023-1989",
    "CVE-2023-1998",
    "CVE-2023-2006",
    "CVE-2023-2007",
    "CVE-2023-2124",
    "CVE-2023-2162",
    "CVE-2023-2177",
    "CVE-2023-2235",
    "CVE-2023-2269",
    "CVE-2023-2898",
    "CVE-2023-4133",
    "CVE-2023-23000",
    "CVE-2023-23004",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-23559",
    "CVE-2023-25012",
    "CVE-2023-26545",
    "CVE-2023-26607",
    "CVE-2023-28327",
    "CVE-2023-28328",
    "CVE-2023-28466",
    "CVE-2023-30456",
    "CVE-2023-31436",
    "CVE-2023-32233",
    "CVE-2023-32269"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"NewStart CGSL MAIN 6.06 : kernel Multiple Vulnerabilities (NS-SA-2023-0142) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0142");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1118");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-7191");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-16089");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-36694");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-29648");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30178");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-32078");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33061");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2196");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2590");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3108");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3344");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3424");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3523");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3595");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3606");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3643");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3707");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3903");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4095");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4129");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41849");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42328");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42329");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42432");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42703");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4379");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4382");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45884");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45885");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45886");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45887");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4662");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-47518");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-47519");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-47520");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-47521");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-47929");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-47946");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0179");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0266");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0386");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0458");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0459");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0590");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-0597");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1073");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1074");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1075");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1076");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1077");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1281");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1382");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1855");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1859");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2006");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2007");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2124");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2177");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2235");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2269");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23000");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23004");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23559");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25012");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-26545");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-26607");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28327");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28328");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28466");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2898");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-30456");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-31436");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32233");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-32269");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4133");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32078");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kata-linux-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-virt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated.");
