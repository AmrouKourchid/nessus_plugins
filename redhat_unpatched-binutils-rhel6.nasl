#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-05-31.
# This plugin has been deprecated as it does not adhere to established standards for this style of check.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory binutils. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195456);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2017-6965",
    "CVE-2017-6966",
    "CVE-2017-6969",
    "CVE-2017-7209",
    "CVE-2017-7210",
    "CVE-2017-7223",
    "CVE-2017-7224",
    "CVE-2017-7225",
    "CVE-2017-7226",
    "CVE-2017-7227",
    "CVE-2017-7299",
    "CVE-2017-7300",
    "CVE-2017-7301",
    "CVE-2017-7302",
    "CVE-2017-7303",
    "CVE-2017-7304",
    "CVE-2017-7614",
    "CVE-2017-8392",
    "CVE-2017-8393",
    "CVE-2017-8394",
    "CVE-2017-8395",
    "CVE-2017-8396",
    "CVE-2017-8397",
    "CVE-2017-8398",
    "CVE-2017-8421",
    "CVE-2017-9038",
    "CVE-2017-9039",
    "CVE-2017-9040",
    "CVE-2017-9041",
    "CVE-2017-9042",
    "CVE-2017-9043",
    "CVE-2017-9044",
    "CVE-2017-9742",
    "CVE-2017-9743",
    "CVE-2017-9744",
    "CVE-2017-9745",
    "CVE-2017-9746",
    "CVE-2017-9747",
    "CVE-2017-9748",
    "CVE-2017-9749",
    "CVE-2017-9750",
    "CVE-2017-9751",
    "CVE-2017-9752",
    "CVE-2017-9753",
    "CVE-2017-9754",
    "CVE-2017-9755",
    "CVE-2017-9756",
    "CVE-2017-9954",
    "CVE-2017-9955",
    "CVE-2017-12449",
    "CVE-2017-12451",
    "CVE-2017-12452",
    "CVE-2017-12453",
    "CVE-2017-12454",
    "CVE-2017-12455",
    "CVE-2017-12456",
    "CVE-2017-12457",
    "CVE-2017-12458",
    "CVE-2017-12799",
    "CVE-2017-12967",
    "CVE-2017-13710",
    "CVE-2017-13716",
    "CVE-2017-13757",
    "CVE-2017-14128",
    "CVE-2017-14129",
    "CVE-2017-14130",
    "CVE-2017-14529",
    "CVE-2017-14729",
    "CVE-2017-14745",
    "CVE-2017-14930",
    "CVE-2017-14932",
    "CVE-2017-14933",
    "CVE-2017-14934",
    "CVE-2017-14938",
    "CVE-2017-14939",
    "CVE-2017-14940",
    "CVE-2017-14974",
    "CVE-2017-15020",
    "CVE-2017-15021",
    "CVE-2017-15022",
    "CVE-2017-15023",
    "CVE-2017-15024",
    "CVE-2017-15025",
    "CVE-2017-15225",
    "CVE-2017-15938",
    "CVE-2017-15939",
    "CVE-2017-15996",
    "CVE-2017-16826",
    "CVE-2017-16827",
    "CVE-2017-16828",
    "CVE-2017-16829",
    "CVE-2017-16830",
    "CVE-2017-16831",
    "CVE-2017-16832",
    "CVE-2017-17080",
    "CVE-2017-17121",
    "CVE-2017-17122",
    "CVE-2017-17123",
    "CVE-2017-17124",
    "CVE-2017-17125",
    "CVE-2017-17126",
    "CVE-2018-6323",
    "CVE-2018-6759",
    "CVE-2018-6872",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945",
    "CVE-2018-10373",
    "CVE-2018-10535",
    "CVE-2018-12641",
    "CVE-2018-12697",
    "CVE-2018-12698",
    "CVE-2018-12699",
    "CVE-2018-12700",
    "CVE-2018-12934",
    "CVE-2018-13033",
    "CVE-2018-17358",
    "CVE-2018-17360",
    "CVE-2018-17794",
    "CVE-2018-17985",
    "CVE-2018-18483",
    "CVE-2018-18484",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-18700",
    "CVE-2018-18701",
    "CVE-2018-19931",
    "CVE-2018-19932",
    "CVE-2018-20002",
    "CVE-2018-1000876",
    "CVE-2019-9070",
    "CVE-2019-9077",
    "CVE-2019-12972",
    "CVE-2019-14250",
    "CVE-2019-17450",
    "CVE-2019-17451",
    "CVE-2020-16590",
    "CVE-2020-16591",
    "CVE-2020-16592",
    "CVE-2020-16593",
    "CVE-2020-16598",
    "CVE-2020-16599",
    "CVE-2020-35448",
    "CVE-2020-35493",
    "CVE-2020-35494",
    "CVE-2020-35495",
    "CVE-2020-35496",
    "CVE-2020-35507",
    "CVE-2021-3487",
    "CVE-2021-20197",
    "CVE-2021-20294",
    "CVE-2021-32256",
    "CVE-2021-37322",
    "CVE-2021-45078",
    "CVE-2022-4285",
    "CVE-2022-27943",
    "CVE-2022-38533",
    "CVE-2022-44840",
    "CVE-2022-47007",
    "CVE-2022-47008",
    "CVE-2022-47010",
    "CVE-2022-47011",
    "CVE-2023-1579",
    "CVE-2023-1972",
    "CVE-2023-2222",
    "CVE-2023-25584",
    "CVE-2023-25585",
    "CVE-2023-25588"
  );

  script_name(english:"RHEL 6 : binutils (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12699");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils220");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-gcc-295");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-gcc-296");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-gcc-32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-gcc-34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-gcc-44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-toolset-11-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-toolset-12-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw-binutils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
