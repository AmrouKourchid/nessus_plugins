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
# extracted from Red Hat Security Advisory mozilla. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196863);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2017-7781",
    "CVE-2018-5146",
    "CVE-2020-6823",
    "CVE-2020-6824",
    "CVE-2020-15685",
    "CVE-2020-16044",
    "CVE-2020-26970",
    "CVE-2020-26971",
    "CVE-2020-26973",
    "CVE-2020-26974",
    "CVE-2020-26976",
    "CVE-2020-26978",
    "CVE-2020-35111",
    "CVE-2020-35113",
    "CVE-2021-4127",
    "CVE-2021-4129",
    "CVE-2021-4140",
    "CVE-2021-23953",
    "CVE-2021-23954",
    "CVE-2021-23960",
    "CVE-2021-23961",
    "CVE-2021-23964",
    "CVE-2021-23968",
    "CVE-2021-23969",
    "CVE-2021-23973",
    "CVE-2021-23978",
    "CVE-2021-23981",
    "CVE-2021-23982",
    "CVE-2021-23984",
    "CVE-2021-23987",
    "CVE-2021-23991",
    "CVE-2021-23992",
    "CVE-2021-23993",
    "CVE-2021-23994",
    "CVE-2021-23995",
    "CVE-2021-23998",
    "CVE-2021-23999",
    "CVE-2021-24002",
    "CVE-2021-29945",
    "CVE-2021-29946",
    "CVE-2021-29948",
    "CVE-2021-29949",
    "CVE-2021-29950",
    "CVE-2021-29956",
    "CVE-2021-29957",
    "CVE-2021-29964",
    "CVE-2021-29967",
    "CVE-2021-29969",
    "CVE-2021-29970",
    "CVE-2021-29976",
    "CVE-2021-29980",
    "CVE-2021-29984",
    "CVE-2021-29985",
    "CVE-2021-29986",
    "CVE-2021-29988",
    "CVE-2021-29989",
    "CVE-2021-29991",
    "CVE-2021-38493",
    "CVE-2021-38496",
    "CVE-2021-38497",
    "CVE-2021-38498",
    "CVE-2021-38500",
    "CVE-2021-38501",
    "CVE-2021-38502",
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38505",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-38510",
    "CVE-2021-43528",
    "CVE-2021-43534",
    "CVE-2021-43535",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546",
    "CVE-2022-1097",
    "CVE-2022-1196",
    "CVE-2022-1197",
    "CVE-2022-1520",
    "CVE-2022-1529",
    "CVE-2022-1802",
    "CVE-2022-1834",
    "CVE-2022-2200",
    "CVE-2022-2226",
    "CVE-2022-2505",
    "CVE-2022-3032",
    "CVE-2022-3033",
    "CVE-2022-3034",
    "CVE-2022-3266",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22745",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764",
    "CVE-2022-24713",
    "CVE-2022-26381",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26386",
    "CVE-2022-26387",
    "CVE-2022-26486",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28289",
    "CVE-2022-29909",
    "CVE-2022-29911",
    "CVE-2022-29912",
    "CVE-2022-29913",
    "CVE-2022-29914",
    "CVE-2022-29916",
    "CVE-2022-29917",
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31744",
    "CVE-2022-31747",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484",
    "CVE-2022-36059",
    "CVE-2022-36318",
    "CVE-2022-36319",
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38476",
    "CVE-2022-38477",
    "CVE-2022-38478",
    "CVE-2022-39236",
    "CVE-2022-39249",
    "CVE-2022-39250",
    "CVE-2022-39251",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40962",
    "CVE-2022-42927",
    "CVE-2022-42928",
    "CVE-2022-42929",
    "CVE-2022-42932",
    "CVE-2022-45403",
    "CVE-2022-45404",
    "CVE-2022-45405",
    "CVE-2022-45406",
    "CVE-2022-45408",
    "CVE-2022-45409",
    "CVE-2022-45410",
    "CVE-2022-45411",
    "CVE-2022-45412",
    "CVE-2022-45414",
    "CVE-2022-45416",
    "CVE-2022-45418",
    "CVE-2022-45420",
    "CVE-2022-45421",
    "CVE-2022-46871",
    "CVE-2022-46872",
    "CVE-2022-46874",
    "CVE-2022-46877",
    "CVE-2022-46878",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882",
    "CVE-2023-0430",
    "CVE-2023-0616",
    "CVE-2023-1945",
    "CVE-2023-1999",
    "CVE-2023-4045",
    "CVE-2023-4046",
    "CVE-2023-4047",
    "CVE-2023-4048",
    "CVE-2023-4049",
    "CVE-2023-4050",
    "CVE-2023-4051",
    "CVE-2023-4053",
    "CVE-2023-4055",
    "CVE-2023-4056",
    "CVE-2023-4057",
    "CVE-2023-4573",
    "CVE-2023-4574",
    "CVE-2023-4575",
    "CVE-2023-4577",
    "CVE-2023-4578",
    "CVE-2023-4580",
    "CVE-2023-4581",
    "CVE-2023-4583",
    "CVE-2023-4584",
    "CVE-2023-4585",
    "CVE-2023-5169",
    "CVE-2023-5171",
    "CVE-2023-5176",
    "CVE-2023-5721",
    "CVE-2023-5724",
    "CVE-2023-5725",
    "CVE-2023-5728",
    "CVE-2023-5730",
    "CVE-2023-5732",
    "CVE-2023-6204",
    "CVE-2023-6205",
    "CVE-2023-6206",
    "CVE-2023-6207",
    "CVE-2023-6208",
    "CVE-2023-6209",
    "CVE-2023-6212",
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-6865",
    "CVE-2023-6867",
    "CVE-2023-23598",
    "CVE-2023-23599",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23605",
    "CVE-2023-25728",
    "CVE-2023-25729",
    "CVE-2023-25730",
    "CVE-2023-25732",
    "CVE-2023-25735",
    "CVE-2023-25737",
    "CVE-2023-25739",
    "CVE-2023-25742",
    "CVE-2023-25743",
    "CVE-2023-25744",
    "CVE-2023-25746",
    "CVE-2023-25751",
    "CVE-2023-25752",
    "CVE-2023-28162",
    "CVE-2023-28164",
    "CVE-2023-28176",
    "CVE-2023-28427",
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29539",
    "CVE-2023-29541",
    "CVE-2023-29548",
    "CVE-2023-29550",
    "CVE-2023-32205",
    "CVE-2023-32206",
    "CVE-2023-32207",
    "CVE-2023-32211",
    "CVE-2023-32212",
    "CVE-2023-32213",
    "CVE-2023-32215",
    "CVE-2023-34414",
    "CVE-2023-34416",
    "CVE-2023-37201",
    "CVE-2023-37202",
    "CVE-2023-37207",
    "CVE-2023-37208",
    "CVE-2023-37211",
    "CVE-2023-50761",
    "CVE-2023-50762",
    "CVE-2024-0741",
    "CVE-2024-0742",
    "CVE-2024-0743",
    "CVE-2024-0746",
    "CVE-2024-0747",
    "CVE-2024-0749",
    "CVE-2024-0750",
    "CVE-2024-0751",
    "CVE-2024-0753",
    "CVE-2024-0755",
    "CVE-2024-1546",
    "CVE-2024-1547",
    "CVE-2024-1548",
    "CVE-2024-1549",
    "CVE-2024-1550",
    "CVE-2024-1551",
    "CVE-2024-1552",
    "CVE-2024-1553",
    "CVE-2024-1936",
    "CVE-2024-2607",
    "CVE-2024-2608",
    "CVE-2024-2609",
    "CVE-2024-2610",
    "CVE-2024-2611",
    "CVE-2024-2612",
    "CVE-2024-2614",
    "CVE-2024-2616",
    "CVE-2024-3302",
    "CVE-2024-3852",
    "CVE-2024-3854",
    "CVE-2024-3857",
    "CVE-2024-3859",
    "CVE-2024-3861",
    "CVE-2024-3864",
    "CVE-2024-29944"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/21");

  script_name(english:"RHEL 6 : mozilla (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26970");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4140");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
