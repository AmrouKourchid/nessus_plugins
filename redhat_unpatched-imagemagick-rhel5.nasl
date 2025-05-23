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
# extracted from Red Hat Security Advisory imagemagick. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195362);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-3714",
    "CVE-2016-3716",
    "CVE-2016-3717",
    "CVE-2016-3718",
    "CVE-2016-5240",
    "CVE-2016-6823",
    "CVE-2016-7515",
    "CVE-2016-7517",
    "CVE-2016-7519",
    "CVE-2016-7523",
    "CVE-2016-7528",
    "CVE-2016-7529",
    "CVE-2016-7530",
    "CVE-2016-7531",
    "CVE-2016-7537",
    "CVE-2016-8862",
    "CVE-2016-8866",
    "CVE-2016-9556",
    "CVE-2016-9559",
    "CVE-2016-10046",
    "CVE-2016-10047",
    "CVE-2016-10048",
    "CVE-2016-10049",
    "CVE-2016-10050",
    "CVE-2016-10051",
    "CVE-2016-10052",
    "CVE-2016-10053",
    "CVE-2016-10054",
    "CVE-2016-10055",
    "CVE-2016-10057",
    "CVE-2016-10058",
    "CVE-2016-10059",
    "CVE-2016-10060",
    "CVE-2016-10061",
    "CVE-2016-10062",
    "CVE-2016-10063",
    "CVE-2016-10064",
    "CVE-2016-10065",
    "CVE-2016-10066",
    "CVE-2016-10067",
    "CVE-2016-10068",
    "CVE-2016-10069",
    "CVE-2016-10070",
    "CVE-2016-10071",
    "CVE-2016-10144",
    "CVE-2016-10145",
    "CVE-2016-10146",
    "CVE-2016-10252",
    "CVE-2017-5506",
    "CVE-2017-5507",
    "CVE-2017-5508",
    "CVE-2017-5509",
    "CVE-2017-5510",
    "CVE-2017-5511",
    "CVE-2017-6335",
    "CVE-2017-6497",
    "CVE-2017-6498",
    "CVE-2017-6499",
    "CVE-2017-6500",
    "CVE-2017-6501",
    "CVE-2017-6502",
    "CVE-2017-7275",
    "CVE-2017-7606",
    "CVE-2017-7619",
    "CVE-2017-7941",
    "CVE-2017-7942",
    "CVE-2017-7943",
    "CVE-2017-8343",
    "CVE-2017-8344",
    "CVE-2017-8345",
    "CVE-2017-8346",
    "CVE-2017-8347",
    "CVE-2017-8348",
    "CVE-2017-8349",
    "CVE-2017-8350",
    "CVE-2017-8351",
    "CVE-2017-8352",
    "CVE-2017-8353",
    "CVE-2017-8354",
    "CVE-2017-8355",
    "CVE-2017-8356",
    "CVE-2017-8357",
    "CVE-2017-8765",
    "CVE-2017-8830",
    "CVE-2017-9098",
    "CVE-2017-9141",
    "CVE-2017-9142",
    "CVE-2017-9143",
    "CVE-2017-9144",
    "CVE-2017-9261",
    "CVE-2017-9262",
    "CVE-2017-9405",
    "CVE-2017-9407",
    "CVE-2017-9409",
    "CVE-2017-9439",
    "CVE-2017-9440",
    "CVE-2017-9499",
    "CVE-2017-9500",
    "CVE-2017-9501",
    "CVE-2017-10928",
    "CVE-2017-10995",
    "CVE-2017-11141",
    "CVE-2017-11166",
    "CVE-2017-11170",
    "CVE-2017-11188",
    "CVE-2017-11310",
    "CVE-2017-11352",
    "CVE-2017-11360",
    "CVE-2017-11447",
    "CVE-2017-11448",
    "CVE-2017-11449",
    "CVE-2017-11450",
    "CVE-2017-11505",
    "CVE-2017-11524",
    "CVE-2017-11525",
    "CVE-2017-11526",
    "CVE-2017-11527",
    "CVE-2017-11528",
    "CVE-2017-11529",
    "CVE-2017-11530",
    "CVE-2017-11531",
    "CVE-2017-11532",
    "CVE-2017-11533",
    "CVE-2017-11534",
    "CVE-2017-11535",
    "CVE-2017-11536",
    "CVE-2017-11537",
    "CVE-2017-11538",
    "CVE-2017-11539",
    "CVE-2017-11540",
    "CVE-2017-11639",
    "CVE-2017-11640",
    "CVE-2017-11644",
    "CVE-2017-11724",
    "CVE-2017-11750",
    "CVE-2017-11751",
    "CVE-2017-11752",
    "CVE-2017-11753",
    "CVE-2017-11754",
    "CVE-2017-11755",
    "CVE-2017-12140",
    "CVE-2017-12418",
    "CVE-2017-12428",
    "CVE-2017-12429",
    "CVE-2017-12432",
    "CVE-2017-12433",
    "CVE-2017-12434",
    "CVE-2017-12435",
    "CVE-2017-12587",
    "CVE-2017-12640",
    "CVE-2017-12641",
    "CVE-2017-12642",
    "CVE-2017-12643",
    "CVE-2017-12644",
    "CVE-2017-12654",
    "CVE-2017-12662",
    "CVE-2017-12663",
    "CVE-2017-12664",
    "CVE-2017-12665",
    "CVE-2017-12666",
    "CVE-2017-12693",
    "CVE-2017-12805",
    "CVE-2017-12875",
    "CVE-2017-12876",
    "CVE-2017-12877",
    "CVE-2017-12983",
    "CVE-2017-13058",
    "CVE-2017-13059",
    "CVE-2017-13060",
    "CVE-2017-13061",
    "CVE-2017-13062",
    "CVE-2017-13131",
    "CVE-2017-13132",
    "CVE-2017-13133",
    "CVE-2017-13134",
    "CVE-2017-13139",
    "CVE-2017-13140",
    "CVE-2017-13141",
    "CVE-2017-13142",
    "CVE-2017-13143",
    "CVE-2017-13144",
    "CVE-2017-13145",
    "CVE-2017-13146",
    "CVE-2017-13658",
    "CVE-2017-13758",
    "CVE-2017-13768",
    "CVE-2017-13769",
    "CVE-2017-14060",
    "CVE-2017-14172",
    "CVE-2017-14173",
    "CVE-2017-14174",
    "CVE-2017-14175",
    "CVE-2017-14224",
    "CVE-2017-14248",
    "CVE-2017-14249",
    "CVE-2017-14324",
    "CVE-2017-14325",
    "CVE-2017-14326",
    "CVE-2017-14341",
    "CVE-2017-14342",
    "CVE-2017-14343",
    "CVE-2017-14400",
    "CVE-2017-14528",
    "CVE-2017-14531",
    "CVE-2017-14532",
    "CVE-2017-14533",
    "CVE-2017-14607",
    "CVE-2017-14624",
    "CVE-2017-14682",
    "CVE-2017-14739",
    "CVE-2017-14741",
    "CVE-2017-14989",
    "CVE-2017-15015",
    "CVE-2017-15016",
    "CVE-2017-15017",
    "CVE-2017-15032",
    "CVE-2017-15033",
    "CVE-2017-15217",
    "CVE-2017-15218",
    "CVE-2017-15277",
    "CVE-2017-15281",
    "CVE-2017-16546",
    "CVE-2017-17499",
    "CVE-2017-17504",
    "CVE-2017-17680",
    "CVE-2017-17681",
    "CVE-2017-17682",
    "CVE-2017-17879",
    "CVE-2017-17880",
    "CVE-2017-17881",
    "CVE-2017-17882",
    "CVE-2017-17884",
    "CVE-2017-17885",
    "CVE-2017-17886",
    "CVE-2017-17887",
    "CVE-2017-17914",
    "CVE-2017-17934",
    "CVE-2017-18008",
    "CVE-2017-18022",
    "CVE-2017-18027",
    "CVE-2017-18028",
    "CVE-2017-18029",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18271",
    "CVE-2017-18273",
    "CVE-2017-1000445",
    "CVE-2017-1000476",
    "CVE-2018-5246",
    "CVE-2018-5247",
    "CVE-2018-5357",
    "CVE-2018-6405",
    "CVE-2018-6876",
    "CVE-2018-6930",
    "CVE-2018-7443",
    "CVE-2018-7470",
    "CVE-2018-10177",
    "CVE-2018-10804",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-13153",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-15607",
    "CVE-2018-16323",
    "CVE-2018-16328",
    "CVE-2018-16640",
    "CVE-2018-16642",
    "CVE-2018-16643",
    "CVE-2018-16644",
    "CVE-2018-16645",
    "CVE-2018-16749",
    "CVE-2018-16750",
    "CVE-2018-17966",
    "CVE-2018-18016",
    "CVE-2018-18024",
    "CVE-2018-18544",
    "CVE-2018-20467",
    "CVE-2019-7175",
    "CVE-2019-7397",
    "CVE-2019-7398",
    "CVE-2019-10131",
    "CVE-2019-10650",
    "CVE-2019-10714",
    "CVE-2019-11470",
    "CVE-2019-11472",
    "CVE-2019-11597",
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12977",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13295",
    "CVE-2019-13296",
    "CVE-2019-13297",
    "CVE-2019-13298",
    "CVE-2019-13299",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13303",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-15141",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16712",
    "CVE-2019-16713",
    "CVE-2019-17540",
    "CVE-2019-17541",
    "CVE-2019-18853",
    "CVE-2019-19948",
    "CVE-2019-19949",
    "CVE-2019-19952",
    "CVE-2020-13902",
    "CVE-2020-19667",
    "CVE-2020-25663",
    "CVE-2020-25664",
    "CVE-2020-25665",
    "CVE-2020-25666",
    "CVE-2020-25667",
    "CVE-2020-25674",
    "CVE-2020-25675",
    "CVE-2020-25676",
    "CVE-2020-27560",
    "CVE-2020-27750",
    "CVE-2020-27751",
    "CVE-2020-27752",
    "CVE-2020-27753",
    "CVE-2020-27754",
    "CVE-2020-27755",
    "CVE-2020-27756",
    "CVE-2020-27757",
    "CVE-2020-27758",
    "CVE-2020-27759",
    "CVE-2020-27760",
    "CVE-2020-27761",
    "CVE-2020-27762",
    "CVE-2020-27763",
    "CVE-2020-27764",
    "CVE-2020-27765",
    "CVE-2020-27766",
    "CVE-2020-27767",
    "CVE-2020-27768",
    "CVE-2020-27769",
    "CVE-2020-27770",
    "CVE-2020-27771",
    "CVE-2020-27772",
    "CVE-2020-27773",
    "CVE-2020-27774",
    "CVE-2020-27775",
    "CVE-2020-27776",
    "CVE-2020-29599",
    "CVE-2021-3596",
    "CVE-2021-20176"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"RHEL 5 : imagemagick (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3714");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19952");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
