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
# extracted from Red Hat Security Advisory kernel. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195722);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2016-2069",
    "CVE-2016-2184",
    "CVE-2016-2185",
    "CVE-2016-2186",
    "CVE-2016-2543",
    "CVE-2016-2544",
    "CVE-2016-2545",
    "CVE-2016-2546",
    "CVE-2016-2547",
    "CVE-2016-2550",
    "CVE-2016-2847",
    "CVE-2016-3134",
    "CVE-2016-3138",
    "CVE-2016-3139",
    "CVE-2016-3140",
    "CVE-2016-3156",
    "CVE-2016-3157",
    "CVE-2016-3672",
    "CVE-2016-3951",
    "CVE-2016-4482",
    "CVE-2016-4486",
    "CVE-2016-4569",
    "CVE-2016-4578",
    "CVE-2016-4580",
    "CVE-2016-4913",
    "CVE-2016-5244",
    "CVE-2016-5829",
    "CVE-2016-6130",
    "CVE-2016-6480",
    "CVE-2016-7042",
    "CVE-2016-7097",
    "CVE-2016-7425",
    "CVE-2016-7915",
    "CVE-2016-8405",
    "CVE-2016-9685",
    "CVE-2016-9794",
    "CVE-2016-10741",
    "CVE-2017-0627",
    "CVE-2017-0630",
    "CVE-2017-0861",
    "CVE-2017-5549",
    "CVE-2017-5551",
    "CVE-2017-5986",
    "CVE-2017-6348",
    "CVE-2017-7542",
    "CVE-2017-7616",
    "CVE-2017-7889",
    "CVE-2017-8890",
    "CVE-2017-8924",
    "CVE-2017-8925",
    "CVE-2017-9074",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077",
    "CVE-2017-11473",
    "CVE-2017-12190",
    "CVE-2017-12762",
    "CVE-2017-13166",
    "CVE-2017-13167",
    "CVE-2017-13693",
    "CVE-2017-13694",
    "CVE-2017-13695",
    "CVE-2017-14051",
    "CVE-2017-14140",
    "CVE-2017-15102",
    "CVE-2017-15274",
    "CVE-2017-16532",
    "CVE-2017-16534",
    "CVE-2017-16536",
    "CVE-2017-16537",
    "CVE-2017-16644",
    "CVE-2017-16646",
    "CVE-2017-16647",
    "CVE-2017-16649",
    "CVE-2017-16650",
    "CVE-2017-17558",
    "CVE-2017-17807",
    "CVE-2017-18017",
    "CVE-2017-18079",
    "CVE-2017-18360",
    "CVE-2017-18550",
    "CVE-2017-18551",
    "CVE-2017-1000370",
    "CVE-2017-1000371",
    "CVE-2017-1000380",
    "CVE-2018-1092",
    "CVE-2018-1120",
    "CVE-2018-1130",
    "CVE-2018-3665",
    "CVE-2018-5333",
    "CVE-2018-5390",
    "CVE-2018-5391",
    "CVE-2018-5803",
    "CVE-2018-6927",
    "CVE-2018-7191",
    "CVE-2018-7492",
    "CVE-2018-7757",
    "CVE-2018-9516",
    "CVE-2018-9568",
    "CVE-2018-10675",
    "CVE-2018-10840",
    "CVE-2018-10902",
    "CVE-2018-10940",
    "CVE-2018-12928",
    "CVE-2018-13405",
    "CVE-2018-14617",
    "CVE-2018-14734",
    "CVE-2018-15572",
    "CVE-2018-16658",
    "CVE-2018-16885",
    "CVE-2018-17977",
    "CVE-2018-18710",
    "CVE-2018-20169",
    "CVE-2018-1000004",
    "CVE-2019-2054",
    "CVE-2019-3459",
    "CVE-2019-3837",
    "CVE-2019-3846",
    "CVE-2019-3896",
    "CVE-2019-5108",
    "CVE-2019-9270",
    "CVE-2019-9458",
    "CVE-2019-10126",
    "CVE-2019-11478",
    "CVE-2019-11479",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11833",
    "CVE-2019-11884",
    "CVE-2019-12381",
    "CVE-2019-12819",
    "CVE-2019-12881",
    "CVE-2019-13631",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-14284",
    "CVE-2019-14821",
    "CVE-2019-14898",
    "CVE-2019-15118",
    "CVE-2019-15212",
    "CVE-2019-15214",
    "CVE-2019-15215",
    "CVE-2019-15219",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15222",
    "CVE-2019-15223",
    "CVE-2019-15666",
    "CVE-2019-15807",
    "CVE-2019-15916",
    "CVE-2019-15921",
    "CVE-2019-15922",
    "CVE-2019-15923",
    "CVE-2019-16230",
    "CVE-2019-16234",
    "CVE-2019-16413",
    "CVE-2019-16714",
    "CVE-2019-16994",
    "CVE-2019-17133",
    "CVE-2019-18282",
    "CVE-2019-18660",
    "CVE-2019-18675",
    "CVE-2019-18680",
    "CVE-2019-18806",
    "CVE-2019-18885",
    "CVE-2019-19047",
    "CVE-2019-19054",
    "CVE-2019-19055",
    "CVE-2019-19056",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19066",
    "CVE-2019-19077",
    "CVE-2019-19338",
    "CVE-2019-19377",
    "CVE-2019-19532",
    "CVE-2019-19533",
    "CVE-2019-19537",
    "CVE-2019-19770",
    "CVE-2019-19922",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20095",
    "CVE-2019-20811",
    "CVE-2019-20812",
    "CVE-2019-20934",
    "CVE-2020-0305",
    "CVE-2020-0431",
    "CVE-2020-0444",
    "CVE-2020-1749",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-8832",
    "CVE-2020-9383",
    "CVE-2020-10135",
    "CVE-2020-10720",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-10773",
    "CVE-2020-10781",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-12114",
    "CVE-2020-12464",
    "CVE-2020-12652",
    "CVE-2020-12655",
    "CVE-2020-12656",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-14351",
    "CVE-2020-14353",
    "CVE-2020-14390",
    "CVE-2020-14416",
    "CVE-2020-15393",
    "CVE-2020-16166",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-25211",
    "CVE-2020-25212",
    "CVE-2020-25285",
    "CVE-2020-25641",
    "CVE-2020-25705",
    "CVE-2020-26139",
    "CVE-2020-26140",
    "CVE-2020-26141",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26146",
    "CVE-2020-26147",
    "CVE-2020-27673",
    "CVE-2020-27675",
    "CVE-2020-27777",
    "CVE-2020-27784",
    "CVE-2020-27815",
    "CVE-2020-28097",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-35501",
    "CVE-2020-36158",
    "CVE-2021-3348",
    "CVE-2021-3411",
    "CVE-2021-3715",
    "CVE-2021-3732",
    "CVE-2021-3772",
    "CVE-2021-3894",
    "CVE-2021-4159",
    "CVE-2021-20177",
    "CVE-2021-20219",
    "CVE-2021-20239",
    "CVE-2021-20261",
    "CVE-2021-20322",
    "CVE-2021-31916",
    "CVE-2021-38209",
    "CVE-2022-2938"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"RHEL 5 : kernel (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acpica-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-alt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
