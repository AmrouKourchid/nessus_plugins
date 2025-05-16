#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-02-12.
# Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory kernel. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199272);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2018-7273",
    "CVE-2018-8043",
    "CVE-2018-10021",
    "CVE-2018-15594",
    "CVE-2018-16862",
    "CVE-2018-17977",
    "CVE-2019-2054",
    "CVE-2019-11184",
    "CVE-2019-12380",
    "CVE-2019-15217",
    "CVE-2019-15218",
    "CVE-2019-15219",
    "CVE-2019-15291",
    "CVE-2019-15807",
    "CVE-2019-16089",
    "CVE-2019-16229",
    "CVE-2019-16230",
    "CVE-2019-18806",
    "CVE-2019-19039",
    "CVE-2019-19054",
    "CVE-2019-19066",
    "CVE-2019-19076",
    "CVE-2019-19080",
    "CVE-2019-19081",
    "CVE-2019-19082",
    "CVE-2019-19083",
    "CVE-2019-19462",
    "CVE-2019-19816",
    "CVE-2019-19965",
    "CVE-2020-8694",
    "CVE-2020-10781",
    "CVE-2020-11494",
    "CVE-2020-11609",
    "CVE-2020-12768",
    "CVE-2020-12769",
    "CVE-2020-13844",
    "CVE-2020-14304",
    "CVE-2020-25639",
    "CVE-2021-20320",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-38199",
    "CVE-2021-45402",
    "CVE-2022-0264",
    "CVE-2022-2905",
    "CVE-2022-3344",
    "CVE-2022-3534",
    "CVE-2022-3542",
    "CVE-2022-3903",
    "CVE-2022-41850",
    "CVE-2023-0045",
    "CVE-2023-1076",
    "CVE-2023-3358",
    "CVE-2023-7042",
    "CVE-2023-31085",
    "CVE-2023-37454",
    "CVE-2023-47233",
    "CVE-2024-0607"
  );

  script_name(english:"RHEL 8 : kernel (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27416.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0145416c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47671.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03185644");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-41082.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04468850");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47674.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04b544a4");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27019.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0635317e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48901.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08a4b452");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47680.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b2d5721");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-49857.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11724cdc");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43888.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b000ee");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-36927.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1617b4d5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-36935.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c80836");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47693.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ba41bc2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46871.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c54c46d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-49861.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1caff3f0");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35793.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cb7797c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43887.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e1f6a55");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-0841.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e25af15");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48939.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fccac0c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44984.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2111a49b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47679.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?216e6402");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47678.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22d5f857");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35914.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24cfb407");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-2201.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2550e872");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47737.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?275ba44d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47505.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29af2776");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47682.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29e208f3");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-39293.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a182e87");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-26984.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2eab9984");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44981.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30dd9c29");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43892.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31ee0538");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42069.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3398a24f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46858.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33990bb3");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48936.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355bb246");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44970.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36ee3691");
  # https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-52651.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39ba099b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-38599.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39e0aba6");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35996.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ad50fb8");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-26946.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b240105");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35902.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bc8f7d9");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27036.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dffe967");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27071.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e57ec05");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-49851.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e5930a1");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48788.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ec2331e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47283.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40f921e0");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44974.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?411de45b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-41062.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44dbecf5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47460.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45aabac8");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27080.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?477f4d47");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47673.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?499ce03c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43911.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a0f6c31");
  # https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-52667.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c50533b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47686.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c652b5a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43908.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d36833a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-45025.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e761c6d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35975.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e9ae789");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47696.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f50618e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47700.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51d34d0a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47722.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57e45a8e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46800.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59b1bc0f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-46950.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59d302cb");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48879.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59e39d19");
  # https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-52897.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a5b424c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47688.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c96fcb2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43893.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d1ac41b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44952.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ded3ea3");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47685.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e914d44");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47743.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e925483");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48903.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ec915ee");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47676.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?625e50d1");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-4442.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6598fa0e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47701.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?659c45e7");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-26942.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65e0ba91");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46744.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b455c5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-52917.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?692b7466");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27077.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69c7824c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-3056.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dfe33c6");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27062.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e17f130");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-41064.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ea139f8");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43912.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ecb27c2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43884.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7050fb9c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47749.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70af501f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47692.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71cdda4f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46861.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7655d69a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47694.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?776c4cad");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47738.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77befe9e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44990.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79bd591b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47707.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79ef26af");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-49860.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a0624fe");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35935.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a1add31");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47666.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ca6176e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43879.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7da27f5b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47565.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?849d9ca8");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48924.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?854ce34b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47711.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86f27398");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44967.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87c3128f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48935.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88acc973");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48902.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?890411d4");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46679.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ae784b2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44973.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8db2a9eb");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46864.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e741d97");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47500.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b6843f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48944.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?936e173d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43889.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96b79c7d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44947.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96dfec3d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27402.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?985a991e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-26974.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bf06295");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47742.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d24e27f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47713.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d484e64");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48876.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e474e9b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27067.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f04b2f0");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44968.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f590703");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43891.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a088c495");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-26961.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a30fcf81");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48931.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a48b6a8a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47660.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4f5a337");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48780.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a51d6070");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47725.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5a38cc4");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44949.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6b08a0e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42232.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a86a92b7");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47709.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abacfb04");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27020.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae36bc20");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48940.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b155f605");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48733.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b22afcaa");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47684.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b40ffa99");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48942.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6dd162d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-26671.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b708a10d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47755.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7335b9d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46791.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba14ac55");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43861.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bafa85db");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43906.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb33501d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48938.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbafbc39");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47745.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0acfc9");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-0564.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd08d693");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47697.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be3209da");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42083.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf6fc885");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42289.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1d38f7d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48920.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c28d1f70");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47718.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2cfbc62");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48941.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6efdf3a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47705.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c732cfaa");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-35835.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c87e9747");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47746.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca7ae6d2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46859.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbe00f72");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48789.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccfc5315");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48909.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d05687f5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48900.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0fa1ff6");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47702.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1745da3");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47672.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2971f1b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47723.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8317c82");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47698.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8791dbc");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44985.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddf2169e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27039.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df023bb4");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48868.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfeba5da");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-36014.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e011344f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47734.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e08bfa94");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48910.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0c8cfa2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47503.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0e80f71");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44958.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3aaff81");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47739.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e44e0d7a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48906.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5827ba7");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-46737.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8162413");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47675.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea2e6f13");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-49855.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaa1b2bd");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-36930.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb021389");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43910.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb11809f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48781.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec0de7fe");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42070.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec66bee4");
  # https://security.access.redhat.com/data/csaf/v2/vex/2022/cve-2022-48923.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed72e0a3");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47728.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edfe969d");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44977.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee8c457e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27018.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0c50627");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27411.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0eb006a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47741.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f112e750");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-27007.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1884eb6");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-47463.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2169cd1");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-47708.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6427dfc");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44954.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa28f22b");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-43874.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa9d73e6");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-44972.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fefeb150");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
