#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2575-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(203003);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2023-38417", "CVE-2023-47210");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2575-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel-firmware (SUSE-SU-2024:2575-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:2575-1 advisory.

    - CVE-2023-38417: Fixed improper input validation for some Intel(R) PROSet/Wireless WiFi software for
    linux before version 23.20 (bsc#1225600)
    - CVE-2023-47210: Fixed improper input validation for some Intel(R) PROSet/Wireless WiFi software before
    version 23.20 (bsc#1225601)

    - Update to version 20240712 (git commit ed874ed83cac):
      * amdgpu: update DMCUB to v0.0.225.0 for Various AMDGPU Asics
      * qcom: add gpu firmwares for x1e80100 chipset (bsc#1219458)
      * linux-firmware: add firmware for qat_402xx devices
      * amdgpu: update raven firmware
      * amdgpu: update SMU 13.0.10 firmware
      * amdgpu: update SDMA 6.0.3 firmware
      * amdgpu: update PSP 13.0.10 firmware
      * amdgpu: update GC 11.0.3 firmware
      * amdgpu: update vega20 firmware
      * amdgpu: update PSP 13.0.5 firmware
      * amdgpu: update PSP 13.0.8 firmware
      * amdgpu: update vega12 firmware
      * amdgpu: update vega10 firmware
      * amdgpu: update VCN 4.0.0 firmware
      * amdgpu: update SDMA 6.0.0 firmware
      * amdgpu: update PSP 13.0.0 firmware
      * amdgpu: update GC 11.0.0 firmware
      * amdgpu: update picasso firmware
      * amdgpu: update beige goby firmware
      * amdgpu: update vangogh firmware
      * amdgpu: update dimgrey cavefish firmware
      * amdgpu: update navy flounder firmware
      * amdgpu: update PSP 13.0.11 firmware
      * amdgpu: update GC 11.0.4 firmware
      * amdgpu: update green sardine firmware
      * amdgpu: update VCN 4.0.2 firmware
      * amdgpu: update SDMA 6.0.1 firmware
      * amdgpu: update PSP 13.0.4 firmware
      * amdgpu: update GC 11.0.1 firmware
      * amdgpu: update sienna cichlid firmware
      * amdgpu: update VPE 6.1.1 firmware
      * amdgpu: update VCN 4.0.6 firmware
      * amdgpu: update SDMA 6.1.1 firmware
      * amdgpu: update PSP 14.0.1 firmware
      * amdgpu: update GC 11.5.1 firmware
      * amdgpu: update VCN 4.0.5 firmware
      * amdgpu: update SDMA 6.1.0 firmware
      * amdgpu: update PSP 14.0.0 firmware
      * amdgpu: update GC 11.5.0 firmware
      * amdgpu: update navi14 firmware
      * amdgpu: update renoir firmware
      * amdgpu: update navi12 firmware
      * amdgpu: update PSP 13.0.6 firmware
      * amdgpu: update GC 9.4.3 firmware
      * amdgpu: update yellow carp firmware
      * amdgpu: update VCN 4.0.4 firmware
      * amdgpu: update SMU 13.0.7 firmware
      * amdgpu: update SDMA 6.0.2 firmware
      * amdgpu: update PSP 13.0.7 firmware
      * amdgpu: update GC 11.0.2 firmware
      * amdgpu: update navi10 firmware
      * amdgpu: update raven2 firmware
      * amdgpu: update aldebaran firmware
      * linux-firmware: Update AMD cpu microcode
      * linux-firmware: Add ISH firmware file for Intel Lunar Lake platform
      * amdgpu: update DMCUB to v0.0.224.0 for Various AMDGPU Asics
      * cirrus: cs35l41: Update various firmware for ASUS laptops using CS35L41
      * amdgpu: Update ISP FW for isp v4.1.1

    - Update to version 20240622 (git commit 7d931f8afa51):
      * linux-firmware: mediatek: Update MT8173 VPU firmware to v1.2.0
      * qcom: Add AIC100 firmware files

    - Update to version 20240618 (git commit 7d931f8afa51):
      * amlogic: Update bluetooth firmware binary
      * linux-firmware: Update firmware file for Intel BlazarU core
      * linux-firmware: Update firmware file for Intel Bluetooth Magnetor core
      * linux-firmware: Update firmware file for Intel Bluetooth Solar core
      * linux-firmware: Update firmware file for Intel Bluetooth Pulsar core
      * rtl_bt: Update RTL8822C BT UART firmware to 0xB5D6_6DCB
      * rtl_bt: Update RTL8822C BT USB firmware to 0xAED6_6DCB
      * amdgpu: update DMCUB to v0.0.222.0 for DCN314
      * iwlwifi: add ty/So/Ma firmwares for core88-87 release
      * iwlwifi: update cc/Qu/QuZ firmwares for core88-87 release
      * linux-firmware: add new cc33xx firmware for cc33xx chips
      * cirrus: cs35l56: Update firmware for Cirrus CS35L56 for ASUS UM5606 laptop
      * cirrus: cs35l56: Update firmware for Cirrus CS35L56 for various ASUS laptops
      * linux-firmware: Add firmware for Lenovo Thinkbooks
      * amdgpu: update yellow carp firmware
      * amdgpu: update VCN 4.0.4 firmware
      * amdgpu: update SDMA 6.0.2 firmware
      * amdgpu: update PSP 13.0.7 firmware
      * amdgpu: update GC 11.0.2 firmware
      * amdgpu: update navi10 firmware
      * amdgpu: update raven2 firmware
      * amdgpu: update raven firmware
      * amdgpu: update SMU 13.0.10 firmware
      * amdgpu: update SDMA 6.0.3 firmware
      * amdgpu: update PSP 13.0.10 firmware
      * amdgpu: update GC 11.0.3 firmware
      * amdgpu: update VCN 3.1.2 firmware
      * amdgpu: update PSP 13.0.5 firmware
      * amdgpu: update psp 13.0.8 firmware
      * amdgpu: update vega20 firmware
      * amdgpu: update vega12 firmware
      * amdgpu: update vega10 firmware
      * amdgpu: update VCN 4.0.0 firmware
      * amdgpu: update smu 13.0.0 firmware
      * amdgpu: update SDMA 6.0.0 firmware
      * amdgpu: update PSP 13.0.0 firmware
      * amdgpu: update GC 11.0.0 firmware
      * amdgpu: update picasso firmware
      * amdgpu: update beige goby firmware
      * amdgpu: update vangogh firmware
      * amdgpu: update dimgrey cavefish firmware
      * amdgpu: update green sardine firmware
      * amdgpu: update navy flounder firmware
      * amdgpu: update PSP 13.0.11 firmware
      * amdgpu: update GC 11.0.4 firmware
      * amdgpu: update VCN 4.0.2 firmware
      * amdgpu: update SDMA 6.0.1 firmware
      * amdgpu: update PSP 13.0.4 firmware
      * amdgpu: update GC 11.0.1 firmware
      * amdgpu: update sienna cichlid firmware
      * amdgpu: update VCN 4.0.5 firmware
      * amdgpu: update PSP 14.0.0 firmware
      * amdgpu: update GC 11.5.0 firmware
      * amdgpu: update navi14 firmware
      * amdgpu: update SMU 13.0.6 firmware
      * amdgpu: update PSP 13.0.6 firmware
      * amdgpu: update GC 9.4.3 firmware
      * amdgpu: update renoir firmware
      * amdgpu: update navi12 firmware
      * amdgpu: update aldebaran firmware
      * amdgpu: add support for PSP 14.0.1
      * amdgpu: add support for VPE 6.1.1
      * amdgpu: add support for VCN 4.0.6
      * amdgpu: add support for SDMA 6.1.1
      * amdgpu: add support for GC 11.5.1
      * amdgpu: Add support for DCN 3.5.1
      * QCA: Update Bluetooth QCA2066 firmware to 2.1.0-00639
      * cnm: update chips&media wave521c firmware.
      * linux-firmware: Add ordinary firmware for RTL8821AU device

    - Update to version 20240519 (git commit aae8224390e2):
      * amdgpu: add new ISP 4.1.1 firmware

    - Update to version 20240510 (git commit 7c2303328d8e):
      * linux-firmware: Amphion: Update vpu firmware
      * linux-firmware: Update firmware file for Intel BlazarU core
      * linux-firmware: Update firmware file for Intel Bluetooth Magnetor core
      * linux-firmware: Update firmware file for Intel Bluetooth Solar core
      * linux-firmware: Update firmware file for Intel Bluetooth Solar core
      * i915: Add BMG DMC v2.06
      * linux-firmware: Add CS35L41 HDA Firmware for Asus HN7306
      * linux-firmware: Update firmware tuning for HP Consumer Laptop
      * amdgpu: DMCUB updates for various AMDGPU ASICs
      * rtl_bt: Update RTL8822C BT UART firmware to 0x0FD6_407B
      * rtl_bt: Update RTL8822C BT USB firmware to 0x0ED6_407B
      * cirrus: cs35l56: Add firmware for Cirrus CS35L56 for various ASUS laptops
      * linux-firmware: Add firmware and tuning for Lenovo Y770S

    - Update to version 20240426 (git commit 2398d264f953):
      * amdgpu: DMCUB updates for various AMDGPU ASICs
      * linux-firmware: Add firmware for Cirrus CS35L56 for various HP laptops
      * i915: Update Xe2LPD DMC to v2.20
      * linux-firmware: Remove Calibration Firmware and Tuning for CS35L41
      * linux-firmware: Add firmware for Lenovo Thinkbook 13X
      * ASoC: tas2781: Add dsp firmware for Thinkpad ICE-1 laptop
      * amdgpu: add DMCUB 3.5 firmware
      * amdgpu: add VPE 6.1.0 firmware
      * amdgpu: add VCN 4.0.5 firmware
      * amdgpu: add UMSCH 4.0.0 firmware
      * amdgpu: add SDMA 6.1.0 firmware
      * amdgpu: add PSP 14.0.0  firmware
      * amdgpu: add GC 11.5.0 firmware
      * amdgpu: update license date

    - Update to version 20240419 (git commit 7eab37522984):
      * Montage: update firmware for Mont-TSSE
      * linux-firmware: Add tuning parameter configs for CS35L41 Firmware
      * linux-firmware: Fix firmware names for Laptop SSID 104316a3
      * linux-firmware: Add CS35L41 HDA Firmware for Lenovo Legion Slim 7 16ARHA7
      * linux-firmware: update firmware for mediatek bluetooth chip (MT7922)
      * linux-firmware: update firmware for MT7922 WiFi device
      * iwlwifi: add gl FW for core87-44 release
      * iwlwifi: add ty/So/Ma firmwares for core87-44 release
      * iwlwifi: update cc/Qu/QuZ firmwares for core87-44 release
      * nvidia: Update Tegra210 XUSB firmware to v50.29
      * amdgpu: update beige goby firmware
      * amdgpu: update dimgrey cavefish firmware
      * amdgpu: update psp 13.0.11 firmware
      * amdgpu: update gc 11.0.4 firmware
      * amdgpu: update navy flounder firmware
      * amdgpu: update renoir firmware
      * amdgpu: update vcn 4.0.2 firmware
      * amdgpu: update sdma 6.0.1 firmware
      * amdgpu: update psp 13.0.4 firmware
      * amdgpu: update gc 11.0.1 firmware
      * amdgpu: update sienna cichlid firmware
      * amdgpu: update vega20 firmware
      * amdgpu: update yellow carp firmware
      * amdgpu: update green sardine firmware
      * amdgpu: update vega12 firmware
      * amdgpu: update raven2 firmware
      * amdgpu: update vcn 4.0.4 firmware
      * amdgpu: update smu 13.0.7 firmware
      * amdgpu: update sdma 6.0.2 firmware
      * amdgpu: update ipsp 13.0.7 firmware
      * amdgpu: update gc 11.0.2 firmware
      * amdgpu: update vega10 firmware
      * amdgpu: update raven firmware
      * amdgpu: update navi14 firmware
      * amdgpu: update smu 13.0.10 firmware
      * amdgpu: update sdma 6.0.3 firmware
      * amdgpu: update psp 13.0.10 firmware
      * amdgpu: update gc 11.0.3 firmware
      * amdgpu: update vcn 3.1.2 firmware
      * amdgpu: update psp 13.0.5 firmware
      * amdgpu: update gc 10.3.6 firmware
      * amdgpu: update navi12 firmware
      * amdgpu: update arcturus firmware
      * amdgpu: update vangogh firmware
      * amdgpu: update navi10 firmware
      * amdgpu: update vcn 4.0.3 firmware
      * amdgpu: update smu 13.0.6 firmware
      * amdgpu: update psp 13.0.6 firmware
      * amdgpu: update gc 9.4.3 firmware
      * amdgpu: update vcn 4.0.0 firmware
      * amdgpu: update smu 13.0.0 firmware
      * amdgpu: update sdma 6.0.0 firmware
      * amdgpu: update psp 13.0.0 firmware
      * amdgpu: update gc 11.0.0 firmware
      * amdgpu: update  firmware
      * amdgpu: update aldebaran firmware
      * amdgpu: update psp 13.0.8 firmware
      * amdgpu: update gc 10.3.7 firmware
      * linux-firmware: mediatek: Update MT8173 VPU firmware to v1.1.9
      * ath10k: WCN3990: hw1.0: add qcm2290 firmware API file
      * ath10k: WCN3990: hw1.0: move firmware back from qcom/ location
      * i915: Add DG2 HuC 7.10.15
      * amdgpu: DMCUB updates for various AMDGPU ASICs
      * linux-firmware: update firmware for en8811h 2.5G ethernet phy
      * rtw89: 8852c: update fw to v0.27.56.14
      * rtw89: 8922a: add firmware v0.35.18.0
      * rtw88: Add RTL8703B firmware v11.0.0

    - Drop duplicated WHENCE from kernel-firmware-* subpackages (bsc#1222319)

    - Update to version 20240322 (git commit 9a6a0cc195c1):
      * mekdiatek: Update mt8186 SOF firmware to v2.0.1
      * linux-firmware: Add firmware for Cirrus CS35L56 for Dell laptops
      * Montage: update firmware for Mont-TSSE
      * WHENCE: Link the Raspberry Pi CM4 and 5B to the 4B
      * Intel Bluetooth: Update firmware file for Intel Bluetooth BE200
      * Intel Bluetooth: Update firmware file for Magnetor Intel Bluetooth AX101
      * Intel Bluetooth: Update firmware file for Magnetor Intel Bluetooth AX203
      * Intel Bluetooth: Update firmware file for Magnetor Intel Bluetooth AX211
      * Intel Bluetooth: Update firmware file for SolarF Intel Bluetooth AX101
      * Intel Bluetooth: Update firmware file for Solar Intel Bluetooth AX101
      * Intel Bluetooth: Update firmware file for SolarF Intel Bluetooth AX203
      * Intel Bluetooth: Update firmware file for Solar Intel Bluetooth AX203
      * Intel Bluetooth: Update firmware file for SolarF Intel Bluetooth AX211
      * Intel Bluetooth: Update firmware file for Solar Intel Bluetooth AX211
      * Intel Bluetooth: Update firmware file for Solar Intel Bluetooth AX210
      * Intel Bluetooth: Update firmware file for Intel Bluetooth AX200
      * Intel Bluetooth: Update firmware file for Intel Bluetooth AX201
      * Intel Bluetooth: Update firmware file for Intel Bluetooth 9560
      * Intel Bluetooth: Update firmware file for Intel Bluetooth 9260
      * amdgpu: DMCUB updates for various AMDGPU ASICs
      * linux-firmware: mediatek: Update MT8173 VPU firmware to v1.1.8
      * imx: sdma: update firmware to v3.6/v4.6

    - Update to version 20240312 (git commit 4a404b5bfdb9):
      * linux-firmware: update firmware for mediatek bluetooth chip (MT7921)
      * iwlwifi: update 9000-family firmwares to core85-89
      * rtl_bt: Update RTL8852A BT USB firmware to 0xD9D6_17DA
      * linux-firmware: update firmware for MT7921 WiFi device
      * linux-firmware: update firmware for mediatek bluetooth chip (MT7922)
      * linux-firmware: update firmware for MT7922 WiFi device
      * linux-firmware: Add CS35L41 HDA Firmware for Lenovo Thinkbook 16P Laptops

    - Update to version 20240229 (git commit 977332782302):
      * amdgpu: Update VCN firmware binaries
      * Intel IPU2: Add firmware files
      * brcm: Add nvram for the Acer Iconia One 7 B1-750 tablet
      * i915: Add Xe2LPD DMC v2.18
      * i915: Update MTL DMC v2.21

    - Update to version 20240220 (git commit 73b4429fae36):
      * linux-firmware: update firmware for en8811h 2.5G ethernet phy
      * linux-firmware: add firmware for MT7996
      * xe: First GuC release for LNL and Xe
      * i915: Add GuC v70.20.0 for ADL-P, DG1, DG2, MTL and TGL
      * linux-firmware: Add CS35L41 firmware for Lenovo Legion 7i gen7 laptop (16IAX7)
      * brcm: Add nvram for the Asus Memo Pad 7 ME176C tablet
      * ice: update ice DDP package to 1.3.36.0
      * Intel IPU3 ImgU: Move firmware file under intel/ipu
      * Intel IPU6: Move firmware binaries under ipu/
      * check_whence: Add a check for duplicate link entries
      * WHENCE: Clean up section separators
      * linux-firmware: Add CS35L41 firmware for additional ASUS Zenbook 2023 models
      * panthor: Add initial firmware for Gen10 Arm Mali GPUs
      * amdgpu: DMCUB Updates for DCN321: 7.0.38.0
      * amdgpu: DMCUB updates for Yellow Carp: 4.0.68.0
      * qcom: update venus firmware file for v5.4
      * Montage: add firmware for Mont-TSSE
      * amdgpu: update DMCUB to v0.0.203.0 for DCN314 and DCN32
      * linux-firmware: Remove 2 HP laptops using CS35L41 Audio Firmware
      * linux-firmware: Fix filenames for some CS35L41 firmwares for HP

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225601");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036099.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47210");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47210");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-amdgpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ath10k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ath11k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ath12k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-atheros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-bnx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-brcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-chelsio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-dpaa2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-i915");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-iwlwifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-liquidio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-media");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-mediatek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-mellanox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-mwifiex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-nfp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-prestera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-qcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-qlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-radeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-realtek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ueagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-usb-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-amd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-firmware-all-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-all-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-atheros-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-atheros-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-brcm-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-brcm-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-i915-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-i915-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-intel-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-intel-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-marvell-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-marvell-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-media-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-media-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nfp-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nfp-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-platform-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-platform-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-prestera-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-prestera-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qcom-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qcom-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-radeon-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-radeon-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-realtek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-realtek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-serial-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-serial-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-sound-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-sound-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ti-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ti-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'ucode-amd-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'ucode-amd-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-all-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-all-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-atheros-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-atheros-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-brcm-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-brcm-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-i915-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-i915-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-intel-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-intel-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-marvell-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-marvell-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-media-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-media-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nfp-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nfp-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-platform-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-platform-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-prestera-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-prestera-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qcom-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qcom-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-radeon-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-radeon-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-realtek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-realtek-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-serial-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-serial-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-sound-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-sound-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ti-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ti-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'ucode-amd-20240712-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'ucode-amd-20240712-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-all-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-atheros-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-brcm-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-i915-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-intel-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-marvell-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-media-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-network-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nfp-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-platform-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-prestera-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-qcom-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-radeon-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-realtek-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-serial-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-sound-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ti-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ucode-amd-20240712-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-firmware / kernel-firmware-all / kernel-firmware-amdgpu / etc');
}
