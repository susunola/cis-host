# SecX Automation Suite

**Compliance Baseline as Code | Hardening & Drift Automation**

**English** | [简体中文](README.zh.md) | [日本語](README.ja.md) | **ภาษาไทย**

Ansible playbooks และ CLI แบบローカルที่ใช้ดำเนินการตรวจสอบมาตรฐานความปลอดภัย **CIS** บน Linux 10 รุ่น และ Windows Server 4 เวอร์ชัน แต่ละชุดทำงานในสองโหมด — `scan` (อ่านอย่างเดียว) และ `apply` (แก้ไข) — และสร้างรายงาน HTML แบบโต้ตอบพร้อมบันทึกการตรวจสอบที่มีโครงสร้างสำหรับแต่ละโฮสต์

**แพลตฟอร์มที่รองรับ:** RHEL 8/9/10 · TencentOS 3/4 · SLES 15/16 · Ubuntu 20.04/22.04/24.04 LTS · Windows Server 2016/2019/2022/2025

## สถาปัตยกรรม

<p align="center">
  <img src="docs/architecture.svg" alt="SecX Automation Suite Architecture" width="800">
</p>

Engine เป็นสคริปต์ไฟล์เดียวที่ไม่มีการพึ่งพาไลบรารีภายนอก (Python 3 บน Linux, PowerShell บน Windows) Ansible ทำหน้าที่จัดการเฉพาะการถ่ายโอนไฟล์ การเรียกใช้คำสั่ง และการสร้างรายงาน แต่ละ Engine สร้างทั้ง `result.json` ที่มีโครงสร้าง และ `audit.log` (JSON-lines) ซึ่งเหมาะสำหรับการตรวจสอบด้านการปฏิบัติตามข้อกำหนด และการนำเข้าสู่ระบบ SIEM

## ขั้นตอนการทำงาน

### scan (อ่านอย่างเดียว)

1. `preflight` — Ansible ตรวจสอบความถูกต้องของตัวแปร ตรวจสอบ Python 3.6+ บนเครื่องเป้าหมาย (PowerShell 5.1+ บน Windows) และยืนยันสิทธิ์ root / Administrator
2. `push` — คัดลอก `cis_engine.py`, `rules.json`, `guidance.json` และ `sections.json` ไปยัง `/tmp/cis-scan/` บนเครื่องเป้าหมาย (`C:\Windows\Temp\cis-scan` บน Windows)
3. `run` — Engine เริ่มทำงานใน `--mode scan` วนตรวจสอบแต่ละกฎในแคตตาล็อก เก็บรวบรวมหลักฐาน และเขียน `result.json` โดยไม่มีการแก้ไขใด ๆ บนเครื่องเป้าหมาย
4. `fetch` — Ansible ดึง `result.json` (และ `audit.log` หากเปิดใช้งาน) กลับมายังเครื่องควบคุม
5. `report` — เทมเพลต Jinja2 (`report.html.j2`) รวม `result.json` เข้ากับข้อมูลโฮสต์ (hostname, IP, MAC, OS, kernel) เพื่อสร้างรายงาน HTML แบบโต้ตอบ

### apply (แก้ไข)

ขั้นตอนที่ 1, 2, 4, 5 เหมือนกับ `scan` ขั้นตอนที่ 3 แตกต่างดังนี้:

3. Engine เริ่มทำงานใน `--mode apply` สำหรับแต่ละกฎที่ไม่ผ่านซึ่งอยู่ในกลุ่มที่สามารถแก้ไขได้ Engine จะสำรองไฟล์ต้นฉบับไปยัง `/var/backups/cis-<os>/` แก้ไขการตั้งค่า จากนั้นตรวจสอบกฎอีกครั้งเพื่อยืนยันสถานะใหม่ กฎที่ต้องรีบูตหรือรีสตาร์ทเซอร์วิสจะถูกข้ามโดยค่าเริ่มต้น เว้นแต่จะตั้งค่า `cis_allow_disruptive=true` อย่างชัดเจน ทุกการกระทำจะถูกบันทึกใน audit log เมื่อเปิดใช้งาน

รายงานแสดงสถานะ **ก่อน** (จากการสแกนครั้งก่อน) และ **หลัง** พร้อมส่วนต่าง หากการ apply ทำให้เกิดข้อผิดพลาดใหม่ในการตรวจสอบซ้ำ รายงานจะแสดงในบล็อก "regressions"

## ชุดเครื่องมือ

| Suite | Benchmark | Engine | จำนวนกฎ |
|-------|-----------|--------|-------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 v1.0.0 | Python 3 | 322 |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 v1.0.0 | Python 3 | 275 |
| `cis-rhel8-ansible/` | CIS Red Hat Enterprise Linux 8 v4.0.0 | Python 3 | 322 |
| `cis-rhel9-ansible/` | CIS Red Hat Enterprise Linux 9 v2.0.0 | Python 3 | 297 |
| `cis-rhel10-ansible/` | CIS Red Hat Enterprise Linux 10 v1.0.1 | Python 3 | 328 |
| `cis-sles15-ansible/` | CIS SLES 15 v2.0.1 | Python 3 | 286 |
| `cis-sles16-ansible/` | CIS SLES 16 v1.0.0 | Python 3 | 336 |
| `cis-ubuntu2004-ansible/` | CIS Ubuntu 20.04 LTS v3.0.0 | Python 3 | 312 |
| `cis-ubuntu2204-ansible/` | CIS Ubuntu 22.04 LTS v3.0.0 | Python 3 | 306 |
| `cis-ubuntu2404-ansible/` | CIS Ubuntu 24.04 LTS v2.0.0 | Python 3 | 332 |
| `cis-win2016-ansible/` | CIS Microsoft Windows Server 2016 v3.0.0 | PowerShell | 337 |
| `cis-win2019-ansible/` | CIS Microsoft Windows Server 2019 v3.0.0 | PowerShell | 338 |
| `cis-win2022-ansible/` | CIS Microsoft Windows Server 2022 v3.0.0 | PowerShell | 342 |
| `cis-win2025-ansible/` | CIS Microsoft Windows Server 2025 v2.1.0 | PowerShell | 360 |

แต่ละชุดเป็นโปรเจกต์ Ansible แบบพร้อมใช้งานในตัวเอง ประกอบด้วย inventory, group_vars, `scan.yml`, `apply.yml`, โครงสร้าง role และเทมเพลตของตัวเอง

## การบันทึกการตรวจสอบ (Audit logging)

เมื่อตั้งค่า `--audit-log` Engine จะเขียนหนึ่งบรรทัด JSON ต่อการดำเนินการของแต่ละกฎลงในไฟล์ที่ระบุ สร้างเส้นทางการตรวจสอบที่มีโครงสร้างและปลอดภัยสำหรับการต่อท้าย แต่ละรายการประกอบด้วย:

| ฟิลด์ | คำอธิบาย |
|-------|-------------|
| `ts` | เวลา UTC ในรูปแบบ ISO-8601 แบบมิลลิวินาที |
| `host` | ชื่อโฮสต์เป้าหมาย |
| `version` | เวอร์ชันของ Engine |
| `mode` | `scan` หรือ `apply` |
| `profile` | `L1` หรือ `L2` |
| `rule` | รหัสกฎ CIS (เช่น `1.1.1.1`) |
| `title` | ชื่อกฎที่อ่านเข้าใจได้ |
| `status` | `pass`, `fail`, `manual`, `error`, `notapplicable` |
| `apply_status` | `applied`, `already`, `skipped_disruptive`, `failed`, `n/a` |
| `detail` | หลักฐานหรือสรุปการแก้ไข (ตัดให้เหลือ 200 ตัวอักษร) |
| `duration_ms` | เวลาดำเนินการเป็นมิลลิวินาที |

**ผ่าน CLI:**

```bash
python3 cis_cli.py scan --os rhel9 --audit-log output/audit-$(hostname).log
```

**ผ่าน Ansible:** เพิ่ม `-e cis_audit_log=/var/log/cis-audit.log` ในการเรียกใช้ playbook

รูปแบบ audit log เป็น JSON แบบขึ้นบรรทัดใหม่ เข้ากันได้กับเครื่องมือรวบรวมล็อก แพลตฟอร์ม SIEM และผู้ตรวจสอบด้านการปฏิบัติตามข้อกำหนด

## เริ่มต้นใช้งาน

### Local CLI (แนะนำ)

```bash
# สแกน L1 (อ่านอย่างเดียว)
python3 cis_cli.py scan --os rhel9 --profile L1 --output output/

# แก้ไข L1
python3 cis_cli.py apply --os ubuntu2204 --profile L1 --output output/

# สแกนเต็มรูปแบบ L2 + อนุญาตกฎที่มีผลกระทบ + audit log
python3 cis_cli.py apply --os tencentos4 --profile L2 --allow-disruptive \
  --audit-log output/audit.log --output output/

# สแกนเฉพาะกฎที่ระบุ
python3 cis_cli.py scan --os sles15 --include "1.1.1,1.1.2,5.2" --output output/
```

ค่าของ `--os`: `tencentos3` `tencentos4` · `rhel8` `rhel9` `rhel10` · `sles15` `sles16` · `ubuntu2004` `ubuntu2204` `ubuntu2404` · `win2016` `win2019` `win2022` `win2025`

### ผ่าน Ansible

```bash
ansible-playbook -i cis-rhel9-ansible/inventory/hosts.ini \
                 cis-rhel9-ansible/scan.yml

ansible-playbook -i cis-rhel9-ansible/inventory/hosts.ini \
                 cis-rhel9-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

## การระบุขอบเขตการทำงานแบบละเอียด

ทั้ง Engine และ wrapper ใช้ตัวกรองร่วมกัน:

| พารามิเตอร์ | วัตถุประสงค์ |
|-----------|---------|
| `--mode scan` / `--mode apply` | ตรวจสอบแบบอ่านอย่างเดียว / แก้ไข |
| `--profile L1` / `--profile L2` | ระดับพื้นฐาน / การป้องกันเชิงลึก |
| `--include 1.1.1,1.1.2,5.2` | เรียกใช้เฉพาะกฎเหล่านี้ |
| `--exclude 1.5,1.6` | ข้ามกฎเหล่านี้ |
| `--sections 1,5` | เรียกใช้เฉพาะกฎที่มีรหัสขึ้นต้นด้วยคำนำหน้าเหล่านี้ |
| `--families sysctl,kmod` | เรียกใช้เฉพาะกฎจากกลุ่มที่แก้ไขได้เหล่านี้ |
| `--audit-log audit.log` | เขียนเส้นทางการตรวจสอบที่มีโครงสร้าง |

เมื่อใช้ Ansible ตัวแปรที่เกี่ยวข้องจะถูกอธิบายไว้ใน README ของแต่ละชุด ภายใต้หัวข้อ "Key Variables"

## โครงสร้างไดเรกทอรี

```
secx/
├── README.md
├── README.zh.md
├── README.ja.md
├── README.th.md
├── cis_cli.py                      # CLI แบบローカル (--os สลับเป้าหมาย)
├── docs/architecture.svg           # แผนผังสถาปัตยกรรม
├── cis-tencentos3-ansible/         # TencentOS 3
├── cis-tencentos4-ansible/         # TencentOS 4
├── cis-rhel8-ansible/              # RHEL 8
├── cis-rhel9-ansible/              # RHEL 9
├── cis-rhel10-ansible/             # RHEL 10
├── cis-sles15-ansible/             # SLES 15
├── cis-sles16-ansible/             # SLES 16
├── cis-ubuntu2004-ansible/         # Ubuntu 20.04 LTS
├── cis-ubuntu2204-ansible/         # Ubuntu 22.04 LTS
├── cis-ubuntu2404-ansible/         # Ubuntu 24.04 LTS
├── cis-win2016-ansible/            # Windows Server 2016
├── cis-win2019-ansible/            # Windows Server 2019
├── cis-win2022-ansible/            # Windows Server 2022
└── cis-win2025-ansible/            # Windows Server 2025
    ├── ansible.cfg
    ├── scan.yml | apply.yml | site.yml
    ├── inventory/  group_vars/
    ├── reports/                    # ผลลัพธ์ HTML / JSON / CSV / audit
    └── roles/cis_<os>/
        ├── files/   engine, rules.json, guidance.json, sections.json
        ├── tasks/   preflight, run, report, gate
        └── templates/  report.html.j2, index.html.j2, findings.csv.j2
```

## รายงาน

รายงาน HTML สองรูปแบบที่แตกต่างกันถูกสร้างขึ้นจากการทำงานทุกครั้ง ทั้งสองเป็นไฟล์แบบสแตติก ครบในตัว พร้อมพิมพ์ และปรับแต่งธีมได้ (สว่าง / มืด) ใช้ Jinja2 + vanilla JS ร่วมกัน และไม่โหลดทรัพยากรจากภายนอก จึงทำงานแบบออฟไลน์ได้เต็มรูปแบบ

| รายงาน | เทมเพลต | ชื่อไฟล์ผลลัพธ์ | เมื่อสร้าง |
|--------|----------|-----------------|---------------|
| **ต่อโฮสต์** | `templates/report.html.j2` | `HOST-PROFILE-mode-TIMESTAMP.html` | ทุกการทำงาน (scan หรือ apply) |
| **ดัชนีกลุ่ม** | `templates/index.html.j2` | `index-TIMESTAMP.html` | Inventory หลายโฮสต์ หรือ `cis_report_index=true` |

เทมเพลต `findings.csv.j2` ก็พร้อมใช้งานสำหรับการนำเข้า Excel/Sheets — เปิดใช้งานด้วย `cis_report_csv=true`

### รายงานต่อโฮสต์

ภาพรวมสถานะการปฏิบัติตามข้อกำหนดที่สมบูรณ์ของโฮสต์เดียว เป็นผลลัพธ์เริ่มต้นสำหรับการสแกนหรือการแก้ไขทุกครั้ง

- **แบนเนอร์คะแนน** — เปอร์เซ็นต์ผ่านโดยรวม พร้อมสีไฟจราจร (เขียว ≥ 90, เหลือง ≥ 70, แดง อื่น ๆ)
- **ข้อมูลระบบ** — hostname, IPv4, MAC, OS, kernel, สถาปัตยกรรม, virtualization, uptime
- **ตารางผลการตรวจ** — ทุกกฎพร้อมสถานะ กลุ่ม ระดับ หลักฐาน คำแนะนำการแก้ไข และการอ้างอิงหน้า benchmark
- **ตัวกรอง** — ตามสถานะ (pass / fail / manual / error / n/a), กลุ่ม, ระดับ, ส่วน; ข้อมูลคงอยู่ใน `localStorage`
- **เปรียบเทียบก่อน/หลัง** — ในโหมด `apply` แสดงความแตกต่างระหว่างการสแกนก่อนและหลัง พร้อมบล็อก regression ที่เน้นกฎที่เคยผ่านแต่ไม่ผ่านหลังแก้ไข

### ดัชนีกลุ่ม

แดชบอร์ดการปฏิบัติตามข้อกำหนดสำหรับหลายโฮสต์ สำหรับผู้ดูแลระบบคลัสเตอร์

- **คะแนนกลุ่ม** — เปอร์เซ็นต์ผ่านโดยรวมของทุกโฮสต์ใน play
- **การ์ดสถิติ 6 รายการ** — ต้องแก้ไข, L1 แก้ไขแล้ว, L2 แก้ไขแล้ว, ตรวจสอบด้วยตนเอง, แก้ไขล้มเหลว, จำนวนโฮสต์
- **ตารางโฮสต์** — แต่ละโฮสต์พร้อมแถบคะแนน ป้าย pass/fail จำนวนที่แก้ไขแล้ว (พร้อมคำเตือน pending-reboot) และลิงก์ไปยังรายงานต่อโฮสต์
- **เจาะลึก** — ทุกแถวโฮสต์มีลิงก์ไปยังรายงานต่อโฮสต์ของการทำงานครั้งนั้น

ดัชนีกลุ่มมีประโยชน์เฉพาะเมื่อมีเป้าหมายมากกว่าหนึ่งรายการ เปิดใช้งานอย่างชัดเจนด้วย `-e cis_report_index=true` เพื่อบังคับสร้างแม้มีการทำงานเพียงโฮสต์เดียว

## หลายโฮสต์

หนึ่ง play ทำงานกับทุกโฮสต์ใน inventory แต่ละโฮสต์ได้รับ `reports/HOST-L1-scan.html` ของตัวเอง เมื่อ inventory มีมากกว่าหนึ่งโฮสต์ role จะสร้าง `reports/index.html` ด้วย — ภาพรวมคลัสเตอร์ที่แสดงคะแนนการปฏิบัติตามข้อกำหนดของแต่ละโหนด จำนวนผ่าน/ไม่ผ่าน และลิงก์ไปยังรายงานต่อโฮสต์

## หมายเหตุ

- `apply` แก้ไขไฟล์การตั้งค่าโดยตรง ไฟล์ต้นฉบับถูกสำรองไว้ที่ `/var/backups/cis-<os>/`
- กฎที่ระบุว่า `disruptive` (รีบูต, remount, รีสตาร์ทเซอร์วิส) จะถูกข้ามโดยค่าเริ่มต้น ใช้ `-e cis_allow_disruptive=true` เพื่อเลือกดำเนินการ ควรทำงานในช่วง maintenance window
- มีหกกลุ่มที่ไม่ถูกแก้ไขอัตโนมัติโดยเจตนา — ต้องใช้วิจารณญาณของมนุษย์หรือขึ้นอยู่กับสภาพแวดล้อม: `bootloader_password`, `info_only`, `manual`, `partition`, `root_access`, `sshd_access` Engine จะรายงานรายการเหล่านี้แต่ไม่แก้ไข
- Engine สำหรับ Linux ต้องการ `rpm`/`dpkg`, `systemctl`, `sshd -T`, `auditctl` และ `/proc` ครอบคลุมตระกูล RHEL, Debian และ SUSE Engine สำหรับ Windows รองรับ Server 2016 / 2019 / 2022 / 2025
- ก่อนรัน `apply` ในสภาพแวดล้อมจริง ควรรัน `scan` ในสภาพแวดล้อมทดสอบ ตรวจสอบรายงาน แล้วจึงดำเนินการต่อ

## ใบอนุญาต

เนื้อหา Benchmark เป็นลิขสิทธิ์ของ Center for Internet Security สคริปต์อัตโนมัติใน repository นี้จัดเตรียมให้ตามสภาพที่เป็นอยู่สำหรับการใช้งานจริง
