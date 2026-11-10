"""
Đọc các khóa Registry liên quan tới thiết bị lưu trữ ngoài và ổ mạng bằng python-registry
(parser độc lập với Eric Zimmerman Tools), xuất CSV để đối chiếu chéo với LNK/Jump List/ShellBags.

Nguồn đọc
- SYSTEM   : Select\\Current, ControlSet00X\\Enum\\USBSTOR (+ Properties {83da6326...} 0064/0065)
- SOFTWARE : Microsoft\\Windows NT\\CurrentVersion\\ProfileList (SID -> user)
             Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt (nhãn volume + volume serial thập phân)
- NTUSER   : ...\\Explorer\\MountPoints2, ...\\Explorer\\Map Network Drive MRU

Lưu ý
- Đọc bản copy trong evidence_work/hives (không ghi gì vào hive).
- python-registry KHÔNG replay transaction log (.LOG1/.LOG2): hive trong CASE01 lấy từ máy đã tắt
  nên đủ dùng, nhưng hive "dirty" có thể thiếu thay đổi cuối.
- Properties 0064/0065 (Win7): First Install / Install Date. Win7 không có 0066/0067.

Chạy:
    pip install python-registry
    python registry_usb_check.py <thư mục hives> -o ../tool_output/registry/registry_usb_network.csv
"""
import argparse
import csv
import os

from Registry import Registry

PROPS_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
PROP_NAMES = {"00000064": "first_install", "00000065": "install_date",
              "00000066": "last_arrival", "00000067": "last_removal"}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z" if dt else ""


def val(key, name, default=""):
    try:
        return key.value(name).value()
    except Registry.RegistryValueNotFoundException:
        return default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hive_dir")
    ap.add_argument("-o", "--output", default="registry_usb_network.csv")
    args = ap.parse_args()
    H = lambda n: os.path.join(args.hive_dir, n)

    rows = []

    def add(source, key_path, item, timestamp, ts_meaning, detail):
        rows.append({"source_hive": source, "key_path": key_path, "item": item,
                     "timestamp_utc": timestamp, "timestamp_meaning": ts_meaning, "detail": detail})

    system = Registry.Registry(H("SYSTEM"))
    current = val(system.open("Select"), "Current", 1)
    cs = f"ControlSet{int(current):03d}"
    add("SYSTEM", "Select", "Current", "", "", f"{current} -> {cs}")

    usbstor = system.open(f"{cs}\\Enum\\USBSTOR")
    for dev in usbstor.subkeys():
        for inst in dev.subkeys():
            serial = inst.name().split("&")[0]
            kp = f"{cs}\\Enum\\USBSTOR\\{dev.name()}\\{inst.name()}"
            name = val(inst, "FriendlyName")
            add("SYSTEM", kp, serial, iso(inst.timestamp()), "Key LastWrite (cập nhật khi cắm lại/driver ghi)",
                f"{dev.name()} | FriendlyName={name}")
            try:
                props = inst.subkey("Properties").subkey(PROPS_GUID)
                for p in props.subkeys():
                    if p.name() in PROP_NAMES:
                        add("SYSTEM", f"{kp}\\Properties\\{PROPS_GUID}\\{p.name()}", serial,
                            iso(p.timestamp()), PROP_NAMES[p.name()] + " (key LastWrite)", name)
            except Registry.RegistryKeyNotFoundException:
                pass

    software = Registry.Registry(H("SOFTWARE"))
    for s in software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList").subkeys():
        add("SOFTWARE", f"Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{s.name()}", s.name(),
            iso(s.timestamp()), "Key LastWrite", f"ProfileImagePath={val(s, 'ProfileImagePath')}")
    try:
        for s in software.open("Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt").subkeys():
            # tên khóa: <...>_<VolumeLabel>_<VolumeSerial thập phân>
            label, _, dec = s.name().rpartition("_")
            vsn = format(int(dec), "08X") if dec.isdigit() else ""
            add("SOFTWARE", f"Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt\\{s.name()}", vsn,
                iso(s.timestamp()), "Key LastWrite (≈ lần volume được gắn gần nhất)",
                f"label_part={label} | volume_serial_dec={dec}")
    except Registry.RegistryKeyNotFoundException:
        pass

    ntuser = Registry.Registry(H("NTUSER.DAT"))
    base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    for s in ntuser.open(f"{base}\\MountPoints2").subkeys():
        add("NTUSER.DAT", f"{base}\\MountPoints2\\{s.name()}", s.name(), iso(s.timestamp()),
            "Key LastWrite (≈ lần user gắn volume/share gần nhất)", "")
    try:
        k = ntuser.open(f"{base}\\Map Network Drive MRU")
        for v in k.values():
            add("NTUSER.DAT", f"{base}\\Map Network Drive MRU", v.name(), iso(k.timestamp()),
                "Key LastWrite", str(v.value()))
    except Registry.RegistryKeyNotFoundException:
        pass

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} dòng -> {args.output}")


if __name__ == "__main__":
    main()
