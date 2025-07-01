import os
import subprocess

LOC_SNI_filter = "."
LOC_NUM_ADU = 3
data_list = ['hema', 'darunfa','dazhong','baiduditu',
            'meituan','douyin','tengxun','58','transit',
            'foodpanda','yelp','opentable','waze',
            'googlemap','moji','haluo','yonghui','kfc']

program_path = "./recog2025/bin/win"

#pcap path
base_path = ""
paths = [f"{base_path}{item}/data/" for item in data_list]

for LOC_Path in paths:
    os.makedirs(LOC_Path, exist_ok=True)
    for file in os.listdir(LOC_Path):
        file_path = os.path.join(LOC_Path, file)
        if os.path.isfile(file_path) and not file.endswith('.pcap'):
            os.remove(file_path)

    cfg_path = os.path.join(LOC_Path, "data.cfg")

    with open(cfg_path, "w", encoding="utf-8") as f:
        content = [
            '//----------------location',
            '',
            f'LOC_Path = "{LOC_Path}";',
            f'LOC_SNI_filter = "{LOC_SNI_filter}";',
            f'LOC_NUM_ADU = {LOC_NUM_ADU};'
        ]
        for c in content:
            f.write(c + "\n")

    print(f"Configuration file created at: {cfg_path}")

    cmd_command = f"{program_path}/location.exe {cfg_path}"
    process = subprocess.Popen(cmd_command, shell=True)
    process.wait()

    print(f"Executed command: {cmd_command}")
