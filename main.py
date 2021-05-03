import pathlib
import ipaddress
import subprocess
import shlex

class Shodanish:
    def __init__(self, options:str = "-T4 -v"):
        if options is None:
            self.options = ""
        else:
            self.options = options
        # we need to find where we stopped and if we never started, init the thing
        self.header_filename = "Shodanish-header.txt"
        if pathlib.Path(self.header_filename).is_file():
            with open(self.header_filename, "r") as f:
                lines = f.readlines()
                for line in lines:
                    line_parts = line.split()
                    # if you want to add new value to file, just add another if close
                    # ip part
                    if line_parts[0] == "last_ip":
                        self.last_ip: ipaddress.IPv4Address = ipaddress.ip_address(line_parts[1])
        else:
            with open(self.header_filename, "w") as f:
                lines = list()
                # here is the same story, add a new couple lines if needed
                # ip part
                self.last_ip: ipaddress.IPv4Address = ipaddress.ip_address("0.0.0.0")
                lines.append(f"last_ip {self.last_ip}\n")
                f.writelines(lines)

    def do_scan(self, ip):
        normal_output_file = f"{ip}_Normal.txt"
        xml_output_file = f"{ip}_XML.xml"
        command = f"nmap -oN {normal_output_file} -oX {xml_output_file} {self.options} {ip}"
        process = subprocess.run(shlex.split(command))

    def start_scans(self):
        bits = [int(i) for i in str(self.last_ip).split('.')]
        try:
            for bit1 in range(bits[0], 256):
                for bit2 in range(bits[1], 256):
                    for bit3 in range(bits[2], 256):
                        for bit4 in range(bits[3], 256):
                            current_ip = ipaddress.ip_address(f"{bit1}.{bit2}.{bit3}.{bit4}")
                            self.do_scan(current_ip)
        except KeyboardInterrupt:
            print("Stopping the scan")
            self.last_ip = current_ip
            with open(self.header_filename, 'r') as f:
                lines = f.readlines()
                data = dict()
                for line in lines:
                    line_parts = line.split()
                    data[line_parts[0]] = line_parts[1]
            lines.clear()
            with open(self.header_filename, 'w') as f:
                for key in data:
                    if key == "last_ip":
                        data[key] = str(current_ip)
                    lines.append(f"{key} {data[key]}\n")
                f.writelines(lines)


if __name__ == '__main__':
    scanner = Shodanish()
    scanner.start_scans()
















if __name__ == '__main__':
    scanner = Shodanish()

