import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime


display_ports = {}

# Input Handling
parser = argparse.ArgumentParser()

parser.add_argument("target")
parser.add_argument("-p", "--ports", default="1-1024")
parser.add_argument("-t", "--timeout", type=float, default=1.0)
parser.add_argument("-w", "--workers", type=int, default=10)
parser.add_argument("-o", "--output")
parser.add_argument("--mode", choices=("sequential", "concurrent"), default="concurrent")

args = parser.parse_args()

# validation functions
def handle_ports():
    PORTS = []
    try:
        if "-" in args.ports:
                start, end = args.ports.strip().split("-", 1)
                start = int(start)
                end = int(end)
                if start>end:
                    raise ValueError("start port must be lower than end port")
                elif start<=0 or end<=0:
                     parser.error("port number should be greater than 0")
                elif start>65535 or end>65535:
                     parser.error("Invalid Port Range")
                PORTS = list(range(start, end+1))
                return PORTS
        
        for value in args.ports.split(","):
            value = value.strip()
            if not value:
                parser.error("Can't accept empty element")
            port_value = int(value)
            if port_value <= 0 or port_value > 65535:
                parser.error(f"Invalid port: {value}")
            if port_value not in PORTS:
                PORTS.append(port_value)
    except ValueError:
        parser.error("Invalid format of ports")
    return PORTS


def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        parser.error("Invalid Ip Address")


def check_for_negative_parameters(timeout, workers):
    if timeout<=0:
        parser.error("timeout must be positive number")
    if workers<=0:
         parser.error("need to have more than 0 workers")


#scanning functions
# Connection Part
def connection(ip, port, timeout):
    result = {
        "ip": ip,
        "port": port,
        "status": "",
        "error": None,
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            result.update({"status": "open"})
        except TimeoutError:
            result.update({"status": "no_response"})
        except ConnectionRefusedError:
            result.update({"status": "closed"})
        except OSError as e:
            result.update({"status": "error", "error": str(e)})
    return result

#sequental scanning
def run_sequental(ip, ports, timeout):
    results = []
    for port in ports:
        results.append(connection(ip, port, timeout))
    return results

#concurrent scanning
def run_concurrent(ip,ports,timeout, workers):
    futures = []
    results = []
    #thread poolis sheqmna
    with ThreadPoolExecutor(max_workers=workers) as executor:
        #yoveli threadistvis gadacema funqciis da future obieqtebis masivshi shenaxva
        for port in ports:
            future = executor.submit(connection, ip, port, timeout)
            futures.append(future)
        #ukve dasrulebuli taskebis gadatana masivshi
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
    return results

def summarize_results(scan_results, elapsed_ms):
    statistics["Duration"] = f"{elapsed_ms:.2f} ms"
    for result in scan_results:
        statistics["Ports Scanned"] += 1
        status = str(result.get("status", "")).strip().lower()
        port = result.get("port")

        if status == "open":
            statistics["Open Ports"] += 1
            display_ports[port] = status
        elif status == "closed":
            statistics["Closed Ports"] += 1
        elif status == "no_response":
            statistics["No response"] += 1
            display_ports[port] = status
        elif status == "error":
            statistics["Errors"] += 1
            display_ports[port] = status

# values
target = args.target
timeout = args.timeout
workers = args.workers
output = args.output
mode = args.mode 

# validation of arguments
validate_ip(target)
ports = handle_ports()
check_for_negative_parameters(timeout, workers)


statistics = {
    "Target": target,
    "Scan Type": "TCP Connect",
    "Scan Mode": mode,
    "Duration" : "",
    "Ports Scanned": 0,
    "Open Ports": 0,
    "Closed Ports": 0,
    "No Response": 0,
    "Errors": 0,
    "Time-Out": timeout,
    "Workers": workers,
}

#scanning
if mode == "sequential" : 
    start_time = time.perf_counter()
    scan_result = run_sequental(target, ports, timeout)
    end_time = time.perf_counter()

else:
    start_time = time.perf_counter()
    scan_result = run_concurrent(target, ports, timeout, workers)
    end_time = time.perf_counter()

elapsed_ms = (end_time-start_time)*1000
summarize_results(scan_result, elapsed_ms)

# sort result array
scan_result.sort(key=lambda r: r["port"])

# Write the results if a file path was provided
if output:
    with open(output, "w", encoding="utf-8") as file:
        file.write("=" * 10 + " Statistics " + "=" * 10 + "\n\n")
        for key, value in statistics.items():
            file.write(f"{key}: {value}\n")

        file.write("\n" + "=" * 12 + " Results " + "=" * 12 + "\n\n")
        file.write("PORT" + " " * 10 + "STATUS\n")
        file.write("-"*20+"\n")
        for port, status in display_ports.items():
            file.write(f"{port:<13} {status}\n")
else:
    print("\n" + "=" * 10 + " Statistics " + "=" * 10 + "\n")
    for key, value in statistics.items():
        print(f"{key}: {value}")

    print("\n" + "=" * 12 + " Results " + "=" * 12 + "\n")
    print("PORT" + " " * 10 + "STATUS")
    print("-"*20)
    for port, status in display_ports.items():
        print(f"{port:<13} {status}")




# statistics["Start Time"] = start_time.strftime("%H:%M:%S")
# statistics["End Time"] = end_time.strftime("%H:%M:%S")
# statistics["Total Scan Time"] = f"{elapsed_ms:.2f} ms"
