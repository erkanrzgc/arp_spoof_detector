# ARP Spoof Detection Script

This Python script is designed to detect ARP spoofing attacks on a network. It monitors ARP traffic and compares the actual MAC address of devices with the claimed MAC addresses in ARP packets. If a mismatch is detected, it alerts the user.

## Disclaimer

This script is provided for **educational purposes only**. Unauthorized network monitoring may violate privacy laws and ethical guidelines. Ensure you have explicit permission to monitor and analyze network traffic in your environment.

**Use responsibly and at your own risk.**

---

## Requirements

This script requires the following:

- Python 3
- `scapy` library (can be installed via `pip install scapy`)
- Administrator/root privileges

---

## How It Works

1. **Get MAC Address:** The `getMAC` function sends an ARP request to retrieve the actual MAC address of a given IP address.
2. **Sniff Network Traffic:** The `sniff` function captures packets on the specified network interface.
3. **Process Packets:** The `process_sniffed_packet` function analyzes ARP packets to detect discrepancies between the real MAC address and the one claimed in the ARP response.
4. **Alert:** If a mismatch is found, the script prints an alert: `"[+] You are under attack!!!"`.

---

## Usage

1. Clone or download this repository.
2. Specify the network interface to monitor in the script. For example, replace `eth0` with your network interface:
   ```python
   sniff("eth0")
   ```
3. Run the script with administrator/root privileges:
   ```bash
   sudo python3 arp_sniffer.py
   ```

---

## Example

If your network interface is `wlan0`, update the script as follows:

```python
sniff("wlan0")
```

Then, execute the script:

```bash
sudo python3 arp_sniffer.py
```

---

## Important Notes

- Ensure the script is run in a network you have permission to monitor.
- This script only detects ARP spoofing and does not block or mitigate it.
- The interface name (`eth0`, `wlan0`, etc.) may vary depending on your system configuration. Use the correct interface name for your system.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

