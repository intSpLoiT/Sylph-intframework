# Usage:
````
┌───T─I─M─E───┐┌───D─A─T─E────>
┌─[ 11:33 AM ]──[ Fri Jan 17 ]
├─[~]
└─>intikam21[~]:# cve_search
usage: cve_search [-h] [-c CVE] [-k KERNEL] [-p PRODUCT] [-pv PRODUCTVERSION]

Github payload searcher by shinningstar

options:
  -h, --help            show this help message and exit
  -c CVE, --cve CVE     CVE string (Ex: CVE-2023-27163)
  -k KERNEL, --kernel KERNEL
                        Linux kernel string (Ex: 5.15.70)
  -p PRODUCT, --product PRODUCT
                        Product to be scanned (Ex: Joomla)
  -pv PRODUCTVERSION, --productversion PRODUCTVERSION
                        Version of the product (Ex: 4.2.6)
┌───T─I─M─E───┐┌───D─A─T─E────>
┌─[ 11:33 AM ]──[ Fri Jan 17 ]
├─[~]
└─>intikam21[~]:#
````
### Photo:
- adding wait

## What is it?
(for script kiddies)
# **cve_search Module in intframework**

The **cve_search** module is designed to search for **Common Vulnerabilities and Exposures (CVE)** information. It allows users to query specific CVEs, Linux kernel versions, products, or product versions to find relevant security vulnerabilities. However, for "script kiddies" (inexperienced users), this tool may be misunderstood or misused. Here’s a simplified explanation:

---

### **What is the cve_search module, and how does it work?**
The **cve_search** module is a tool to gather information about security vulnerabilities. It helps users find details about specific CVEs, vulnerabilities in Linux kernels, or security issues related to specific products and their versions. It is not a hacking tool but rather an information-gathering utility.

#### **Options:**
- **`-c` or `--cve`**: Searches for a specific CVE code. Example: `CVE-2023-27163`.
- **`-k` or `--kernel`**: Searches for vulnerabilities in a specific Linux kernel version. Example: `5.15.70`.
- **`-p` or `--product`**: Searches for vulnerabilities in a particular product. Example: `Joomla`.
- **`-pv` or `--productversion`**: Searches for vulnerabilities in a specific version of a product. Example: Joomla `4.2.6`.

---

### **Usage:**
```bash
# Search for a specific CVE
intikam21[~]:# cve_search -c CVE-2023-27163

# Search for vulnerabilities in a specific Linux kernel version
intikam21[~]:# cve_search -k 5.15.70

# Search for vulnerabilities in a specific product
intikam21[~]:# cve_search -p Joomla

# Search for vulnerabilities in a specific version of a product
intikam21[~]:# cve_search -p Joomla -pv 4.2.6

# Help command to see all available options
intikam21[~]:# cve_search -h
```

---

### **Notes for Script Kiddies:**
1. **Understand before using:** This module is purely for information gathering. Misusing the data without technical understanding can cause damage and lead to legal issues.

2. **Responsibility:** Finding vulnerabilities doesn’t mean exploiting them. The goal is to help secure systems, not attack them.

3. **Educate yourself:** Using tools like this without proper knowledge can result in mistakes and risks for both you and the systems involved.

4. **GitHub Payload Search:** The module searches GitHub for potential exploit code. However, trying to use such exploits without understanding can lead to failure or unintended consequences.

---

In summary, the **cve_search** module is an **information-gathering tool** designed to assist in identifying vulnerabilities. It’s not meant for illegal activities or exploitation. Users are advised to learn the basics of security before using such tools.
