# DNS-Tunneling-Detector
Python code to parse DNS logs and identify DNS tunnel by
traffic analysis and payload analysis.

Link to presented simulation: <a href="https://github.com/o500/DNS-Tunneling-Detector/blob/64c03581019011b0d5f0cb1f618c1925156bb887/DNS%20TUNNELING%20DETECTOR.pdf">Presentation</a>

Programs used: DNScat client and server, DNSmasq DNS server, and our program.

More detailes:
The tool/software, which we wrote in Python, not only enables the user
to view various statistics regarding DNS traffic, manually block/approve
domains, but it also blocks in real time domains which it condemns
suspicious, based on traffic analysis we learned about from various
sources around the web.
All the graphics(graphs, windows, etc.) of the tool/software were created
using PySimpleGUI, a Python package for creating GUIs.
The parser part of the tool/software includes full Docstrings

When deciding whether a domain is suspicious, two factors are taken
into account, the domain’s name and the number of queries for that
domain in a time span of 10 minutes. As sources around the web
suggested, we set a threshold for the number of queries per one domain
in a time span of 10 minutes, and once it’s reached the domain is
considered suspicious as it indicates a rather heavy traffic for that one
domain in a relatively short time burst.
The other thing we analyzed is the domain’s name, a legit domain
generally won’t be longer than 52 characters, won’t include more than 27
unique characters and won’t include more than 7 digits, thus a domain
name that violates any of this conditions is condemned suspicious by
our tool/software.
As long as the tool/software stays active, it keeps on parsing and
analyzing the data produced from the DNS server’s logs file.
Running the simulation
We performed the simulation of a DNS attack by configuring a DNS
server and running through it a tunnel between a client and a
server(DNScat applications) on a virtual machine, and then running our
tool/software in order to detect and block the DNS tunnel in real time.
<img src="https://github.com/o500/DNS-Tunneling-Detector/blob/78a71533eff85116c1a63fe30611fc166c2d3528/Detector.JPG">
