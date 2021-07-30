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

<img src="https://github.com/o500/DNS-Tunneling-Detector/blob/78a71533eff85116c1a63fe30611fc166c2d3528/Detector.JPG">
