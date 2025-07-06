<!-- Project: NexusSIEM -->
<a name="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Stargazers][stars-shield]][stars-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/FuryCode-bit/NexusSIEM">
    <img src="readme/ua.png" alt="Logo" height="80">
  </a>

<h3 align="center">NexusSIEM: A Behavioral SIEM Rule Engine</h3>

  <p align="center">
    An advanced analysis tool for detecting sophisticated cyber threats through behavioral profiling of network traffic.
    <br />
    <br />
    <a href="https://github.com/FuryCode-bit/NexusSIEM"><strong>Explore the Project »</strong></a>
    <br />
    <br />
    <a href="https://github.com/FuryCode-bit/NexusSIEM/issues">Report Bug</a>
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## About The Project

![Project Screenshot][project-screenshot]

NexusSIEM is a Python-based security information analysis engine designed to detect network compromises. Developed as a practical project for the Network Security course at the University of Aveiro, it moves beyond simple signature-based detection to identify threats based on their behavior.

By establishing a quantitative baseline of normal network activity, the engine analyzes anomalous traffic logs to uncover a wide range of threats, including:
*   Internal lateral movement and network scanning.
*   Large-scale data exfiltration over encrypted channels (HTTPS).
*   Command & Control (C&C) communication via DNS and HTTPS beaconing.
*   Coordinated external botnet attacks, such as credential stuffing and DDOS campaigns.

The core of the project is a custom SIEM analysis library (`analysis.py`) and a Jupyter Notebook (`report.ipynb`) that uses this library to generate a comprehensive security report.

<!-- BUILT WITH -->
### Built With

This project leverages a powerful stack of data analysis and visualization libraries to process and interpret network data.

*   [![Pandas][Pandas.io]][Pandas-url]
*   [![NumPy][NumPy.org]][NumPy-url]
*   [![Matplotlib][Matplotlib.org]][Matplotlib-url]
*   [![Seaborn][Seaborn.pydata.org]][Seaborn-url]
*   [![NetworkX][NetworkX.org]][NetworkX-url]
*   [![Folium][Folium.python-visualization.github.io]][Folium-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running, follow these simple steps.

### Installation

1.  Clone the repo
    ```sh
    git clone https://github.com/FuryCode-bit/NexusSIEM.git
    ```
2.  Navigate to the project directory
    ```sh
    cd NexusSIEM
    ```
3.  Install Python packages
    ```sh
    pip install -r requirements.txt
    ```
4.  Download the datasets and the GeoLite2-Country database and place them in the `datasets/` directory as configured in `report.ipynb`.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

The primary entry point for this project is the `report.ipynb` Jupyter Notebook.

1.  **Configure Paths**: Open `report.ipynb` and update the file paths for the baseline, anomalous, and server datasets to match your local setup.
    ```python
    BASELINE_PATH = 'datasets/dataset10/data10.parquet'
    ANOMALOUS_PATH = 'datasets/dataset10/test10.parquet'
    SERVERS_PATH = 'datasets/dataset10/servers10.parquet'
    GEOIP_DB_PATH = 'datasets/GeoLite2-Country.mmdb'
    ```
2.  **Run the Notebook**: Execute the cells in the notebook sequentially. The script will load the data, run the full analysis pipeline using the `UltimateSIEM` class, and generate a detailed report complete with markdown explanations and visualizations.

The notebook is designed to be a self-contained security brief, walking through the investigation from initial profiling to the final correlation of threats.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- DETECTION METHODOLOGY -->
## Detection Methodology

The engine employs a rule-based system that scores devices based on the severity and combination of detected malicious behaviors. Key detection rules include:

#### Internal Threats:
*   **Data Exfiltration**: Flags hosts uploading anomalously large volumes of data over HTTPS, with scores scaling based on the amount of data stolen.
*   **C&C Beaconing**: Detects rhythmic, machine-like connections to external servers by analyzing the standard deviation of connection time intervals.
*   **Lateral Movement**: Identifies hosts initiating connections to a significant number of new internal devices not seen in the baseline.
*   **Anomalous Destinations**: Alerts on communications to new or high-risk geopolitical regions (e.g., RU, IR, CN) based on a tiered threat model.

#### External Threats:
*   **Connection Flooding**: Detects brute-force or DDoS attempts by flagging external IPs with an excessively high connection count.
*   **Automated Bot Activity**: Identifies bots through their 24/7 operational patterns and highly periodic, non-human connection timing.

A **Critical Combo Multiplier** is applied to hosts exhibiting multiple high-risk behaviors (e.g., scanning and exfiltrating data), ensuring that the most dangerous threats are prioritized.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/FuryCode-bit/NexusSIEM.svg?style=for-the-badge
[contributors-url]: https://github.com/FuryCode-bit/NexusSIEM/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/FuryCode-bit/NexusSIEM.svg?style=for-the-badge
[stars-url]: https://github.com/FuryCode-bit/NexusSIEM/stargazers
[license-shield]: https://img.shields.io/github/license/FuryCode-bit/NexusSIEM.svg?style=for-the-badge
[license-url]: https://github.com/FuryCode-bit/NexusSIEM/blob/master/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/bernardeswebdev
[project-screenshot]: readme/siem.png
[Pandas.io]: https://img.shields.io/badge/pandas-150458.svg?style=for-the-badge&logo=pandas&logoColor=white
[Pandas-url]: https://pandas.pydata.org/
[NumPy.org]: https://img.shields.io/badge/numpy-4d77cf.svg?style=for-the-badge&logo=numpy&logoColor=white
[NumPy-url]: https://numpy.org/
[Matplotlib.org]: https://img.shields.io/badge/matplotlib-212121.svg?style=for-the-badge&logo=matplotlib&logoColor=white
[Matplotlib-url]: https://matplotlib.org/
[Seaborn.pydata.org]: https://img.shields.io/badge/seaborn-2c3e50.svg?style=for-the-badge&logo=seaborn&logoColor=white
[Seaborn-url]: https://seaborn.pydata.org/
[NetworkX.org]: https://img.shields.io/badge/networkx-34749f.svg?style=for-the-badge&logo=networkx&logoColor=white
[NetworkX-url]: https://networkx.org/
[Folium.python-visualization.github.io]: https://img.shields.io/badge/folium-1a1a1a.svg?style=for-the-badge&logo=folium&logoColor=white
[Folium-url]: https://python-visualization.github.io/folium/
