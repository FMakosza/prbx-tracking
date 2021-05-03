This repository contains code for part of the methodology for the BSc Computer Science dissertation "The Prevalence of Third Party Tracking in Government and Public Sector Websites". 

The crawl process described in the paper can be repeated by executing the following commands (after cloning this repo):

```
mv crawl.py readme.md tool.py urls.json OpenWPM-0.14.1/
cd OpenWPM-0.14.1
git clone https://github.com/disconnectme/disconnect-tracking-protection/
./install.sh
conda activate openwpm
```

The OpenWPM conda environment will now be ready for use. In a live Python session (in my case, version 3.9.2) run the following commands to execute an OpenWPM crawl on the URLs in `urls.json`:

```python
import tool
tool.runCrawlsFromJson()

trackers = tool.parseDisconnectList()
tool.initDB()
tool.searchCrawl(trackers)
```

This will create a `datadir/analysis-data.sqlite` database which contains a list of every request URL which matched a domain in the Disconnect Tracking Protection list.
