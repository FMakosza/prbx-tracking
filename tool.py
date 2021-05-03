import sqlite3
import os
import sys
import json
import glob
import re
import time
from urllib.error import URLError
from urllib.request import urlopen, Request
from socket import timeout

import crawl

ANALYSIS_DB_PATH = 'datadir/analysis-data.sqlite'

def resolveURLList():
    '''
    This function was used to check for redirects and broken links in a list of
    URLs. It assumes there's an 'unresolved_urls.json' file where the domains 
    don't have the http(s):// prefix. 
    '''
    with open('unresolved_urls.json') as f:
        urls = json.load(f)
    resolved_urls = {}
    broken_urls = {}
    
    # Basically any user agent will work here, some sites don't respond to 
    # requests with empty user agents
    header = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0'}
    find_slash = re.compile("/")
    
    for key in urls.keys():
        resolved_urls[key] = []
        broken_urls[key] = []
        
        for url in urls[key]:
            resolved_url = None
            
            # Sloppy, but it works. Some websites in the set did not respond to
            # HTTPS requests or requests without a www. prefix, so three
            # permutations are tried before a website is deemed inaccessible.
            https_req = Request('https://' + url, None, header)
            http_req = Request('http://' + url, None, header)
            www_req = Request('http://www.' + url, None, header)
            print("Resolving {}...\t".format(url), end='')
            try:
                try:
                    with urlopen(https_req, timeout=5) as open_url:
                        resolved_url = open_url.url
                except (URLError, timeout):
                    try:
                        with urlopen(http_req, timeout=5) as open_url:
                            resolved_url = open_url.url                
                    except (URLError, timeout):
                        try:
                            with urlopen(www_req, timeout=5) as open_url:
                                resolved_url = open_url.url
                        except (URLError, timeout):
                            print("{} not accessible. Skipping.".format(url))
                            broken_urls[key].append(url)
            except Exception as e:
                print("\nUnexpected problem resolving {}. Skipping.".format(url))
                print("{}".format(e))     
                broken_urls[key].append(url)
            
            if resolved_url is not None:
                try:
                    # Tries to remove any subdirectories from the URL
                    third_slash = list(find_slash.finditer(resolved_url))[2]
                    resolved_url = resolved_url[:third_slash.end()]
                except IndexError:
                    # Just let resolved_url be resolved_url, this error means
                    # there's no trailing slash                    
                    pass 
                
                # If the URL redirected to a previously seen domain, this
                # stops it from being added to the list twice.
                if resolved_url in resolved_urls[key]:
                    print("Resolved {} from {}, already recorded, skipping.".format(resolved_url, url))
                else:
                    print("Resolved {} from {}.".format(resolved_url, url))
                    resolved_urls[key].append(resolved_url)
                
            time.sleep(0.5)
    
    with open('urls.json', 'w') as f:
        print("Writing resolved URLs to file.")
        json.dump(resolved_urls, f)
    
def removeDuplicateURLs():
    '''
    Removes duplicates from a URL file. Useful for when you add to the list
    but don't want/need to verify everything with resolveURLList
    '''
    with open('urls.json') as f:
        urls = json.load(f)
    final_urls = {}
    
    all_urls = []
    for key in urls.keys():
        final_urls[key] = []
        for url in urls[key]:
            if url in all_urls:
                print("{} already seen before. Skipping.".format(url))
            else:
                final_urls[key].append(url)
                all_urls.append(url)
    
    with open('urls_nodupes.json', 'w') as f:
        print("Writing duplicate-free URLs to file.")
        json.dump(final_urls, f)            

def runCrawl(url_list, db_name='crawl-data', manual=True, append=False):
    '''
    Basic wrapper to OpenWPM crawl script. 
        url_list is a list of URLs to crawl: ['https://abc.com', 
            'https://xyz.net'] etc
        db_name is the name of the database to write crawl output to
        manual can be set to False to skip the crawl data deletion warning
        append can be set to True to append to existing crawl data instead of
    deleting it
    '''
    if manual and not append:
        go = input("Proceeding will delete the old crawl data. Enter Y to continue.\n")
    else:
        go = 'y'
        
    if go.lower() == 'y':
        if not append:
            try:
                os.remove('datadir/{}.sqlite'.format(db_name))
            except FileNotFoundError:
                print("Old crawl data not found. Continuing.")

        crawl.crawl(url_list, db_name)
    else:
        print("Aborting.")
        
def runCrawlsFromJson():
    '''
    Runs sequence of OpenWPM crawls on URL files. The file has to be structured
    like this:
    {
        'category_name': [url1, url2],
        'other_category_name': [url3, url4]
    }
    
    A new crawl is initiated for each category, and its output is put in
    {category_name}-crawl-data.sqlite.
    '''
    with open('urls.json') as f:
        urls = json.load(f)
    
    input("Ctrl-C out now if you don't want to delete the old crawl data.\n")
    input("Last warning.")
    
    init_time = time.time()
    for category in urls:
        start_time = time.time()
        print("Starting crawl for category {}".format(category))
        
        runCrawl(urls[category], '{}-crawl-data'.format(category), False)
        
        print("Finished crawl for {} in {:.1f} minutes."
            .format(category, (time.time()-start_time)/60))
    
    print("Finished all crawls in {:.1f} minutes."
        .format((time.time()-init_time)/60))

def parseDisconnectList():
    '''
    Produces a dictionary of suspicious domains of the form
        {domain: {'parent': parent_company, 
                    'categories': ['Advertising', 'FingerprintingGeneral', etc],
                    'parent_url': parent_company_url}}
    '''
    disconnect_domains = {}
    
    with open('disconnect-tracking-protection/services.json') as f:
        disconnect = json.load(f)
                            
    for threat_category in disconnect['categories']:
        # threat_category is 'Advertising' or 'Content' etc
        for entry in disconnect['categories'][threat_category]: # list, not dict
            # entry is a dict like {'33Across': {'http://33across.com/': ['33across.com']}}
            for entity in entry: # dict 
                # entity would be '33Across' from above
                for url in entry[entity]:
                    # http://33across.com/ from above
                    if 'http' not in url:
                        continue
                    for domain in entry[entity][url]: # list, not dict
                        # domain would be 33across.com from above
                        if domain in disconnect_domains:
                            disconnect_domains[domain]['categories'].append(threat_category)
                        else:
                            disconnect_domains[domain] = {'parent': entity,
                                'categories': [threat_category],
                                'parent_url': url}
                
    return disconnect_domains

def initDB():
    '''
    Initialises the SQLite database where suspected tracker requests will be
    stored.
    '''
    con = sqlite3.connect(ANALYSIS_DB_PATH)
    cur = con.cursor()
    
    cur.execute('''CREATE TABLE results (site_domain text, 
        tracker_url text, 
        threat text, 
        category text,
        parent text,
        resource_type text)''')
    con.commit()
    con.close()

def searchCrawl(trackers):
    '''
    Very simple script to extract requests to domains on Disconnect's tracker 
    list to a different database.
    '''
    out_con = sqlite3.connect(ANALYSIS_DB_PATH)
    out_cur = out_con.cursor()
    
    for crawl_path in glob.iglob('datadir/*crawl-data.sqlite'):
        con = sqlite3.connect(crawl_path)
        category = crawl_path.removeprefix('datadir/').removesuffix('-crawl-data.sqlite')
        
        # rows become dictionaries with column labels instead of lists
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        
        cur.execute('''SELECT * FROM http_requests''')
        for line in cur:
            for tracker_domain in trackers:
                if tracker_domain in line['url']:
                    for threat in trackers[tracker_domain]['categories']:
                        site_domain = line['top_level_url']
                        tracker_url = line['url']
                        parent = trackers[tracker_domain]['parent']
                        resource_type = line['resource_type']
                        
                        
                        out_cur.execute(
                            '''INSERT INTO results VALUES (?, ?, ?, ?, ?, ?)''', 
                            [site_domain, tracker_url, threat, category, parent, resource_type])
                        print("Discovered {} on crawl for site {}. DB ID {}, threat {}"
                            .format(tracker_domain, line['top_level_url'], line['id'], threat))
        out_con.commit()
    
    con.close()
    out_con.close()
                
def removeImagesFromCrawl(results_db=ANALYSIS_DB_PATH):
    con = sqlite3.connect(results_db)
    cur = con.cursor()
    
    cur.execute('''CREATE TABLE results_noimg (site_domain text, 
        tracker_url text, 
        threat text, 
        category text,
        parent text,
        resource_type text)''')
    con.commit()
    
    cur.execute('''SELECT * FROM results''')
    results = cur.fetchall()
    print(len(results))
    for i in results:
        site_domain, tracker_url, threat, category, parent, resource_type = i
        if tracker_url[-4:] not in ['.png', '.gif', '.jpg', 'jpeg']:
            cur.execute('''INSERT INTO results_noimg VALUES (?, ?, ?, ?, ?, ?)''',
                (site_domain, tracker_url, threat, category, parent, resource_type))
    con.commit()
    con.close()
    
def analyseResults(results_db=ANALYSIS_DB_PATH):
    con = sqlite3.connect(results_db)
    # rows become dictionaries with column labels instead of lists
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    
    cur.execute('''SELECT DISTINCT category FROM results_noimg''')
    # list of website categories (national_government, nhs, etc)
    site_categories = []
    for category in cur:
        site_categories.append(list(category)[0])
      
    # list of parent companies (Google, Facebook, etc)
    parent_orgs = []
    cur.execute('''SELECT DISTINCT parent FROM results_noimg''')
    for parent in cur:
        parent_orgs.append(list(parent)[0])
        
    # number of requests per site to higher threat categories
    site_requests_worse = []
    cur.execute('''SELECT site_domain, COUNT(*) FROM results_noimg WHERE threat 
        IN ("FingerprintingGeneral", "FingerprintingInvasive", "Advertising")
        GROUP BY site_domain''')
    for request in cur:
        domain, req_count = list(request)
        site_requests_worse.append([req_count, domain])
    site_requests_worse = sorted(site_requests_worse, reverse=True)
    
    print("Most third party requests as flagged by Disconnect, within " +
        "FingerprintingGeneral, FingerprintingInvasive, and Advertising " +
        "categories:")
    for i in range(5):
        try:
            print("{} requests \t- {}"
                  .format(site_requests_worse[i][0], site_requests_worse[i][1]))
        except IndexError:
            pass
        
    # number of websites on which each parent org appears
    site_parents = []

    for parent in parent_orgs:
        cur.execute('''SELECT parent, COUNT(DISTINCT site_domain) FROM
            results_noimg WHERE parent IS ?''', (parent,))
        # should always only be one result
        result = cur.fetchone()
        site_parents.append([result[1], parent])

    site_parents = sorted(site_parents, reverse=True)
    
    print("Parent company whose scripts appeared on most websites:")
    for i in range(10):
        try:
            print("{} appearances \t- {}"
                  .format(site_parents[i][0], site_parents[i][1]))
        except IndexError:
            pass
        
    site_parents_cat = {}
    for category in site_categories:
        site_parents_cat[category] = []
        for parent in parent_orgs:
            cur.execute('''SELECT parent, COUNT(DISTINCT site_domain) FROM
                results_noimg WHERE parent IS ? AND category IS ?''',
                (parent, category))
            
            # there should be only one results
            result = cur.fetchone()
            
            site_parents_cat[category].append([result[1], parent])
    
        site_parents_cat[category] = sorted(site_parents_cat[category],
            reverse=True)
    
    print("Parent company whose scripts appeared on most websites, categorised:")
    for category in site_parents_cat:
        print("---- {} ----".format(category))
        try:
            for i in range(10):
                print("{} appearances \t- {}"
                    .format(site_parents_cat[category][i][0],
                        site_parents_cat[category][i][1]))
        except IndexError:
            pass
        
    # most common problematic URLs
    trackers = parseDisconnectList()
    tracker_counter = {}
    cur.execute('''SELECT * FROM results_noimg WHERE threat 
        IN ("FingerprintingGeneral", "FingerprintingInvasive", "Advertising")''')
    for result in cur:
        for tracker in trackers:
            if tracker in result['tracker_url']:
                if tracker in tracker_counter:
                    if result['site_domain'] not in tracker_counter[tracker]:
                        tracker_counter[tracker].append(result['site_domain'])  
                else:
                    tracker_counter[tracker] = [result['site_domain']]
    
    counter = []
    for tracker_url in tracker_counter:
        counter.append([len(tracker_counter[tracker_url]), tracker_url])
    
    counter = sorted(counter, reverse=True)
    
    print("{} unique domains in high risk set".format(len(counter)))
    for i in range(20):
        count, domain = counter[i]
        print("{} appearances \t- {}"
            .format(count, domain))
        
    # most common problematic URLs
    trackers = parseDisconnectList()
    tracker_counter = {}
    cur.execute('''SELECT * FROM results_noimg''')
    for result in cur:
        for tracker in trackers:
            if tracker in result['tracker_url']:
                if tracker in tracker_counter:
                    if result['site_domain'] not in tracker_counter[tracker]:
                        tracker_counter[tracker].append(result['site_domain'])  
                else:
                    tracker_counter[tracker] = [result['site_domain']]
    
    counter = []
    for tracker_url in tracker_counter:
        counter.append([len(tracker_counter[tracker_url]), tracker_url])
    
    counter = sorted(counter, reverse=True)
    
    print("{} unique domains in full set".format(len(counter)))
    for i in range(20):
        count, domain = counter[i]
        print("{} appearances \t- {}"
            .format(count, domain))
        
    # most third parties per domain
    tp_list = {}
    cur.execute('''SELECT DISTINCT site_domain, parent FROM results_noimg''')
    for result in cur:
        if result['site_domain'] not in tp_list:
            tp_list[result['site_domain']] = [result['parent']]
        else:
            tp_list[result['site_domain']].append(result['parent'])
    
    tp_counter = []
    for domain in tp_list:
        tp_counter.append([len(tp_list[domain]), domain])
    
    tp_counter = sorted(tp_counter, reverse=True)
    
    for i in range(5):
        tp_count, domain = tp_counter[i]
        tps = tp_list[domain]
        print("{} third parties in {} \t- {}"
            .format(tp_count, domain, tps))
    
    con.close()
