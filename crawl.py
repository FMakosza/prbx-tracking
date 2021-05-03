'''
This script is based on the OpenWPM 'demo.py' file.
'''

from pathlib import Path

from openwpm.command_sequence import CommandSequence
from openwpm.commands.browser_commands import GetCommand
from openwpm.config import BrowserParams, ManagerParams
from openwpm.storage.sql_provider import SQLiteStorageProvider
from openwpm.task_manager import TaskManager

def crawl(sites, db_filename):
    '''
    sites ihe list of sites that we wish to crawl
    db_filename is the file name of the output database
    '''
    
    # Loads the default ManagerParams
    # and NUM_BROWSERS copies of the default BrowserParams
    NUM_BROWSERS = 12

    manager_params = ManagerParams(num_browsers=NUM_BROWSERS)
    browser_params = [BrowserParams(display_mode="headless") for _ in range(NUM_BROWSERS)]

    # Update browser configuration (use this for per-browser settings)
    for i in range(NUM_BROWSERS):
        # Record HTTP Requests and Responses
        browser_params[i].http_instrument = True
        # Record cookie changes
        browser_params[i].cookie_instrument = True
        # Record Navigations
        browser_params[i].navigation_instrument = True
        # Record JS Web API calls
        browser_params[i].js_instrument = True
        # Record the callstack of all WebRequests made
        browser_params[i].callstack_instrument = True
        # Record DNS resolution
        browser_params[i].dns_instrument = True
        
        browser_params[i].bot_mitigation = True

    # Update TaskManager configuration (use this for crawl-wide settings)
    manager_params.data_directory = Path("./datadir/")
    manager_params.log_directory = Path("./datadir/")

    # Commands time out by default after 60 seconds
    with TaskManager(
        manager_params,
        browser_params,
        SQLiteStorageProvider(Path("./datadir/{}.sqlite".format(db_filename))),
        None,
    ) as manager:
        # Visits the sites
        for index, site in enumerate(sites):

            def callback(success: bool, val: str = site) -> None:
                print(
                    f"CommandSequence for {val} ran {'successfully' if success else 'unsuccessfully'}"
                )

            # Parallelize sites over all number of browsers set above.
            command_sequence = CommandSequence(
                site,
                site_rank=index,
                reset=True,
                callback=callback,
            )

            # Start by visiting the page
            command_sequence.append_command(GetCommand(url=site, sleep=3), timeout=60)

            # Run commands across the three browsers (simple parallelization)
            manager.execute_command_sequence(command_sequence)
