import requests
import urllib.parse
import re
import URLModule.sql_vul_check as sql_vul_check
import requests
target_links = []


def extract_links_from(url):
    response = requests.get(url)
    var = response.content.decode('utf-8','ignore')
    value = []
    value = re.findall(r'(?:a href=")(.*?)"', var)
    value = value + re.findall(r"(?:a href=')(.*?)'", var)
    return value

'''
    The flag variable takes in a boolean value to check whether you want to scrape the given page or the complete website
'''	
def scraper(url, flag=False):
    href_links = extract_links_from(url)
    for link in href_links:
        link = urllib.parse.urljoin(url, link)

        if '#' in link:
            link = link.split("#")[0]

        if url in link and link not in target_links:
            target_links.append(link)
            if flag is True:
                scraper(link, flag)

def call_sql_vul_check(myQueue):
    myQueue.put(sql_vul_check.find_error_based_sql(target_links))