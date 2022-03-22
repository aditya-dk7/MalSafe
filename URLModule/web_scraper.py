import requests
import urllib.parse
import re
import time 
import sys
import URLModule.sql_vul_check as sql_vul_check
import requests
import queue
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
def print_target_links():
    for i in target_links:
        print(i)

def load_animation(): 

	# String to be displayed when the application is loading 
	load_str = "Scraping Website..."
	ls_len = len(load_str) 


	# String for creating the rotating line 
	animation = "|/-\\"
	anicount = 0
	
	# used to keep the track of 
	# the duration of animation 
	counttime = 0		
	
	# pointer for travelling the loading string 
	i = 0

	while (counttime != 40): 
		
		# used to change the animation speed 
		# smaller the value, faster will be the animation 
		time.sleep(0.085) 
							
		# converting the string to list 
		# as string is immutable 
		load_str_list = list(load_str) 
		
		# x->obtaining the ASCII code 
		x = ord(load_str_list[i]) 
		
		# y->for storing altered ASCII code 
		y = 0							

		# if the character is "." or " ", keep it unaltered 
		# switch uppercase to lowercase and vice-versa 
		if x != 32 and x != 46:			 
			if x>90: 
				y = x-32
			else: 
				y = x + 32
			load_str_list[i]= chr(y) 
		
		# for storing the resultant string 
		res =''			 
		for j in range(ls_len): 
			res = res + load_str_list[j] 
			
		# displaying the resultant string 
		sys.stdout.write("\r"+res + animation[anicount]) 
		sys.stdout.flush() 

		# Assigning loading string 
		# to the resultant string 
		load_str = res 

		
		anicount = (anicount + 1)% 4
		i =(i + 1)% ls_len 
		counttime = counttime + 1
		
                                    		
	
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