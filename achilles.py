#!/usr/bin/python3
# import sys

# print(sys.argv) # collection of arguements
# print('The first arguement was:'+ sys.argv[1])
import argparse
import requests
import validators

parser = argparse.ArgumentParser(description="The Achilles HTML vulnerability Analyzer version 1.0")
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The Url of the HTML to analyze")

args = parser.parse_args()
# print(args.url)
url = args.url

if (validators.url(url)):
    result_html = requests.get(url).text
    print(result_html)
    # print("That was a good URL")
else:
    print("Invalid URL. Please include full url including https://")
    # print('That wasnt a good URL')



