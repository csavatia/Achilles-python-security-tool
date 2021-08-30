#!/usr/bin/python3
import argparse
import requests
import validators
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment
import yaml

parser = argparse.ArgumentParser(description="The Achilles HTML vulnerability Analyzer version 1.0")
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The Url of the HTML to analyze")
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o','--output', help='Report file output path')

args = parser.parse_args()
url = args.url

config = {'forms': True, 'comments': True, 'passwords': True}
if (args.config):
    print('Using config file: ' + args.config)
    config_file = open(args.config, 'r')
    # config = yaml.load(config_file)
    config_from_file = yaml.load(config_file)
    if(config_from_file):
        # config = config_from_file
        config = {**config, **config_from_file}


report = ''

if (validators.url(url)):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')
    # print(parsed_html.find_all('form')) # findsany html element
    forms = (parsed_html.find_all('form')) # findsany html element
    comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
    password_inputs = parsed_html.find_all('input', {'name':'password'})
    # print(parsed_html.title)

    if(config['forms']):
        for form in forms:
            if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'htpps')):
                # form_is_secure = False
                # print(form_is_secure)
                report += 'Form Issue: Insecure form action ' + form.get('action') + ' found in document\n'
    
    if(config['comments']):
        for comment in comments:
            if(comment.find('key: ') > -1):
                report += 'Comment Issuee: Key is found in the HTML comments, please remove\n '
    
    if(config['passwords']):
        for password_input in password_inputs:
            if(password_input.get('type') != 'password'):
                report += 'Input Issue: Plaintext password input found. Please change to password type input\n'

else:
    print("Invalid URL. Please include full url including https://")

if(report == ''):
    # print('Nice Job! your HTML document is secure')
    report += 'Nice Job! your HTML document is secure \n'
else:
    header = 'Vulnerability report is as follows: \n'
    header += '===========================================================\n\n'
    report = header + report
    # print('Vulnerability Report is as follows:')
    # report +='Vulnerability Report is as follows:'
    # print('===========================================================\n')
    # report +='===========================================================\n'
    # print(report)
print(report)

if(args.output):
    # print(args.output)
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print('Report saved to: ' + args.output)