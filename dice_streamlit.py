import streamlit as st
import json
import time
import uuid
import os
import requests
from loguru import logger
from botasaurus.browser import Wait
from botasaurus.user_agent import UserAgent
from botasaurus.window_size import WindowSize
import string
from botasaurus.browser import browser, Driver
from selenium.webdriver.chrome.service import Service
from chrome_extension_python import Extension
import random
import re
import hashlib
import base64
import psutil
import subprocess
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException


if "driver" not in st.session_state:
    st.session_state.driver = None

if "port" not in st.session_state:
    st.session_state.port = "9225"

if "remote_driver" not in st.session_state:
    st.session_state.remote_driver = None


if "email" not in st.session_state:
    st.session_state.email = "_@gmail.com"

if "password" not in st.session_state:
    st.session_state.password = "_12345"

if "uploaded_file" not in st.session_state:
    st.session_state.uploaded_file = None

if "job_apply_limit" not in st.session_state:
    st.session_state.job_apply_limit = 10

if "job_apply_counter" not in st.session_state:
    st.session_state.job_apply_counter = 0

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-User": "?1",
    "Sec-GPC": "1",
    "Referer": "https://dice.com/",
    "DNT": "1"
}

def file_upload_start(file_path):
    print("in file_upload_start function")
    try:
        file_size = os.path.getsize(file_path)
        print(f"File size: {file_size} bytes")
        file_name = os.path.basename(file_path)
        payload = json.dumps({"filename":str(file_name),"mimetype":"application/pdf","size":int(file_size),"apikey":"AVJmTRZCARKC18a44as05z","store":{"location":"s3","path":"resumes/"}})
        start_headers = {
            'Filestack-Source': 'JS-3.30.2',
            'sec-ch-ua': '"Not;A=Brand";v="24", "Chromium";v="128"',
            'Filestack-Trace-Span': 'jssdk-j9g15FsocI',
            'DNT': '1',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Filestack-Trace-Id': '1725396665-uV5sLd6NTn',
            'sec-ch-ua-platform': '"macOS"',
            'Accept': '*/*',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'host': 'upload.filestackapi.com'
        }

        s = requests.post(f"https://upload.filestackapi.com/multipart/start", headers=start_headers, data=payload)
        print(s.status_code)
        if s.status_code == 200:
            return s.json()
        else:
            raise Exception("Failed to start file upload")
    except Exception as e:
        logger.error(e)
        raise Exception("Failed to start file upload")

def file_upload(filepath, response):
    print("in file_upload function")
    try:
        file_size = os.path.getsize(filepath)
        print(f"File size: {file_size} bytes")


        with open(filepath, 'rb') as f: # Important to read the file here to properly calculate MD5
            file_data_upload = f.read()
        md5_hash = hashlib.md5(file_data_upload).digest()
        base64_encoded_md5 = base64.b64encode(md5_hash).decode('utf-8')
        
        uri = response["uri"]
        region = response["region"]
        upload_id = response["upload_id"]
        
        payload = json.dumps({"apikey":"AVJmTRZCARKC18a44as05z",
                              "uri":str(uri),
                              "upload_id":str(upload_id),
                              "region":str(region),
                              "store":{"location":"s3","path":"resumes/"},
                              "part":1,
                              "size":int(file_size),
                              "md5":base64_encoded_md5
                             })

        upload_headers = {
            'Filestack-Source': 'JS-3.30.2',
            'sec-ch-ua': '"Not;A=Brand";v="24", "Chromium";v="128"',
            'Filestack-Trace-Span': 'jssdk-0889RRi8Y2',
            'DNT': '1',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Filestack-Trace-Id': '1725396666-unu0tYJiB9',
            'sec-ch-ua-platform': '"macOS"',
            'Accept': '*/*',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'host': 'upload-ap-northeast-1.filestackapi.com'
        }

        u = requests.post(f"https://upload-ap-northeast-1.filestackapi.com/multipart/upload", headers=upload_headers, data=payload)
        print(u.status_code)
        if u.status_code == 200:
            return u.json()
        else:
            raise Exception("Failed to file upload")
    except Exception as e:
        logger.error(e)
        raise Exception("Failed to file upload")

def put_file(filepath, response):
    print("in put_file function")
    try:
        url = response["url"]
        headers_putter = response["headers"]
        # with open(filepath, 'rb') as f:
        #     file_data = f.read()
        print("headers_putter: ")
        print(headers_putter)
        print("\n\n\n")


        with open(filepath, 'rb') as f:
            file_data_put = f.read()

        

        p = requests.put(url, headers=headers_putter, data=file_data_put)
        print(p.status_code)
        print(p.text) 
        print("\n\n\n")


        
        if p.status_code == 200:
            return True
        else:
            raise Exception("Failed to put file")
    except Exception as e:
        logger.error(e)
        raise Exception("Failed to put file")

def complete_file_upload(filepath, response):
    print("in complete_file_upload function")
    try:
        file_size = os.path.getsize(filepath)
        fileName = os.path.basename(filepath)
        uri = response["uri"]
        upload_id = response["upload_id"]
        region = response["region"]
        payload = json.dumps({"apikey":"AVJmTRZCARKC18a44as05z","uri":uri,"upload_id":upload_id,"region":region,"store":{"location":"s3","path":"resumes/"},"filename":str(fileName),"mimetype":"application/pdf","size":int(file_size),"parts":[{"part_number":1,"etag":"\"e4a71885536ddeec1832ab034c965cc9\""}]})
        headers_complete = {
            'Filestack-Source': 'JS-3.30.2',
            'sec-ch-ua': '"Not;A=Brand";v="24", "Chromium";v="128"',
            'Filestack-Trace-Span': 'jssdk-X0L036R5c2',
            'DNT': '1',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Filestack-Trace-Id': '1725396670-pSUL08c27H',
            'sec-ch-ua-platform': '"macOS"',
            'Accept': '*/*',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'host': 'upload-ap-northeast-1.filestackapi.com'
        }
        p = requests.post("https://upload-ap-northeast-1.filestackapi.com/multipart/complete", headers=headers_complete, data=payload)
        print(p.status_code)
        if p.status_code == 200:
            return p.json()
        else:
            raise Exception("Failed to complete file upload")
    except Exception as e:
        logger.error(e)
        raise Exception("Failed to complete file upload")

def get_correletion_id(cookies, authorization):
    print("in get_correletion_id function")
    try:
        cookies = cookies
        xlegacyauth = cookies["CMS_Cookie"]
        candidateId = cookies["candidate_id"]
        auth_header = {
            "authorization": f"Bearer {authorization}",
            "x-legacy-auth": xlegacyauth,
            "Content-Type": "application/json"
        }
        query = f"query getCandidate {{\n        retrieveCandidate(candidateId : \"{candidateId}\") {{\n          visibility {{\n            status\n            }}\n          }}\n        }}"
        payload = ({
            "query": query
        })

        r = requests.post(f"https://api.prod.candidate-prod.dhiaws.com/graphql", headers=auth_header, json=payload)
        print(r.status_code)
        if r.status_code == 200:
            #get X-Correlation-Id from the response header
            correlation_id = r.headers["X-Correlation-Id"]
            return correlation_id
        raise Exception("Failed to get correlation id")
    except Exception as e:
        logger.error(e)
        raise Exception("Failed to get correlation id")

def create_document(obj):
    print("in create_document function")
    try:
        container = obj["container"]
        filename = obj["filename"]
        key = obj["key"]
        url = obj["url"]
        candidate_id = obj["candidate_id"]
        job_id = obj["job_id"]
        correlation_id = obj["correlation_id"]
        authorization = obj["authorization"]
        x_legacy_auth = obj["x_legacy_auth"]

        payload = ({
            "operationName": "createApplication",
            "variables": {
                "input": {
                "candidate_id": candidate_id,
                "job_id": job_id,
                "resume": {
                    "filestack": {
                    "container": container,
                    "filename": filename,
                    "key": key,
                    "mime_type": "application/pdf",
                    "url": url
                    }
                },
                "cover_letter": None,
                "screener": None,
                "correlation_id": correlation_id,
                "captchaToken": None
                }
            },
            "query": "mutation createApplication($input: ApplicationInput!) {\n  createApplication(input: $input) {\n    application_id\n    __typename\n  }\n}\n"   
        })

        create_document_headers = {
            'sec-ch-ua': '"Not;A=Brand";v="24", "Chromium";v="128"',
            'DNT': '1',
            'sec-ch-ua-mobile': '?0',
            'Authorization': authorization,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'content-type': 'application/json',
            'accept': '*/*',
            'x-legacy-auth': x_legacy_auth,
            'sec-ch-ua-platform': '"macOS"',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'host': 'api.prod.jobapplication-prod.dhiaws.com'
        }

        c = requests.post(f"https://api.prod.jobapplication-prod.dhiaws.com/graphql", headers=create_document_headers, json=payload)
        print(c.status_code)
        if c.status_code == 200:
            return c.json()
        else:
            return None
    except Exception as e:
        logger.error(e)
        return None
    
def are_there_any_questions(cookies, authorization, jobid):
    print("in are_there_any_questions function")
    try:
        cookies = cookies
        xlegacyauth = cookies["CMS_Cookie"]

        auth_header = {
            "authorization": authorization,
            "x-legacy-auth": xlegacyauth,
            "Content-Type": "application/json"
        }

        payload = ({
        "operationName": "retrieveJob",
        "variables": {
            "jobId": jobid
        },
        "query": "query retrieveJob($jobId: ID!) {\n  retrieveJob(jobId: $jobId) {\n    id\n    remote\n    recruiter_id\n    company {\n      id\n      name\n      url\n      logo_url\n      __typename\n    }\n    position {\n      id\n      title\n      url\n      __typename\n    }\n    location {\n      city\n      state\n      country\n      __typename\n    }\n    screener {\n      title\n      id\n      customerId\n      description\n      shared\n      questions {\n        displayPosition\n        text\n        scores\n        answers\n        type\n        choiceAnswerOption\n        __typename\n      }\n      __typename\n    }\n    ofccp_questions {\n      question\n      answers\n      __typename\n    }\n    __typename\n  }\n}\n"
        })

        r = requests.post(f"https://api.prod.jobapplication-prod.dhiaws.com/graphql", headers=auth_header, json=payload)
        print(r.status_code)
        if r.status_code == 200:
            applied = r.json()["data"]["retrieveJob"]["screener"]
            if applied:
                logger.info(f"Job Has Additional Questions: {jobid}")
                return False
            else:
                logger.info(f"Job is suitable! {jobid}")
                return True
        return False
    except Exception as e:
        logger.error(e)
        return False

def is_applied(cookies, authorization, jobid):
    print("in is_applied function")
    try:
        cookies = cookies
        xlegacyauth = cookies["CMS_Cookie"]
        candidateId = cookies["candidate_id"]

        auth_header = {
            "authorization": authorization,
            "x-legacy-auth": xlegacyauth,
            "Content-Type": "application/json"
        }

        payload = ({
  "query": "\n            query candidateAppliedToJob($jobId: ID!, $candidateId: ID!) {\n              candidateAppliedToJob(jobId: $jobId, candidateId: $candidateId) {\n                applied,\n                applied_date\n              }\n            }\n          ",
  "variables": {
      "jobId": str(jobid),
      "candidateId": str(candidateId)
  }
})

        r = requests.post(f"https://api.prod.jobapplication-prod.dhiaws.com/graphql", headers=auth_header, json=payload)
        print(r.status_code)
        if r.status_code == 200:
            applied = r.json()["data"]["candidateAppliedToJob"]["applied"]
            if applied:
                logger.info(f"Job is applied: {jobid}")
                return False
            else:
                logger.info(f"Job is not applied: {jobid}")
                return True
        return False
    except Exception as e:
        logger.error(e)
        return False

def easy_apply(driver):
    print("in easy_apply function")
    try:
        st.session_state.driver.save_screenshot(f"easy_apply.png")
        st.session_state.driver.save_screenshot(f"easy_apply_2.png")
        nextBtn = st.session_state.driver.get_element_with_exact_text("Next", wait=Wait.VERY_LONG)
        if nextBtn:
            st.session_state.driver.wait_for_element("button.seds-button-primary.btn-next", wait=Wait.VERY_LONG).click()
        st.session_state.driver.save_screenshot(f"easy_apply_3.png")
        submitBtn = st.session_state.driver.get_element_with_exact_text("Submit", wait=Wait.VERY_LONG)
        st.session_state.driver.save_screenshot(f"easy_apply_4.png")
        if submitBtn:
            st.session_state.driver.wait_for_element("button.seds-button-primary.btn-next", wait=Wait.VERY_LONG).click()
            return True
        else:
            return False
    except:
        return False
    
# def get_jobs(apikey, query):
#     try:
#         headers["x-api-key"] = apikey
#         whole_arr = []
#         count = 0
#         while True:
#             count += 1
#             r = requests.get(f"https://job-search-api.svc.dhigroupinc.com/v1/dice/jobs/search?q={query}&countryCode2=US&radius=30&radiusUnit=mi&page={count}&pageSize=20&facets=employmentType%7CpostedDate%7CworkFromHomeAvailability%7CworkplaceTypes%7CemployerType%7CeasyApply%7CisRemote%7CwillingToSponsor&fields=id%7CjobId%7Cguid%7Csummary%7Ctitle%7CpostedDate%7CmodifiedDate%7CjobLocation.displayName%7CdetailsPageUrl%7Csalary%7CclientBrandId%7CcompanyPageUrl%7CcompanyLogoUrl%7CcompanyLogoUrlOptimized%7CpositionId%7CcompanyName%7CemploymentType%7CisHighlighted%7Cscore%7CeasyApply%7CemployerType%7CworkFromHomeAvailability%7CworkplaceTypes%7CisRemote%7Cdebug%7CjobMetadata%7CwillingToSponsor&culture=en&recommendations=true&interactionId=0&fj=true&includeRemote=true", headers=headers)
#             if r.status_code == 200:
#                 whole_arr.extend(r.json()['data'])
#             else:
#                 break
#             if count == 500:
#                 break
#         return whole_arr
#     except:
#         return None


def get_jobs(apikey, query):
    print("in get_jobs function")
    try:
        headers["x-api-key"] = apikey  # Set API key in headers
        whole_arr = []  # Initialize empty list to store job data
        count = 0  # Page counter
        while True:
            count += 1
            logger.info(f"Fetching page {count}...")  # Log page number
            r = requests.get(  # Make request to Dice API with timeout
                f"https://job-search-api.svc.dhigroupinc.com/v1/dice/jobs/search?q={query}&countryCode2=US&radius=30&radiusUnit=mi&page={count}&pageSize=20&facets=employmentType%7CpostedDate%7CworkFromHomeAvailability%7CworkplaceTypes%7CemployerType%7CeasyApply%7CisRemote%7CwillingToSponsor&fields=id%7CjobId%7Cguid%7Csummary%7Ctitle%7CpostedDate%7CmodifiedDate%7CjobLocation.displayName%7CdetailsPageUrl%7Csalary%7CclientBrandId%7CcompanyPageUrl%7CcompanyLogoUrl%7CcompanyLogoUrlOptimized%7CpositionId%7CcompanyName%7CemploymentType%7CisHighlighted%7Cscore%7CeasyApply%7CemployerType%7CworkFromHomeAvailability%7CworkplaceTypes%7CisRemote%7Cdebug%7CjobMetadata%7CwillingToSponsor&culture=en&recommendations=true&interactionId=0&fj=true&includeRemote=true",
                headers=headers,
                timeout=30  # Set a 30-second timeout for the request
            )
            if r.status_code == 200: #Handles successfull request
                logger.info(f"Received {len(r.json()['data'])} jobs on page {count}")
                whole_arr.extend(r.json()['data']) #Append all retrieved jobs to the list
            elif r.status_code == 429:  # "Too Many Requests" - Rate limited
                retry_after = int(r.headers.get('Retry-After', 30)) #Get retry-after value from header, or default to 30
                logger.warning(f"Rate limited! Retrying after {retry_after} seconds...")
                time.sleep(retry_after) #Sleep
                continue  # Retry the request after the specified delay

            else:  # Other non-200 status codes (errors)
                logger.warning(f"Request failed with status code {r.status_code}: {r.text}")  # Log error with response text
                break  # Exit loop on error (or implement more sophisticated error handling)

            if count == 500: #Stop after 500 pages
                break
        logger.info(f"Finished fetching jobs. Total jobs: {len(whole_arr)}")  # Log total jobs fetched
        return whole_arr #Return list

    except requests.exceptions.Timeout as e: #Handles request timeout
        logger.error(f"Request timed out: {e}")
        return None

    except Exception as e:  # Catches any other exception during API interaction or JSON processing
        logger.error(f"Error in get_jobs: {e}")
        return None  # Return None on error



def get_api_key(url):
    print("in get_api_key function")
    try:
        
        r = requests.get(url, headers=headers, timeout = 30)
        if r.status_code == 200:
            return r.text.split("apiKey: \'")[1].split("\'")[0]
        else:
            return None
    except:
        return None

def get_details(driver):
    print("in get_details function")
    page_html = st.session_state.driver.page_html
    script_tag = find_script_tag(page_html)
    if script_tag:
        logger.info(f"Found script tag: {script_tag}")
        api_key = get_api_key(script_tag)
        if api_key:
            logger.info(f"Found api key: {api_key}")
            data = get_jobs(api_key, "mulesoft")
            if data:
                logger.info(f"Found jobs: {len(data)}")
                return data
            raise Exception("Failed to get jobs")
        else:
            logger.error(f"Api key not found")
    else:
        logger.error(f"Script tag not found")
    raise Exception("Failed to get script tag")

def find_script_tag(html):
    print("in find_script_tag function")
    try:
        pattern = r'<script src="https://[a-zA-Z0-9]+\.cloudfront\.net/config/environment\.js"></script>'
        match = re.search(pattern, html)
        
        if match:
            return match.group().split("\"")[1].split("\"")[0]
        else:
            return None
    except:
        return None
    
def random_true_false():
    print("in random_true_false function")
    return random.random() < 0.145

def generate_random_string(length=8):
    print("in generate_random_string function")
    letters = string.ascii_letters  # Includes both lowercase and uppercase letters
    return "".join(random.choice(letters) for _ in range(length))

# Function to perform random scrolling
def random_scroll(driver, direction="down"):
    print("in random_scroll function")
    logger.info(f"Scrolling direction: {direction}")
    # Get the total height of the page
    total_height = st.session_state.driver.run_js("return document.body.scrollHeight")

    if direction == "down":
        # Scroll down to the bottom in random speed
        current_position = 0
        while current_position < total_height:
            # Random delay
            time.sleep(random.uniform(1.0, 2.0))
            # Scroll down by a random amount
            scroll_amount = random.randint(200, 500)
            st.session_state.driver.run_js(f"window.scrollBy(0, {scroll_amount})")
            current_position += scroll_amount
    else:
        # Scroll up to the top in random speed
        current_position = total_height
        while current_position > 0:
            # Random delay
            time.sleep(random.uniform(1.0, 2.0))
            # Scroll up by a random amount
            scroll_amount = random.randint(200, 500)
            st.session_state.driver.run_js(f"window.scrollBy(0, -{scroll_amount})")
            current_position -= scroll_amount

port = "9225"

def open_chrome_debugging_window(port):
    print("in open_chrome_debugging_window function")
    chrome_command = [
        "C:/Program Files/Google/Chrome/Application/chrome.exe",  # Update if needed
        f"--remote-debugging-port={port}",
        f"--user-data-dir=C:/chrome-debug-{port}"  # Create this directory manually
    ]
    if not is_chrome_open(port):
        subprocess.Popen(chrome_command) 
        time.sleep(10)  # Give Chrome time to start
    else:
        print(f"Chrome is already running with debugging port {port}")

def is_chrome_open(port):
    print("in is_chrome_open function")
    for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        try:  # Handle processes that might not have cmdline
            if process.info['name'] == 'chrome.exe' or process.info['name'] == 'chrome': # For cross platform support
                if f"--remote-debugging-port={port}" in process.info['cmdline']:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
             continue  # Ignore exceptions and keep checking other processes
    return False


# def login_to_dice(remote_driver, email_str, password_str):
#     remote_driver.get("https://www.dice.com/dashboard/login")
#     email_element = remote_driver.find_element("name", "email")
#     email_element.send_keys(email_str)
#     email_button_element = remote_driver.find_element("xpath", "//*[@data-testid='sign-in-button']")
#     email_button_element.click()
#     time.sleep(5)
#     password_field = remote_driver.find_element("name", "password")
#     password_field.send_keys(password_str)
#     sign_in_button = remote_driver.find_element("xpath", "//*[@data-testid='submit-password']")
#     sign_in_button.click()
#     time.sleep(20)
    

def take_screenshot(email, pw, url="https://www.dice.com/home/home-feed"):
    print("in take_screenshot function")
    open_chrome_debugging_window(port)  # Your function to open Chrome in debug mode

    chrome_options = Options()
    chrome_options.debugger_address = f"localhost:{port}"
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')

    st.session_state.remote_driver = webdriver.Chrome(service=Service(), options=chrome_options)


    # driver = webdriver.Chrome(service=Service(), options=chrome_options)
    
    # @browser(
    #     headless=True,
    #     user_agent=UserAgent.HASHED,
    #     window_size=WindowSize.HASHED,
    #     raise_exception=True,
    #     close_on_crash=True,
    #     tiny_profile=True,
    #     profile=str(email),
    #     extensions=[
    #         Extension(
    #             "https://chromewebstore.google.com/detail/webrtc-leak-shield/bppamachkoflopbagkdoflbgfjflfnfl"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/spoof-timezone/kcabmhnajflfolhelachlflngdbfhboe"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/random-user-agent-switche/einpaelgookohagofgnnkcfjbkkgepnp"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/canvas-blocker-fingerprin/nomnklagbgmgghhjidfhnoelnjfndfpd?hl=en"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/font-fingerprint-defender/fhkphphbadjkepgfljndicmgdlndmoke?hl=en"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/webgl-fingerprint-defende/olnbjpaejebpnokblkepbphhembdicik"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/audiocontext-fingerprint/pcbjiidheaempljdefbdplebgdgpjcbe"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/clientrects-fingerprint-d/niphfcamineobpiggefmngniahlpipah"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/clientrects-fingerprint-d/niphfcamineobpiggefmngniahlpipah"
    #         ),
    #         Extension(
    #             "https://chromewebstore.google.com/detail/webgpu-fingerprint-defend/kadocklfjjaaekpjhmpbkbjkhloacing"
    #         ),
    #     ],
    # )
    # @browser(driver=webdriver.Chrome(service=Service(executable_path="C:/chromedriver-win64/chromedriver.exe"), options=chrome_options), raise_exception=True) 
    # @browser(driver=webdriver.Chrome(service=Service(), options=chrome_options), raise_exception=True)
    
    # def get_heading_from_driver(driver: Driver, data: str):

    @browser(raise_exception=True)
    def get_heading_from_driver(driver: Driver, data: str, email=st.session_state.email, pw=st.session_state.password, url=url):
    # def get_heading_from_driver(driver: Driver, data: str, email=email, pw=pw, url=url, remote_driver=remote_driver):
    
        # driver.attach(driver)
        try:
            # print user agent
            st.session_state.driver = driver
            logger.info(f"User Agent: {st.session_state.driver.user_agent}")


            #login part

            # driver.get("https://www.dice.com/dashboard/login")
            # driver.type("input[name='email']", email)
            # driver.click("button[type='submit']")
            # email_element = driver.find_element("name", "email")
            # email_element.send_keys(email_str)
            # email_button_element = driver.find_element("xpath", "//*[@data-testid='sign-in-button']")
            # email_button_element.click()
            # time.sleep(5)
            # password_field = driver.find_element("name", "password")
            # password_field.send_keys(password_str)
            # sign_in_button = driver.find_element("xpath", "//*[@data-testid='submit-password']")
            # sign_in_button.click()
            # time.sleep(20)

            st.session_state.driver.google_get("https://www.dice.com/dashboard/login")

            dice_email = st.session_state.email
            dice_password = st.session_state.password

            st.session_state.driver.type("input[name='email']", dice_email)
            print("c1")
            # driver.click("xpath", "//*[@data-testid='sign-in-button']")  # Use XPath for the button
            # driver.click("xpath", "//*[@data-testid='sign-in-button']")  # Use XPath for the button
            # signin_element = driver.wait_for_element("data-testid", "sign-in-button")
            signin_element = st.session_state.driver.wait_for_element("button[data-testid='sign-in-button']", 5)
            print("c2")
            signin_element.click()
            print("c3")
            
            # pw_element = driver.wait_for_element("name", "password", wait=20) # Use botasaurus wait
            # pw_element = driver.wait_for_element("name", "password") # Use botasaurus wait
            pw_element = st.session_state.driver.wait_for_element("input[name='password']", 5)
            print("c4")
            time.sleep(10)
            
            pw_element.type(dice_password)  # Use .type() on the element, not driver.type
            print("c5")
    
            # submit_button = driver.wait_for_element("xpath", "//*[@data-testid='submit-password']", wait=5) # Use botasaurus wait
            # submit_button = driver.wait_for_element("xpath", "//*[@data-testid='submit-password']") # Use botasaurus wait
            # submit_button = driver.wait_for_element("data-testid", "submit-password")
            submit_button = st.session_state.driver.wait_for_element("button[data-testid='submit-password']", 5)
            print("c6")
            time.sleep(10)
            
            submit_button.click() #Use .click() on the element
            time.sleep(20)
    
            # Add an explicit wait for an element that appears *after* successful login
            # driver.wait_for_element(".profile-overview-section", wait=20) # Wait for an element that confirms login
            # driver.wait_for_element(".profile-overview-section") # Wait for an element that confirms login
            print("c7")
            


        
            
            st.session_state.driver.google_get(url)
            remote_cookies = st.session_state.remote_driver.get_cookies() 
            for cookie in remote_cookies:
                st.session_state.driver.add_cookie(cookie)
            cookies = st.session_state.driver.get_cookies_dict()
            try:
                # cookies = driver.get_cookies_dict()
                authorization = cookies["access"] 
                
            except:
                authorization = None

            dice_email = st.session_state.email
            dice_password = st.session_state.password
            # login_to_dice(remote_driver, dice_email, dice_password)
                
            data = get_details(st.session_state.driver) 
            
            st.session_state.driver.save_screenshot(f"{email}.png")
            if data:
                return data, authorization, cookies
            #clear cookies
            st.session_state.driver.google_get("https://www.dice.com/dashboard/login?redirectURL=/home/home-feed")
            #enter email
            #t.a.yah.s.chw.a.rz2.57@googlemail.com
            st.session_state.driver.type("input[name='email']", email)
            #click submit
            st.session_state.driver.click("button[type='submit']")
            for i in range(3):
                try:
                    pw_element = st.session_state.driver.wait_for_element("input[name='password']", wait=Wait.VERY_LONG)
                    break
                except:
                    pass
            if pw_element:
                #enter password
                st.session_state.driver.type("input[name='password']", pw)
                #click submit
                st.session_state.driver.click("button[type='submit']")
                
                for i in range(5):
                    try:
                        cookies = st.session_state.driver.get_cookies_dict()
                        authorization = cookies["access"]
                        second_data = get_details(st.session_state.driver)
                        return second_data, authorization, cookies
                    except:
                        second_data = None
                        time.sleep(1)

                if second_data:
                    return second_data, authorization, cookies

            return None, None, None
        except Exception as e:
            logger.error(f"Error taking screenshot for link {url}: {e}")
            raise e

    # return get_heading_from_driver()
    return get_heading_from_driver(email=st.session_state.email, pw=st.session_state.password, url=url)

# def process_data(data, authorization, cookies, img_obj):
#     for job in data:
#         is_it_easy = job['easyApply']
#         if is_it_easy:
#             isApplied = is_applied(cookies, authorization, job['guid'])
#             areThereAny = False
#             if isApplied:
#                 areThereAny = are_there_any_questions(cookies, authorization, job['guid'])
#             if isApplied and areThereAny:
#                 logger.info(f"Job is easy apply: {job['title']}")
#                 logger.info(f"{job['detailsPageUrl']}")
#                 logger.info(f"Job is not applied: {job['title']}")
#                 correltion_id = get_correletion_id(cookies, authorization)
#                 img_obj['candidate_id'] = cookies["candidate_id"]
#                 img_obj['job_id'] = job['guid']
#                 img_obj['correlation_id'] = correltion_id
#                 img_obj['authorization'] = authorization
#                 img_obj['x_legacy_auth'] = cookies["CMS_Cookie"]

#                 c_r = create_document(img_obj)
#                 logger.info(c_r)
#             else:
#                 logger.info(f"Job is applied: {job['title']}")
#                 continue
#             break
#     return data

def process_data(data, authorization, cookies, img_obj):
    print("in process_data function")
    applied_jobs_df = pd.DataFrame(columns=["Job Title", "Application Status"]) # Create an empty DataFrame

    for job in data:  # Iterate through each job in the data
        is_it_easy = job['easyApply'] # Check if the job is an "easy apply" type
        if is_it_easy: # If it's an easy apply job
            try: #Handles potential exceptions during the application process
                isApplied = is_applied(cookies, authorization, job['guid'])  # Check if the job has already been applied for
                areThereAny = False # Initialize a flag to check for additional questions (False initially)
                if isApplied: # If the job hasn't been applied to yet
                    areThereAny = are_there_any_questions(cookies, authorization, job['guid'])  # Check for additional questions
                if isApplied and areThereAny:  # Proceed only if not applied, easy apply, and no additional questions
                    st.session_state.job_apply_counter = st.session_state.job_apply_counter + 1
                    
                    logger.info(f"Job is easy apply: {job['title']}")  # Log
                    logger.info(job['detailsPageUrl'])  # Log the job details URL
                    logger.info(f"Job is not applied: {job['title']}")  # Log
                    correltion_id = get_correletion_id(cookies, authorization) #Gets correlation ID
                    img_obj['candidate_id'] = cookies["candidate_id"] #Gets candidate ID from cookie
                    img_obj['job_id'] = job['guid']  # Get the job GUID
                    img_obj['correlation_id'] = correltion_id  # Set correlation ID
                    img_obj['authorization'] = authorization  # Set authorization token
                    img_obj['x_legacy_auth'] = cookies["CMS_Cookie"]  # Set legacy auth token
                    c_r = create_document(img_obj)  # Attempt to create/submit application
                    logger.info(c_r)  # Logs response
                    if c_r and c_r.get("data") and c_r["data"].get("createApplication") and c_r["data"]["createApplication"].get("application_id"):  #Check if the application was successfully created. This check should be adapted to the format of a successful response from the API. If the format changes, change the check as well.
                        logger.info(f"Successfully applied for: {job['title']}")
                        new_row = pd.DataFrame({"Job Title": [job["title"]], "Application Status": ["Job applied"]}) #Adds the information for the successfully applied job to the DataFrame
                        applied_jobs_df = pd.concat([applied_jobs_df, new_row], ignore_index=True) #Concatenates the dataframes
                        applied_jobs_df.to_excel("applied_jobs.xlsx", index=False)  # Save to Excel. The file is overwritten every time a job is applied successfully. Consider changing this to appending instead of overwriting.
                    else: #Handles an unsuccessfull application attempt
                        logger.error(f"Failed to apply for: {job['title']}. Response: {c_r}")  # Log error with response details. Useful for debugging
                        # ... (Optional: Implement handling for failed applications, like retrying, storing error details, etc.)

                    if st.session_state.job_apply_counter >= st.session_state.job_apply_limit:
                        break  # Exit loop after one application attempt or error. Remove this 'break' if you want to apply to all suitable jobs.
                else: #Handles cases in which the job has already been applied for, or it has additional questions
                    logger.info(f"Job is applied or not suitable: {job['title']}") #Logs message. The message is not strictly correct, since the job is simply "not suitable" if it has additional questions but hasn't been applied for.
            except Exception as e: #Handles exceptions during the application process.
                logger.error(f"Error during application process: {e}")
                # ... (Handle application error appropriately, e.g., log, retry, or skip)
            
    return data


# def main():
#     print("in main function")
#     # start = time()
#     # print(f"Started at {start}")
#     resume_str = str(input("Enter the name of the file of your Resume to be uploaded: "))
#     res1 = file_upload_start(resume_str)
#     res = file_upload(resume_str, res1)
#     res = put_file(resume_str, res)
#     res = complete_file_upload(resume_str, res1)
#     data, authorization, cookies = take_screenshot("t.a.yah.s.chw.a.rz2.57@googlemail.com", "3`4=4\"OYLt0g")
#     final = process_data(data, authorization, cookies, res)
#     print(len(final))
#     # end = time()
#     # print(f"Ended at {end}")
#     # print(f"Total time taken: {end - start}")

# if __name__ == "__main__":
#     print("in __main__ function")
#     main()


st.title("Dice Job Application Automation")  # Title of page
st.write("Enter Dice account credentials and select resume file.")

# Folder to store resumes
uploads_dir = "uploaded_resumes"
os.makedirs(uploads_dir, exist_ok=True)  # Create folder if it doesn't exist


with st.form("dice_credentials"):  # Streamlit form for input
    st.session_state.email = st.text_input("Dice Email")
    st.session_state.password = st.text_input("Dice Password", type="password") #Hide password characters
    st.session_state.job_apply_limit = st.text_input("Max number of jobs to apply for: ")
    st.session_state.uploaded_file = st.file_uploader("Choose a Resume (PDF)", type="pdf")  # File uploader
    submit_button = st.form_submit_button(label='Submit') #Submit button

# if submit_button:  # Check if the form has been submitted

#     if uploaded_file is not None:  # Checks if file was uploaded correctly
#         file_path = os.path.join(uploads_dir, uploaded_file.name)  #Defines the path where the file will be stored
#         with open(file_path, "wb") as f:  # Saves file to specified path
#             f.write(uploaded_file.getbuffer()) #Writes the file content. It overwrites the file if it already exists
#         st.success(f"File '{uploaded_file.name}' uploaded successfully!")  #Confirmation message

#         try: #Wraps all following code in a try-except block to handle and print any exception to the Streamlit page
#             start_time = time.time()  #Start time
#             # ... (Filestack upload functions remain the same. Pass 'file_path' to 'file_upload_start')

#             res1 = file_upload_start(file_path)  #Initiates the multipart file upload
#             res = file_upload(file_path, res1)  # Uploads the file data
#             res = put_file(file_path, res)  # Sends file content
#             res = complete_file_upload(file_path, res1)  # Completes file upload
#             # ... (take_screenshot remains the same, passing 'email' and 'password')
#             data, authorization, cookies = take_screenshot(email, password) # Performs the login and scraping, and returns data from Dice using the credentials entered on the Streamlit page
#             # ... (process_data remains the same)
#             final = process_data(data, authorization, cookies, res) #Processes data and applies to jobs
#             # ... (Prints len(final), end time, execution time). Can be displayed on Streamlit
#             print(len(final)) #Can be displayed on the Streamlit app
#             end_time = time.time()
#             print(f"Ended at {end_time}") #Can be displayed on the streamlit app
#             print(f"Total time taken: {end_time - start_time}") #Can be displayed on the streamlit app

#         except Exception as e:  # Handles exceptions
#             logger.exception(e)  # Logs the exception
#             st.error(f"An error occurred: {e}") # Display error on Streamlit
#     else: #Handles cases when the file has not been uploaded successfully
#         st.error("Please upload a resume (PDF file).")


if submit_button:  # Check if the form has been submitted
    st.session_state.job_apply_limit = int(st.session_state.job_apply_limit)
    if st.session_state.uploaded_file is not None:  # Checks if file was uploaded correctly
        file_path = os.path.join(uploads_dir, st.session_state.uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(st.session_state.uploaded_file.getbuffer())
        st.success(f"File '{st.session_state.uploaded_file.name}' uploaded successfully!")

        try:
            start_time = time.time()

            res1 = file_upload_start(file_path)
            res = file_upload(file_path, res1)
            res = put_file(file_path, res)
            res = complete_file_upload(file_path, res1)

            data, authorization, cookies = take_screenshot(st.session_state.email, st.session_state.password) #Use session state variables

            final = process_data(data, authorization, cookies, res)
            st.write(f"Number of jobs processed: {len(final)}") # Display on Streamlit
            end_time = time.time()
            st.write(f"Ended at {end_time}")  # Display on Streamlit
            st.write(f"Total time taken: {end_time - start_time}")  # Display on Streamlit

        except Exception as e:
            logger.exception(e)
            st.error(f"An error occurred: {e}")
    else:
        st.error("Please upload a resume (PDF file).")