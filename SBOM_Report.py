from blackduck import Client
from datetime import datetime
import sys
import os
import requests
import argparse
import time
import logging
import zipfile

# Configuration:
BLACK_DUCK_URL = "https://solidigm.app.blackduck.com"


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def connect_blackduck(api_token):
    """Establish connection to Black Duck."""
    try:
        bd = Client(
            base_url=BLACK_DUCK_URL,
            token=api_token,
            timeout=60.0,
            verify=True
        )
        logger.info("Connected to Black Duck successfully!")
        return bd
    except Exception as e:
        logger.error(f"Error connecting to Black Duck: {e}")
        sys.exit(1)


#Create Project
def create_project(bd, project_name, description=None):
    """Create a new project in Black Duck."""
    project_data = {
        'name': project_name,
        'description': description,
        'projectLevelAdjustments': True,
    }
    try:
        r = bd.session.post("/api/projects", json=project_data)
        r.raise_for_status()
        logger.info(f"Created project: {r.links['project']['url']}")
    except requests.HTTPError as err:
        logger.error(f"Error creating project: {err}")
        sys.exit(1)

#Get Project ID

def get_project(bd, project_name):

    projects = bd.get_resource("projects", params={"q": f"name:{project_name}"})
    
    for project in projects:
        if project.get("name") == project_name:           
            logger.info(f"Found project: {project.get('name')}")
            project_id = project.get("_meta")['href'].split('/')[-1]
            return project, project_id
    logger.error(f"Project '{project_name}' not found.")
    sys.exit(1)



#Get Version ID
def get_version(bd, project, version_name=None):
    """Retrieve a project version by name or default to the latest version."""
    versions = list(bd.get_resource("versions", parent=project))
    if versions:
        if version_name:
            version = next((v for v in versions if v['versionName'] == version_name), None)
        else:
            version = versions[0]

        if version:
           # logger.info(f"Found version: {version}")

            version_id = version["_meta"]["href"].split("/")[-1]  
            logger.info(f"Version ID: {version_id}")
            return {"id": version_id, "versionName": version['versionName']}  
        else:
            logger.error(f"Version '{version_name}' not found.")
            sys.exit(1)
    else:
        logger.error("No versions found for the project.")
        sys.exit(1)

#create Report from version and project name
def create_sbom_report(bd, project_id, version_id):
    """Create an SBOM report for the given project version."""
    url = f"/api/projects/{project_id}/versions/{version_id}/sbom-reports"
    
    headers = {
        'Accept': 'application/json',          
    }
    payload = {
        "reportFormat": "JSON", 
        "sbomType": "SPDX_23",  
    }
    try:
        response = bd.session.post(url, headers=headers, json=payload)
        rep_status = response.raise_for_status()

        if response.status_code == 201:
            try:        
                # Retrieve and log the Location header
                location = response.headers.get('Location')
                report_id = location.split("/")[-1]
                logger.info(f"Report_id : {report_id}")

                logger.info("Please Wait SBOM report generating....")
                #waiting for creating report. If need increase more seconds
                time.sleep(30)
                
                return report_id
            except requests.exceptions.JSONDecodeError:
                logger.error("Failed to decode the response as JSON")
                return None

    except requests.exceptions.HTTPError as err:
        logger.error(f"HTTP error occurred while creating SBOM report: {err}")
        if err.response:
            logger.error(f"Error response content: {err.response.text}")
        return None  
    
    except requests.exceptions.RequestException as err:
        logger.error(f"Error occurred while sending the request to create SBOM report: {err}")
        return None  
    
    except Exception as e:
        logger.error(f"Unexpected error while creating SBOM report: {e}")
        return None  


def get_sbom_report_name(bd, project_id: str, version_id: str, reportId: str):
    """Retrieve the list of SBOM reports for the given project version."""
    url = f"/api/projects/{project_id}/versions/{version_id}/reports/{reportId}"
    
    headers = {
        'Accept': 'application/vnd.blackducksoftware.report-4+json', 
    }

    response = bd.session.get(url, headers=headers)
    response.raise_for_status()

    report_list = response.json()
    logger.debug(f"Response content: {report_list}")
    
    reports = report_list.get("fileName")

    logger.debug(f"Retrieved {len(reports)} SBOM reports.")

    return reports



def download_sbom_report(bd, project_id: str, version_id: str, report_id: str):
    # Download the latest report
    download_url = f"/api/projects/{project_id}/versions/{version_id}/reports/{report_id}/download"
    print("Starting download...")

    try:
        response = bd.session.get(download_url)
        response.raise_for_status()

        filename = get_sbom_report_name(bd, project_id, version_id, report_id)
        logger.info(f"SBOM report created successfully. Report filename: {filename}")

        if response.content:
            with open(filename, 'wb') as file:
                file.write(response.content)
            print(f"Report downloaded successfully as '{filename}'.")
            return filename
        else:
            print("Download failed: No content in the response.")

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")
    

#extract the report and save the .Json file on current working folder
def extract_and_flatten(zip_file_path, extract_to_folder=None):
    try:
        if extract_to_folder is None:
            extract_to_folder = os.getcwd()

        if not os.path.exists(extract_to_folder):
            os.makedirs(extract_to_folder)

        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for file in zip_ref.namelist():
                file_name = os.path.basename(file)

                if file_name:
                    zip_ref.extract(file, extract_to_folder)

                    extracted_file_path = os.path.join(extract_to_folder, file_name)

                    os.rename(os.path.join(extract_to_folder, file), extracted_file_path)
                    print(f"Extracted and moved {file} to {extracted_file_path}")

    except zipfile.BadZipFile:
        print(f"Error: The file {zip_file_path} is not a valid ZIP archive.")
    except Exception as e:
        print(f"Error during extraction: {e}")

#main funtion 
def main():

    parser = argparse.ArgumentParser(description="Interact with Black Duck API.")
    parser.add_argument('--api_token', required=True, help='API Token for Black Duck')
    parser.add_argument('--project_name', required=True, help='Name of the project')
    parser.add_argument('--create_project', action='store_true', help='Create a new project')
    parser.add_argument('--description', help='Description for the new project')
    parser.add_argument('--version', help='Version of the project (optional)')
    parser.add_argument('--create_report', action='store_true',help='Create new report (optional)')

    args = parser.parse_args()
    #connecting blackduck through API token
    bd = connect_blackduck(args.api_token)
    #create new Project
    if args.create_project:
        create_project(bd, args.project_name, args.description)
    else:
        #use exiting project 
        project, project_id = get_project(bd, args.project_name)
        if args.version:
            version = get_version(bd, project, args.version)
        else:
            version = get_version(bd, project)

        # Create the SBOM report
        if args.create_report:
            report_id = create_sbom_report(bd, project_id, version['id'])
            sbom_report_file = download_sbom_report(bd, project_id, version['id'], report_id)
            extract_and_flatten(sbom_report_file)
            os.remove(sbom_report_file)



if __name__ == "__main__":
    main()



